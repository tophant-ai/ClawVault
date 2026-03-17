"""mitmproxy addon for transparent API call interception."""

from __future__ import annotations

import json
import time
import uuid
from urllib.parse import urlparse

import structlog
from mitmproxy import http

from claw_vault.audit.models import AuditRecord
from claw_vault.detector.engine import DetectionEngine, ScanResult
from claw_vault.guard.action import Action
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.monitor.token_counter import TokenCounter
from claw_vault.sanitizer.replacer import Sanitizer
from claw_vault.sanitizer.restorer import Restorer

logger = structlog.get_logger()


class ClawVaultAddon:
    """mitmproxy addon that intercepts, scans, and optionally sanitizes API traffic.

    This is the core interception pipeline:
    Request:  detect → evaluate → (sanitize|block|allow) → log
    Response: restore placeholders → scan for dangerous commands → log
    """

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        rule_engine: RuleEngine | None = None,
        sanitizer: Sanitizer | None = None,
        restorer: Restorer | None = None,
        token_counter: TokenCounter | None = None,
        audit_callback=None,
        intercept_hosts: list[str] | None = None,
    ) -> None:
        self.engine = detection_engine or DetectionEngine()
        self.rules = rule_engine or RuleEngine()
        self.sanitizer = sanitizer or Sanitizer()
        self.restorer = restorer or Restorer()
        self.token_counter = token_counter or TokenCounter()
        self.audit_callback = audit_callback
        self.intercept_hosts = intercept_hosts or [
            "api.openai.com",
            "api.anthropic.com",
            "api.siliconflow.cn",
        ]
        self._session_id = str(uuid.uuid4())[:8]
        self._pending_requests: dict[str, dict] = {}
        # Track blocked message contents so they can be stripped from future
        # requests in the same conversation, preserving session continuity.
        self._blocked_contents: set[str] = set()
        logger.info(
            "interceptor_initialized",
            session_id=self._session_id,
            intercept_hosts=self.intercept_hosts,
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept outgoing request to AI provider."""
        start_time = time.monotonic()
        flow_id = str(id(flow))

        if not self._should_intercept(flow):
            logger.debug(
                "request_skipped_not_intercept_host",
                method=flow.request.method,
                host=flow.request.pretty_host,
                url=flow.request.pretty_url,
                intercept_hosts=self.intercept_hosts,
            )
            return

        body = self._get_request_body(flow)
        if not body:
            logger.debug(
                "request_skipped_empty_body",
                method=flow.request.method,
                url=flow.request.pretty_url,
            )
            return

        # Strip previously blocked messages from conversation history
        body = self._strip_blocked_messages(body)
        self._set_request_body(flow, body)

        logger.info(
            "request_interception_started",
            flow_id=flow_id,
            method=flow.request.method,
            url=flow.request.pretty_url,
            body_size=len(body),
        )

        # Extract only user message content for scanning (skip system prompts)
        scan_text = self._extract_user_content(body)
        # Extract agent name from system prompt or request metadata
        agent_name = self._extract_agent_name(body)

        # Run detection pipeline on user content only
        scan = self.engine.scan_full(scan_text)
        action_result = self.rules.evaluate(scan)
        logger.info(
            "request_evaluated",
            flow_id=flow_id,
            action=action_result.action.value,
            threat_level=scan.threat_level.value,
            risk_score=action_result.risk_score,
            sensitive_count=len(scan.sensitive),
            command_count=len(scan.commands),
            injection_count=len(scan.injections),
        )

        self._pending_requests[flow_id] = {
            "original_body": body,
            "scan": scan,
            "start_time": start_time,
            "model": self.token_counter.detect_model_from_url(flow.request.pretty_url),
        }

        if action_result.action == Action.BLOCK:
            # Remember the blocked content so it can be stripped from future requests
            self._blocked_contents.add(scan_text)
            # Build human-readable detail lines
            detail_lines = self._format_block_details(scan, action_result)
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": {
                            "message": f"[ClawVault] {action_result.reason}\n\n{detail_lines}",
                            "type": "claw_vault_block",
                            "code": "content_blocked",
                        },
                    }
                ),
                {"Content-Type": "application/json"},
            )
            logger.warning(
                "request_blocked",
                flow_id=flow_id,
                url=flow.request.pretty_url,
                reason=action_result.reason,
                risk_score=action_result.risk_score,
            )
            self._emit_audit(flow, scan, action_result.action.value, body, agent_name=agent_name, user_content=scan_text)
            return

        if action_result.action == Action.ASK_USER:
            # Interactive mode: return a warning as a fake LLM response
            detail_lines = self._format_block_details(scan, action_result)
            warning_msg = (
                f"⚠️ [ClawVault Security Alert]\n\n"
                f"{action_result.reason}\n\n"
                f"{detail_lines}\n\n"
                f"Please modify your message and resend, or contact an administrator to adjust the security policy."
            )
            flow.response = self._make_llm_response(body, warning_msg)
            logger.info(
                "request_warning_interactive",
                flow_id=flow_id,
                url=flow.request.pretty_url,
                reason=action_result.reason,
            )
            self._emit_audit(flow, scan, "ask_user", body, agent_name=agent_name, user_content=scan_text)
            return

        if action_result.action == Action.SANITIZE and scan.sensitive:
            sanitized = self.sanitizer.sanitize_by_value(body, scan.sensitive)
            self._set_request_body(flow, sanitized)
            logger.info(
                "request_sanitized",
                flow_id=flow_id,
                url=flow.request.pretty_url,
                replacements=len(scan.sensitive),
                mapping=list(self.sanitizer.mapping.keys()),
            )
            self._emit_audit(flow, scan, "sanitize", body, agent_name=agent_name, user_content=scan_text)
            return

        # ALLOW
        self._emit_audit(flow, scan, action_result.action.value, body, agent_name=agent_name, user_content=scan_text)

        latency_ms = (time.monotonic() - start_time) * 1000
        logger.debug(
            "request_intercepted",
            flow_id=flow_id,
            url=flow.request.pretty_url,
            action=action_result.action.value,
            latency_ms=f"{latency_ms:.1f}",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Process AI response: restore placeholders, scan for dangers."""
        flow_id = str(id(flow))
        req_info = self._pending_requests.pop(flow_id, None)

        if not flow.response or not self._should_intercept(flow):
            return

        body = self._get_response_body(flow)
        if not body:
            return

        # Restore sanitized placeholders
        mapping = self.sanitizer.mapping
        if mapping:
            restored = self.restorer.restore(body, mapping)
            if restored != body:
                self._set_response_body(flow, restored)
                body = restored

        # Scan response for dangerous commands
        response_scan = self.engine.scan_response(body)
        if response_scan.has_threats:
            logger.warning(
                "dangerous_response_detected",
                url=flow.request.pretty_url,
                threats=response_scan.total_detections,
            )

        # Record token usage
        if req_info:
            model = req_info.get("model", "default")
            original_body = req_info.get("original_body", "")
            self.token_counter.record_usage(original_body, body, model)

    @staticmethod
    def _extract_user_content(body: str) -> str:
        """Extract the LAST user message from OpenAI/Anthropic JSON body.

        Chat APIs send the full conversation history in every request.
        We only scan the latest user message because:
        - System prompts cause false positive injection detections.
        - Previous user messages were already scanned when first sent.
        - Scanning the full history causes safe new messages (e.g. "hi")
          to be blocked because an earlier message contained sensitive data.

        Falls back to the full body if JSON parsing fails.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return body

        if not isinstance(data, dict):
            return body

        # OpenAI format: {"messages": [{"role": "user", "content": "..."}]}
        messages = data.get("messages")
        if isinstance(messages, list):
            # Find the LAST user message only
            for msg in reversed(messages):
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") != "user":
                    continue
                content = msg.get("content", "")
                if isinstance(content, str) and content:
                    return ClawVaultAddon._strip_openclaw_metadata(content)
                elif isinstance(content, list):
                    # Vision/multimodal: [{"type": "text", "text": "..."}]
                    parts = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            parts.append(item.get("text", ""))
                    if parts:
                        return "\n".join(parts)

        # Anthropic format: {"prompt": "..."}
        prompt = data.get("prompt")
        if isinstance(prompt, str) and prompt:
            return prompt

        return body

    def _strip_blocked_messages(self, body: str) -> str:
        """Remove previously blocked user messages from conversation history.

        When a message is blocked, subsequent requests in the same session
        still carry it in the messages array.  We strip those entries so the
        conversation can continue without the offending content.
        """
        if not self._blocked_contents:
            return body
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return body
        if not isinstance(data, dict):
            return body

        messages = data.get("messages")
        if not isinstance(messages, list):
            return body

        # Find the index of the last user message — never strip it
        last_user_idx = -1
        for idx in range(len(messages) - 1, -1, -1):
            if isinstance(messages[idx], dict) and messages[idx].get("role") == "user":
                last_user_idx = idx
                break

        original_len = len(messages)
        cleaned = []
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                cleaned.append(msg)
                continue
            # Never strip the last (current) user message
            if idx == last_user_idx:
                cleaned.append(msg)
                continue
            content = msg.get("content", "")
            role = msg.get("role", "")
            if role == "user" and isinstance(content, str) and content in self._blocked_contents:
                logger.debug("stripped_blocked_message", content_preview=content[:40])
                continue
            # Also strip ClawVault error/warning assistant responses
            if role == "assistant" and isinstance(content, str) and "[ClawVault]" in content:
                logger.debug("stripped_claw_vault_response", content_preview=content[:40])
                continue
            cleaned.append(msg)

        if len(cleaned) == original_len:
            return body

        data["messages"] = cleaned
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _format_block_details(scan: ScanResult, action_result) -> str:
        """Format detection details into human-readable lines for the TUI."""
        lines = []
        if scan.sensitive:
            lines.append("Sensitive data detected:")
            for s in scan.sensitive:
                lines.append(f"  • {s.description}: {s.masked_value}")
        if scan.commands:
            lines.append("Dangerous commands detected:")
            for c in scan.commands:
                lines.append(f"  • {c.reason}: {c.command[:50]}")
        if scan.injections:
            lines.append("Injection attacks detected:")
            for i in scan.injections:
                lines.append(f"  • {i.description}")
        if action_result.details:
            for d in action_result.details:
                if d not in "\n".join(lines):
                    lines.append(f"  • {d}")
        return "\n".join(lines)

    @staticmethod
    def _make_llm_response(request_body: str, message: str) -> http.Response:
        """Create a fake LLM-style response so the warning appears as an
        assistant message in the TUI chat interface."""
        try:
            data = json.loads(request_body)
            model = data.get("model", "clawvault")
        except Exception:
            model = "clawvault"

        resp_body = {
            "id": f"clawvault-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": message,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        return http.Response.make(
            200,
            json.dumps(resp_body, ensure_ascii=False),
            {"Content-Type": "application/json"},
        )

    def _should_intercept(self, flow: http.HTTPFlow) -> bool:
        """Check if this flow targets an AI provider we should intercept."""
        host = self._normalize_host(flow.request.pretty_host)
        for raw_rule in self.intercept_hosts:
            rule = self._normalize_host(raw_rule)
            if not rule:
                continue
            if host == rule:
                return True
            if rule.startswith("*.") and host.endswith(rule[1:]):
                return True
        return False

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Normalize host rule/input to improve matching robustness."""
        value = (host or "").strip().lower().rstrip(".")
        if not value:
            return ""
        # Allow rules such as "https://api.example.com:443/path"
        if "://" in value:
            parsed = urlparse(value)
            value = (parsed.hostname or "").strip().lower().rstrip(".")
        # Allow rules such as "api.example.com:443"
        if ":" in value and not value.startswith("*."):
            value = value.split(":", 1)[0]
        return value

    @staticmethod
    def _get_request_body(flow: http.HTTPFlow) -> str:
        """Extract text content from request."""
        content = flow.request.get_text()
        return content or ""

    @staticmethod
    def _get_response_body(flow: http.HTTPFlow) -> str:
        """Extract text content from response."""
        if flow.response:
            return flow.response.get_text() or ""
        return ""

    @staticmethod
    def _set_request_body(flow: http.HTTPFlow, text: str) -> None:
        flow.request.set_text(text)

    @staticmethod
    def _set_response_body(flow: http.HTTPFlow, text: str) -> None:
        if flow.response:
            flow.response.set_text(text)

    def _emit_audit(self, flow: http.HTTPFlow, scan: ScanResult, action: str, body: str,
                     agent_name: str | None = None, user_content: str | None = None) -> None:
        """Create and emit an audit record."""
        record = AuditRecord(
            session_id=self._session_id,
            direction="request",
            api_endpoint=flow.request.pretty_url,
            method=flow.request.method,
            risk_level=scan.threat_level.value,
            risk_score=scan.max_risk_score,
            action_taken=action,
            detections=[
                *[f"sensitive:{s.pattern_type}" for s in scan.sensitive],
                *[f"command:{c.command[:30]}" for c in scan.commands],
                *[f"injection:{i.injection_type}" for i in scan.injections],
            ],
            agent_name=agent_name,
            user_content=user_content,
        )
        if self.audit_callback:
            self.audit_callback(record, scan)

    @staticmethod
    def _strip_openclaw_metadata(content: str) -> str:
        """Strip OpenClaw TUI metadata prefix from user message content.

        OpenClaw prepends metadata like:
            Sender (untrusted metadata):
            ```json
            {"label": "openclaw-tui ...", ...}
            ```

            [Mon 2026-03-09 02:10 GMT+8] ...

            <actual user message>

        We extract only the actual user message for scanning and display.
        """
        import re
        # Match the metadata block: "Sender ...\n```json\n{...}\n```\n\n[timestamp] ...\n\n"
        pattern = r'^Sender\s*\(.*?\):\s*```json\s*\{[^}]*\}\s*```\s*(?:\[.*?\]\s*\.{3}\s*)?'
        if re.search(pattern, content, re.DOTALL):
            stripped = re.sub(pattern, '', content, count=1, flags=re.DOTALL).strip()
            return stripped  # may be empty if user message was only metadata
        return content

    @staticmethod
    def _extract_agent_name(body: str) -> str | None:
        """Try to extract the agent name from the request body.

        Strategies:
        1. Check the ``user`` field (OpenAI standard) for ``agent:<name>:...`` pattern.
        2. Parse the first system message for agent identity keywords.
        3. Check for custom ``x-agent-name`` style fields.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict):
            return None

        # Strategy 1: "user" field with agent:<name>:... pattern
        user_field = data.get("user", "")
        if isinstance(user_field, str) and user_field.startswith("agent:"):
            parts = user_field.split(":")
            if len(parts) >= 2:
                return parts[1]

        # Strategy 2: Parse system prompt for agent name
        messages = data.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") != "system":
                    continue
                content = msg.get("content", "")
                if not isinstance(content, str):
                    continue
                # Common patterns: "You are <name>", "Your name is <name>"
                import re
                m = re.search(r'(?:you are|your name is|agent[: ]+)\s*["\']?([A-Za-z0-9_-]+)', content, re.IGNORECASE)
                if m:
                    name = m.group(1).lower()
                    # Skip generic words
                    if name not in ('a', 'an', 'the', 'not', 'now', 'here'):
                        return name
                break  # Only check first system message

        return None
