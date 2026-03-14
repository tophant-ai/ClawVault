"""mitmproxy addon for transparent API call interception."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import structlog
from mitmproxy import http

from claw_vault.audit.models import AuditRecord
from claw_vault.detector.engine import DetectionEngine, ScanResult
from claw_vault.guard.action import Action, ActionResult
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.monitor.token_counter import TokenCounter
from claw_vault.proxy.traffic_logger import ProxyTrafficLogger
from claw_vault.sanitizer.replacer import Sanitizer
from claw_vault.sanitizer.restorer import Restorer

logger = structlog.get_logger()


def _get_agent_config(agent_id: str | None) -> dict[str, Any]:
    """Lazy wrapper to get agent config, avoiding circular imports."""
    from claw_vault.dashboard.api import get_agent_config

    return get_agent_config(agent_id)


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
        audit_callback: Callable[[AuditRecord, ScanResult | None], None] | None = None,
        intercept_hosts: list[str] | None = None,
        traffic_logger: ProxyTrafficLogger | None = None,
    ) -> None:
        self.engine = detection_engine or DetectionEngine()
        self.rules = rule_engine or RuleEngine()
        self.sanitizer = sanitizer or Sanitizer()
        self.restorer = restorer or Restorer()
        self.token_counter = token_counter or TokenCounter()
        self.audit_callback = audit_callback
        self.traffic_logger = traffic_logger
        self.intercept_hosts = intercept_hosts or [
            "api.openai.com",
            "api.anthropic.com",
            "api.siliconflow.cn",
        ]
        self._session_id = str(uuid.uuid4())[:8]
        self._pending_requests: dict[str, dict[str, Any]] = {}
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

        received_body = self._get_request_body(flow)
        if not received_body:
            logger.debug(
                "request_skipped_empty_body",
                method=flow.request.method,
                url=flow.request.pretty_url,
            )
            return

        # Strip previously blocked messages from conversation history
        body = self._strip_blocked_messages(received_body)
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
        agent_id = self._extract_agent_name(body)
        session_id = None

        # Get agent-specific config (priority: agent > global > defaults)
        agent_config = _get_agent_config(agent_id)

        self._pending_requests[flow_id] = {
            "original_body": received_body,
            "forwarded_body": body,
            "request_headers": dict(flow.request.headers),
            "start_time": start_time,
            "model": self.token_counter.detect_model_from_url(flow.request.pretty_url),
            "agent_id": agent_id,
            "session_id": session_id,
            "agent_config": agent_config,
            "action": "allow",
            "risk_level": None,
            "risk_score": None,
            "response_logged": False,
            "synthetic_response": False,
        }

        # Skip detection if agent is disabled
        if not agent_config.get("enabled", True):
            logger.info(
                "request_skipped_agent_disabled",
                flow_id=flow_id,
                agent_id=agent_id,
            )
            return

        # Run detection pipeline with agent-specific detection config
        scan = self.engine.scan_full(scan_text, detection_config=agent_config.get("detection"))
        action_result = self.rules.evaluate(
            scan,
            guard_mode=agent_config.get("guard_mode"),
            auto_sanitize=agent_config.get("auto_sanitize"),
        )
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

        pending = self._pending_requests[flow_id]
        pending["scan"] = scan
        pending["forwarded_body"] = body
        pending["action"] = action_result.action.value
        pending["risk_level"] = scan.threat_level.value
        pending["risk_score"] = scan.max_risk_score

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
            self._emit_audit(
                flow,
                scan,
                action_result.action.value,
                body,
                agent_id=agent_id,
                session_id=session_id,
                user_content=scan_text,
            )
            self._log_synthetic_response_event(flow, flow_id)
            return

        if action_result.action == Action.ASK_USER:
            # Interactive mode: return a warning as a fake LLM response
            detail_lines = self._format_block_details(scan, action_result)
            warning_msg = (
                f"⚠️ [ClawVault Security Alert]\n\n"
                f"{action_result.reason}\n\n"
                f"{detail_lines}\n\n"
                "Please modify your message and resend, or contact an administrator "
                "to adjust the security policy."
            )
            flow.response = self._make_llm_response(body, warning_msg)
            logger.info(
                "request_warning_interactive",
                flow_id=flow_id,
                url=flow.request.pretty_url,
                reason=action_result.reason,
            )
            self._emit_audit(
                flow,
                scan,
                "ask_user",
                body,
                agent_id=agent_id,
                session_id=session_id,
                user_content=scan_text,
            )
            self._log_synthetic_response_event(flow, flow_id)
            return

        if action_result.action == Action.SANITIZE and scan.sensitive:
            sanitized = self.sanitizer.sanitize_by_value(body, scan.sensitive)
            self._set_request_body(flow, sanitized)
            pending["forwarded_body"] = sanitized
            logger.info(
                "request_sanitized",
                flow_id=flow_id,
                url=flow.request.pretty_url,
                replacements=len(scan.sensitive),
                mapping=list(self.sanitizer.mapping.keys()),
            )
            self._emit_audit(
                flow,
                scan,
                "sanitize",
                body,
                agent_id=agent_id,
                session_id=session_id,
                user_content=scan_text,
            )
            return

        # ALLOW
        self._emit_audit(
            flow,
            scan,
            action_result.action.value,
            body,
            agent_id=agent_id,
            session_id=session_id,
            user_content=scan_text,
        )

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

        raw_received_body = self._get_response_body(flow)
        if not raw_received_body:
            return

        if req_info and req_info.get("synthetic_response") and req_info.get("response_logged"):
            return

        body = raw_received_body

        # Restore sanitized placeholders
        mapping = self.sanitizer.mapping
        if mapping:
            restored = self.restorer.restore(body, mapping)
            if restored != body:
                self._set_response_body(flow, restored)
                body = restored

        # Get agent config from pending request info
        agent_config = req_info.get("agent_config", {}) if req_info else {}

        logged_received_body = self._prepare_logged_response_body(flow, raw_received_body)
        logged_returned_body = self._prepare_logged_response_body(flow, body)

        # Scan response for dangerous commands (with agent's detection config)
        response_scan = self.engine.scan_response(
            logged_returned_body, detection_config=agent_config.get("detection")
        )
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
            self.token_counter.record_usage(original_body, logged_returned_body, model)

        self._log_transaction_event(
            flow=flow,
            flow_id=flow_id,
            response_body=logged_received_body,
            returned_body=logged_returned_body,
            source="upstream",
            req_info=req_info,
            risk_level=response_scan.threat_level.value if response_scan.has_threats else None,
            risk_score=response_scan.max_risk_score if response_scan.has_threats else None,
        )

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
    def _format_block_details(scan: ScanResult, action_result: ActionResult) -> str:
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
            model = data.get("model", "claw-vault")
        except Exception:
            model = "claw-vault"

        resp_body = {
            "id": f"claw-vault-{uuid.uuid4().hex[:8]}",
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
        content = flow.request.get_content(strict=False)
        if content is None:
            return ""
        return ClawVaultAddon._decode_http_body(
            content=content,
            content_type=flow.request.headers.get("Content-Type", ""),
        )

    @staticmethod
    def _get_response_body(flow: http.HTTPFlow) -> str:
        """Extract text content from response."""
        if flow.response is None:
            return ""
        content = flow.response.get_content(strict=False)
        if content is None:
            return ""
        return ClawVaultAddon._decode_http_body(
            content=content,
            content_type=flow.response.headers.get("Content-Type", ""),
        )

    @staticmethod
    def _decode_http_body(content: bytes, content_type: str) -> str:
        candidates = ClawVaultAddon._build_decode_candidates(content_type)
        for encoding_name in candidates:
            try:
                return content.decode(encoding_name)
            except UnicodeDecodeError:
                continue
        return content.decode("utf-8", errors="replace")

    @staticmethod
    def _build_decode_candidates(content_type: str) -> list[str]:
        normalized = content_type.lower()
        candidates: list[str] = []
        charset = ClawVaultAddon._extract_charset(normalized)

        if ClawVaultAddon._should_prefer_utf8(normalized, charset):
            candidates.extend(["utf-8", "utf-8-sig"])

        if charset:
            normalized_charset = charset.lower()
            if normalized_charset in {"gbk", "gb2312"}:
                candidates.append("gb18030")
            else:
                candidates.append(normalized_charset)

        if normalized.startswith("text/"):
            candidates.extend(["utf-8", "utf-8-sig"])

        if "json" in normalized:
            candidates.extend(["utf-8", "utf-8-sig"])

        candidates.extend(["gb18030", "latin-1"])
        return ClawVaultAddon._deduplicate_preserve_order(candidates)

    @staticmethod
    def _should_prefer_utf8(content_type: str, charset: str | None) -> bool:
        if "json" in content_type or "text/event-stream" in content_type:
            return True
        return charset in {None, "latin-1", "iso-8859-1"}

    @staticmethod
    def _extract_charset(content_type: str) -> str | None:
        match = re.search(r"charset=([^;]+)", content_type, re.IGNORECASE)
        if match is None:
            return None
        return match.group(1).strip().strip("\"'")

    @staticmethod
    def _deduplicate_preserve_order(values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered

    @staticmethod
    def _set_request_body(flow: http.HTTPFlow, text: str) -> None:
        flow.request.set_text(text)

    @staticmethod
    def _set_response_body(flow: http.HTTPFlow, text: str) -> None:
        if flow.response:
            flow.response.set_text(text)

    @staticmethod
    def _prepare_logged_response_body(flow: http.HTTPFlow, body: str) -> str:
        if not body:
            return ""
        if not ClawVaultAddon._is_sse_response(flow):
            return body
        return ClawVaultAddon._aggregate_sse_body(body)

    @staticmethod
    def _is_sse_response(flow: http.HTTPFlow) -> bool:
        if flow.response is None:
            return False
        content_type = flow.response.headers.get("Content-Type", "")
        return "text/event-stream" in content_type.lower()

    @staticmethod
    def _aggregate_sse_body(body: str) -> str:
        segments: list[str] = []
        payload_lines: list[str] = []
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(":"):
                continue
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            payload_lines.append(payload)
            extracted = ClawVaultAddon._extract_text_from_sse_payload(payload)
            if extracted:
                segments.append(extracted)

        if segments:
            return "".join(segments)
        return "\n".join(payload_lines)

    @staticmethod
    def _extract_text_from_sse_payload(payload: str) -> str:
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return payload

        parts: list[str] = []

        def add_text(value: Any) -> None:
            if isinstance(value, str) and value:
                parts.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        text_value = item.get("text")
                        if isinstance(text_value, str) and text_value:
                            parts.append(text_value)

        choices = data.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    add_text(delta.get("content"))
                message = choice.get("message")
                if isinstance(message, dict):
                    add_text(message.get("content"))

        delta = data.get("delta")
        if isinstance(delta, dict):
            add_text(delta.get("text"))

        content_block = data.get("content_block")
        if isinstance(content_block, dict):
            add_text(content_block.get("text"))

        content_block_delta = data.get("content_block_delta")
        if isinstance(content_block_delta, dict):
            delta = content_block_delta.get("delta")
            if isinstance(delta, dict):
                add_text(delta.get("text"))

        return "".join(parts)

    def _emit_audit(
        self,
        flow: http.HTTPFlow,
        scan: ScanResult,
        action: str,
        body: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        user_content: str | None = None,
    ) -> None:
        """Create and emit an audit record."""
        record = AuditRecord(
            agent_id=agent_id,
            agent_name=agent_id,
            session_id=session_id or "",
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
            user_content=user_content,
        )
        if self.audit_callback:
            self.audit_callback(record, scan)

    def _log_transaction_event(
        self,
        *,
        flow: http.HTTPFlow,
        flow_id: str,
        response_body: str,
        returned_body: str,
        source: str,
        req_info: dict[str, Any] | None,
        risk_level: str | None = None,
        risk_score: float | None = None,
    ) -> None:
        if self.traffic_logger is None or flow.response is None:
            return

        info = req_info or {}
        action = str(info.get("action", "allow"))
        agent_id = info.get("agent_id")
        session_id = info.get("session_id")
        self.traffic_logger.log_transaction(
            proxy_session_id=self._session_id,
            flow_id=flow_id,
            action=action,
            source=source,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            session_id=session_id if isinstance(session_id, str) else None,
            risk_level=risk_level,
            risk_score=risk_score,
            request={
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": info.get("request_headers", dict(flow.request.headers)),
                "body": info.get("original_body", ""),
                "forwarded_body": info.get("forwarded_body", info.get("original_body", "")),
            },
            response={
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "body": response_body,
                "returned_body": returned_body,
            },
        )

    def _log_synthetic_response_event(self, flow: http.HTTPFlow, flow_id: str) -> None:
        if flow.response is None:
            return

        req_info = self._pending_requests.get(flow_id)
        if req_info is None:
            return

        response_body = self._get_response_body(flow)
        logged_response_body = self._prepare_logged_response_body(flow, response_body)
        self._log_transaction_event(
            flow=flow,
            flow_id=flow_id,
            response_body=logged_response_body,
            returned_body=logged_response_body,
            source="synthetic",
            req_info=req_info,
        )
        req_info["response_logged"] = True
        req_info["synthetic_response"] = True

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
        pattern = r"^Sender\s*\(.*?\):\s*```json\s*\{[^}]*\}\s*```\s*(?:\[.*?\]\s*\.{3}\s*)?"
        if re.search(pattern, content, re.DOTALL):
            stripped = re.sub(pattern, "", content, count=1, flags=re.DOTALL).strip()
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

                m = re.search(
                    r'(?:you are|your name is|agent[: ]+)\s*["\']?([A-Za-z0-9_-]+)',
                    content,
                    re.IGNORECASE,
                )
                if m:
                    name = m.group(1).lower()
                    # Skip generic words
                    if name not in ("a", "an", "the", "not", "now", "here"):
                        return name
                break  # Only check first system message

        return None
