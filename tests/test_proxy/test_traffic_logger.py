# ruff: noqa: S101

"""Tests for dedicated proxy traffic logging."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.monitor.token_counter import TokenCounter
from claw_vault.proxy.interceptor import ClawVaultAddon
from claw_vault.proxy.traffic_logger import ProxyTrafficLogger

CN_SANITIZE_INFO = "\u8131\u654f\u4fe1\u606f"
CN_WHAT_IS_SANITIZE = "\u4ec0\u4e48\u662f\u8131\u654f\uff1f"
CN_MY_EMAIL_IS = "\u6211\u7684\u90ae\u7bb1\u662f"


@dataclass
class _DummyMessage:
    _text: str
    headers: dict[str, str] = field(default_factory=dict)

    def get_text(self) -> str:
        return self._text

    def set_text(self, text: str) -> None:
        self._text = text


@dataclass
class _DummyRequest(_DummyMessage):
    method: str = "POST"
    pretty_url: str = "https://api.openai.com/v1/chat/completions"
    pretty_host: str = "api.openai.com"

    def get_content(self, strict: bool = False) -> bytes | None:
        return self._text.encode()


@dataclass
class _DummyResponse(_DummyMessage):
    status_code: int = 200
    content_bytes: bytes | None = None

    def get_content(self, strict: bool = False) -> bytes | None:
        if self.content_bytes is not None:
            return self.content_bytes
        return self._text.encode()


@dataclass
class _DummyFlow:
    request: _DummyRequest
    response: _DummyResponse | None = None


def test_proxy_traffic_logger_redacts_sensitive_headers_and_parses_json(tmp_path) -> None:
    log_path = tmp_path / "proxy_traffic.jsonl"
    logger = ProxyTrafficLogger(log_path)

    logger.log_transaction(
        proxy_session_id="session-1",
        flow_id="flow-1",
        action="allow",
        source="upstream",
        agent_id="agent-a",
        session_id="sess-a",
        risk_level=None,
        risk_score=None,
        request={
            "method": "POST",
            "url": "https://api.openai.com/v1/chat/completions",
            "headers": {"Authorization": "Bearer email_value", "Content-Type": "application/json"},
            "body": '{"messages":[]}',
            "forwarded_body": '{"messages":[]}',
        },
        response={
            "status_code": 200,
            "headers": {"Set-Cookie": "token=email_value", "Content-Type": "application/json"},
            "body": '{"ok":true}',
            "returned_body": '{"ok":true}',
        },
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    assert payload["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert payload["response"]["headers"]["Set-Cookie"] == "[REDACTED]"
    assert payload["request"]["body"] == {"messages": []}
    assert payload["response"]["body"] == {"ok": True}


def test_decode_http_body_prefers_utf8_for_sse_without_charset() -> None:
    hello_text = "\u4f60\u597d"
    content = f'data: {{"choices":[{{"delta":{{"content":"{hello_text}"}}}}]}}\n\n'.encode()
    decoded = ClawVaultAddon._decode_http_body(content, "text/event-stream")
    assert hello_text in decoded


def test_addon_writes_single_combined_transaction_entry(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "permissive", "auto_sanitize": False},
    )

    traffic_logger = ProxyTrafficLogger(tmp_path / "proxy_traffic.jsonl")
    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="permissive", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
        traffic_logger=traffic_logger,
    )
    request_body = json.dumps(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Authorization": "Bearer email_value", "Content-Type": "application/json"},
        )
    )

    addon.request(flow)
    flow.response = _DummyResponse(
        _text='{"id":"resp-1","choices":[{"message":{"content":"world"}}]}',
        headers={"Content-Type": "application/json"},
        status_code=200,
    )
    addon.response(flow)

    lines = (tmp_path / "proxy_traffic.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["action"] == "allow"
    assert entry["source"] == "upstream"
    assert entry["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert entry["request"]["body"] == {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
    }
    assert entry["response"]["status_code"] == 200
    assert entry["response"]["body"] == {
        "id": "resp-1",
        "choices": [{"message": {"content": "world"}}],
    }


def test_addon_aggregates_sse_response_before_logging(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "permissive", "auto_sanitize": False},
    )

    traffic_logger = ProxyTrafficLogger(tmp_path / "proxy_traffic.jsonl")
    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="permissive", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
        traffic_logger=traffic_logger,
    )
    request_body = json.dumps(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Authorization": "Bearer email_value", "Content-Type": "application/json"},
        )
    )

    addon.request(flow)
    flow.response = _DummyResponse(
        _text=(
            'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
            "data: [DONE]\n"
        ),
        headers={"Content-Type": "text/event-stream; charset=utf-8"},
        status_code=200,
    )
    addon.response(flow)

    lines = (tmp_path / "proxy_traffic.jsonl").read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])

    assert entry["response"]["body"] == "Hello world"
    assert entry["response"]["returned_body"] == "Hello world"


def test_addon_intercepts_openrouter_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["openrouter.ai"],
    )
    request_body = json.dumps(
        {"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "password=Secret123"}]}
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            pretty_url="https://openrouter.ai/api/v1/chat/completions",
            pretty_host="openrouter.ai",
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403


@pytest.mark.parametrize(
    ("host", "path", "model"),
    [
        ("api.minimax.io", "/v1/chat/completions", "MiniMax-M3"),
        ("api.minimaxi.com", "/anthropic/v1/messages", "MiniMax-M2.7"),
    ],
)
def test_addon_intercepts_minimax_host(
    monkeypatch: pytest.MonkeyPatch, host: str, path: str, model: str
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=[host],
    )
    request_body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": "password=Secret123"}]}
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            pretty_url=f"https://{host}{path}",
            pretty_host=host,
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert addon._pending_requests[str(id(flow))]["model"] == model


def _openclaw_tui_message(content: str) -> str:
    return (
        'Sender (untrusted metadata):\n'
        '```json\n'
        '{"label":"openclaw-tui main"}\n'
        '```\n\n'
        f'{content}'
    )


def _openclaw_system_prompt() -> str:
    return "You are a personal assistant running inside OpenClaw.\n## Tooling"




def test_openclaw_clawvault_sanitize_rewrites_and_continues_without_logging_raw(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "permissive", "auto_sanitize": False},
    )

    traffic_logger = ProxyTrafficLogger(tmp_path / "proxy_traffic.jsonl")
    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="permissive", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
        traffic_logger=traffic_logger,
    )
    email_value = "alice@example.com"
    request_body = json.dumps(
        {
            "model": "gpt-4o",
            "stream": False,
            "messages": [
                {"role": "system", "content": _openclaw_system_prompt()},
                {
                    "role": "user",
                    "content": f"@clawvault {CN_SANITIZE_INFO} {CN_MY_EMAIL_IS} {email_value}",
                },
            ],
        }
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is None
    forwarded = json.loads(flow.request.get_text())
    assert forwarded["messages"][-1]["content"] == f"{CN_MY_EMAIL_IS} [EMAIL_1]"
    assert email_value not in json.dumps(forwarded, ensure_ascii=False)

    flow.response = _DummyResponse(
        _text='{"id":"resp-1","choices":[{"message":{"content":"Use [EMAIL_1]"}}]}',
        headers={"Content-Type": "application/json"},
        status_code=200,
    )
    addon.response(flow)

    assert "[EMAIL_1]" in flow.response.get_text()
    entry_text = (tmp_path / "proxy_traffic.jsonl").read_text(encoding="utf-8")
    assert email_value not in entry_text
    entry = json.loads(entry_text)
    assert entry["action"] == "sanitize"
    assert entry["source"] == "upstream"
    assert entry["request"]["body"]["messages"][-1]["content"] == f"{CN_MY_EMAIL_IS} [EMAIL_1]"
    forwarded_content = entry["request"]["forwarded_body"]["messages"][-1]["content"]
    assert forwarded_content == f"{CN_MY_EMAIL_IS} [EMAIL_1]"


def test_openclaw_clawvault_sanitize_question_is_not_local_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "permissive", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="permissive", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
    )
    request_body = json.dumps(
        {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": _openclaw_system_prompt()},
                {"role": "user", "content": f"@clawvault {CN_WHAT_IS_SANITIZE}"},
            ],
        }
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is None

def test_strict_block_openclaw_tui_non_stream_returns_chat_completion(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    traffic_logger = ProxyTrafficLogger(tmp_path / "proxy_traffic.jsonl")
    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
        traffic_logger=traffic_logger,
    )
    request_body = json.dumps(
        {
            "model": "gpt-4o",
            "stream": False,
            "messages": [
                {"role": "system", "content": _openclaw_system_prompt()},
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "password=Secret123"}],
                },
            ],
        }
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 200
    assert flow.response.headers["Content-Type"] == "application/json"
    payload = json.loads(flow.response.get_text())
    assert payload["object"] == "chat.completion"
    content = payload["choices"][0]["message"]["content"]
    assert "[ClawVault] Strict mode: threat blocked" in content
    assert "Sensitive data detected" in content

    entry = json.loads((tmp_path / "proxy_traffic.jsonl").read_text(encoding="utf-8"))
    assert entry["action"] == "block"
    assert entry["source"] == "synthetic"
    assert entry["response"]["status_code"] == 200


def test_strict_block_openclaw_tui_stream_returns_sse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
    )
    request_body = json.dumps(
        {
            "model": "gpt-4o",
            "stream": True,
            "messages": [
                {"role": "system", "content": _openclaw_system_prompt()},
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "password=Secret123"}],
                },
            ],
        }
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={"Content-Type": "application/json"},
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 200
    assert flow.response.headers["Content-Type"].startswith("text/event-stream")
    body = flow.response.get_text()
    assert (
        '"delta": {"role": "assistant", "content": "[ClawVault] Strict mode: threat blocked'
        in body
    )
    assert '"delta": {}, "finish_reason": "stop", "index": 0' in body
    assert "data: [DONE]" in body


def test_strict_block_explicit_compat_header_returns_chat_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
    )
    request_body = json.dumps(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "password=Secret123"}]}
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=request_body,
            headers={
                "Content-Type": "application/json",
                "X-ClawVault-Block-Response": "openai-compatible",
            },
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 200
    payload = json.loads(flow.response.get_text())
    assert "[ClawVault] Strict mode: threat blocked" in payload["choices"][0]["message"]["content"]


def test_strict_block_non_chat_request_stays_403(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "claw_vault.proxy.interceptor._get_agent_config",
        lambda agent_id: {"enabled": True, "guard_mode": "strict", "auto_sanitize": False},
    )

    addon = ClawVaultAddon(
        rule_engine=RuleEngine(mode="strict", auto_sanitize=False),
        token_counter=TokenCounter(),
        intercept_hosts=["api.openai.com"],
    )
    flow = _DummyFlow(
        request=_DummyRequest(
            _text=json.dumps({"prompt": "password=Secret123"}),
            headers={
                "Content-Type": "application/json",
                "X-ClawVault-Block-Response": "openai-compatible",
            },
        )
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
