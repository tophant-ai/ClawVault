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
            "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
            "body": '{"messages":[]}',
            "forwarded_body": '{"messages":[]}',
        },
        response={
            "status_code": 200,
            "headers": {"Set-Cookie": "token=secret", "Content-Type": "application/json"},
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
    content = 'data: {"choices":[{"delta":{"content":"你好"}}]}\n\n'.encode()
    decoded = ClawVaultAddon._decode_http_body(content, "text/event-stream")
    assert "你好" in decoded


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
            headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
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
            headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
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
