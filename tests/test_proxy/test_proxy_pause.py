"""Tests for proxy pause/resume functionality."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from claw_vault.proxy.interceptor import ClawVaultAddon


@dataclass
class _DummyRequest:
    _text: str
    method: str = "POST"
    pretty_url: str = "https://api.openai.com/v1/chat/completions"
    pretty_host: str = "api.openai.com"
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})

    def get_content(self, strict: bool = False) -> bytes | None:
        return self._text.encode()

    def set_text(self, text: str) -> None:
        self._text = text


@dataclass
class _DummyFlow:
    request: _DummyRequest
    response: object | None = None


def _make_body(user_message: str) -> str:
    return json.dumps({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": user_message}],
    })


@pytest.fixture
def addon():
    return ClawVaultAddon(
        intercept_hosts=["api.openai.com"],
    )


class TestProxyPause:
    def test_pause_blocks_intercepted_requests(self, addon):
        """Paused proxy should return 403 for intercepted hosts."""
        addon.pause("High-risk file change detected: .env")

        body = _make_body("Hello")
        flow = _DummyFlow(request=_DummyRequest(_text=body))
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_data = json.loads(flow.response.get_content().decode())
        assert resp_data["error"]["code"] == "proxy_paused"
        assert ".env" in resp_data["error"]["message"]

    def test_pause_does_not_affect_non_intercepted(self, addon):
        """Paused proxy should pass through non-intercepted hosts."""
        addon.pause("test reason")

        body = _make_body("Hello")
        flow = _DummyFlow(
            request=_DummyRequest(
                _text=body,
                pretty_host="example.com",
                pretty_url="https://example.com/api",
            )
        )
        addon.request(flow)

        # Non-intercepted host should not get a response set
        assert flow.response is None

    def test_resume_restores_normal_operation(self, addon):
        """After resume, requests should be processed normally."""
        addon.pause("test reason")
        addon.resume()

        body = _make_body("Hello")
        flow = _DummyFlow(request=_DummyRequest(_text=body))
        addon.request(flow)

        # Should not get 403 (may get other responses from detection pipeline)
        if flow.response is not None:
            assert flow.response.status_code != 403

    def test_is_paused_property(self, addon):
        assert addon.is_paused is False
        addon.pause("test")
        assert addon.is_paused is True
        addon.resume()
        assert addon.is_paused is False

    def test_pause_info_when_not_paused(self, addon):
        assert addon.pause_info is None

    def test_pause_info_when_paused(self, addon):
        addon.pause("file change", event_id="evt-123")
        info = addon.pause_info
        assert info is not None
        assert info["paused"] is True
        assert info["reason"] == "file change"
        assert info["event_id"] == "evt-123"

    def test_pause_info_cleared_after_resume(self, addon):
        addon.pause("test")
        addon.resume()
        assert addon.pause_info is None
