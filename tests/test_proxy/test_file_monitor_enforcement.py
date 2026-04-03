"""Tests for file monitor → proxy enforcement integration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from claw_vault.detector.engine import DetectionEngine, ScanResult
from claw_vault.detector.patterns import DetectionResult, PatternCategory
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
class _DummyResponse:
    status_code: int = 200
    _text: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def get_content(self, strict: bool = False) -> bytes | None:
        return self._text.encode()


@dataclass
class _DummyFlow:
    request: _DummyRequest
    response: _DummyResponse | None = None


def _make_body(user_message: str) -> str:
    return json.dumps({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": user_message},
        ],
    })


def _make_scan_with_sensitive(value: str) -> ScanResult:
    """Create a ScanResult with a single sensitive detection."""
    det = DetectionResult(
        pattern_type="api_key",
        category=PatternCategory.API_KEY,
        value=value,
        masked_value=value[:4] + "****",
        start=0,
        end=len(value),
        risk_score=9.0,
        confidence=1.0,
        description="API key detected",
    )
    scan = ScanResult()
    scan.sensitive = [det]
    return scan


@pytest.fixture
def addon():
    return ClawVaultAddon(
        intercept_hosts=["api.openai.com"],
    )


class TestFlaggedFileBlocking:
    def test_flagged_value_blocks_request(self, addon):
        """Request containing a flagged sensitive value should be blocked with 403."""
        api_key = "sk-proj-abc123def456"
        scan = _make_scan_with_sensitive(api_key)
        addon.flag_file_content("/home/user/.env", scan)

        body = _make_body(f"Use this key: {api_key}")
        flow = _DummyFlow(request=_DummyRequest(_text=body))
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_data = json.loads(flow.response.get_content().decode())
        assert resp_data["error"]["code"] == "flagged_file_content"

    def test_unflag_allows_request(self, addon):
        """After unflagging, request should pass through normally."""
        api_key = "sk-proj-abc123def456"
        scan = _make_scan_with_sensitive(api_key)
        addon.flag_file_content("/home/user/.env", scan)
        addon.unflag_file("/home/user/.env")

        body = _make_body(f"Use this key: {api_key}")
        flow = _DummyFlow(request=_DummyRequest(_text=body))
        addon.request(flow)

        # Should not be blocked by flagged-file check (may be blocked by
        # normal detection, but that's a different code path)
        if flow.response is not None:
            resp_data = json.loads(flow.response.get_content().decode())
            assert resp_data["error"]["code"] != "flagged_file_content"

    def test_non_matching_content_passes(self, addon):
        """Request without flagged content should not be blocked by file monitor."""
        api_key = "sk-proj-abc123def456"
        scan = _make_scan_with_sensitive(api_key)
        addon.flag_file_content("/home/user/.env", scan)

        body = _make_body("Hello, tell me a joke")
        flow = _DummyFlow(request=_DummyRequest(_text=body))
        addon.request(flow)

        # Should not be blocked by flagged-file check
        if flow.response is not None:
            resp_data = json.loads(flow.response.get_content().decode())
            assert resp_data["error"]["code"] != "flagged_file_content"

    def test_file_deletion_clears_flags(self, addon):
        """Flagging with empty ScanResult should clear the file's flagged values."""
        api_key = "sk-proj-abc123def456"
        scan = _make_scan_with_sensitive(api_key)
        addon.flag_file_content("/home/user/.env", scan)

        # Simulate deletion: flag with empty scan
        addon.flag_file_content("/home/user/.env", ScanResult())

        assert addon._get_all_flagged_values() == set()

    def test_multiple_files_flagged(self, addon):
        """Multiple files can be flagged independently."""
        key1 = "sk-proj-abc123"
        key2 = "AKIAIOSFODNN7EXAMPLE"
        addon.flag_file_content("/a/.env", _make_scan_with_sensitive(key1))
        addon.flag_file_content("/b/.env", _make_scan_with_sensitive(key2))

        all_values = addon._get_all_flagged_values()
        assert key1 in all_values
        assert key2 in all_values

        # Unflag one file, other remains
        addon.unflag_file("/a/.env")
        all_values = addon._get_all_flagged_values()
        assert key1 not in all_values
        assert key2 in all_values
