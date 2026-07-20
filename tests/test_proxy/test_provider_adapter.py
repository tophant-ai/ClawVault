# ruff: noqa: S101

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from claw_vault.config import ProviderAdapterConfig, Settings
from claw_vault.dashboard.api import set_dependencies
from claw_vault.dashboard.app import create_app
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.proxy.provider_adapter import configure_provider_adapter

TOKEN_FIXTURE = "sk-" + "proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"


class _FakeAsyncClient:
    last_request: dict[str, object] | None = None

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, url: str, *, content: str, headers: dict[str, str]):
        self.__class__.last_request = {"url": url, "content": content, "headers": headers}
        return httpx.Response(
            200,
            json={
                "id": "upstream-1",
                "choices": [{"message": {"role": "assistant", "content": "Use [EMAIL_1]"}}],
            },
            headers={"Content-Type": "application/json"},
        )

    def stream(self, method: str, url: str, *, content: str, headers: dict[str, str]):
        self.__class__.last_request = {
            "method": method,
            "url": url,
            "content": content,
            "headers": headers,
        }
        return _FakeStreamResponse()


class _FakeStreamResponse:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def aiter_bytes(self):
        yield b'data: {"choices":[{"delta":{"content":"Use [EMAIL_1]"}}]}\n\n'
        yield b"data: [DONE]\n\n"


def _payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "gpt-4o",
        "stream": stream,
        "messages": [{"role": "user", "content": "@clawvault sanitize email=alice@example.com"}],
    }


def _strict_settings() -> Settings:
    settings = Settings()
    settings.guard.mode = "strict"
    settings.rules = []
    return settings


def _rule_engine(**kwargs) -> RuleEngine:
    engine = RuleEngine(**kwargs)
    engine.set_rules([])
    return engine


@pytest.fixture(autouse=True)
def _reset_dashboard_state():
    set_dependencies(None, None, None, settings=Settings())


def test_provider_adapter_rewrites_non_stream_request_before_upstream(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    client = TestClient(create_app())

    response = client.post("/v1/chat/completions", json=_payload())

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Use [EMAIL_1]"
    assert _FakeAsyncClient.last_request is not None
    forwarded = str(_FakeAsyncClient.last_request["content"])
    assert "email=[EMAIL_1]" in forwarded
    assert "alice@example.com" not in forwarded
    assert "@clawvault" not in forwarded
    assert _FakeAsyncClient.last_request["url"] == "https://upstream.test/v1/chat/completions"


def test_provider_adapter_rewrites_stream_request_before_upstream(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    client = TestClient(create_app())

    with client.stream("POST", "/v1/chat/completions", json=_payload(stream=True)) as response:
        body = response.read().decode()

    assert response.status_code == 200
    assert "Use [EMAIL_1]" in body
    assert _FakeAsyncClient.last_request is not None
    forwarded = str(_FakeAsyncClient.last_request["content"])
    assert json.loads(forwarded)["stream"] is True
    assert "email=[EMAIL_1]" in forwarded
    assert "alice@example.com" not in forwarded
    assert "@clawvault" not in forwarded


def test_provider_adapter_blocks_empty_sanitize_without_upstream(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    client = TestClient(create_app())

    payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "@clawvault sanitize"}]}
    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 400
    assert _FakeAsyncClient.last_request is None
    assert "alice@example.com" not in response.text




def test_provider_adapter_blocks_strict_secret_without_upstream(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    set_dependencies(
        None,
        None,
        None,
        settings=_strict_settings(),
        rule_engine=_rule_engine(mode="strict"),
    )
    client = TestClient(create_app())

    payload = {
        "model": "gpt-4o",
        "stream": False,
        "messages": [{"role": "user", "content": f"Please use this key: {TOKEN_FIXTURE}"}],
    }
    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "Strict mode: threat blocked" in content
    assert TOKEN_FIXTURE not in response.text
    assert _FakeAsyncClient.last_request is None


def test_provider_adapter_blocks_strict_stream_secret_without_upstream(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    set_dependencies(
        None,
        None,
        None,
        settings=_strict_settings(),
        rule_engine=_rule_engine(mode="strict"),
    )
    client = TestClient(create_app())

    payload = {
        "model": "gpt-4o",
        "stream": True,
        "messages": [{"role": "user", "content": f"Please use this key: {TOKEN_FIXTURE}"}],
    }
    with client.stream("POST", "/v1/chat/completions", json=payload) as response:
        body = response.read().decode()

    assert response.status_code == 200
    assert "Strict mode: threat blocked" in body
    assert "data: [DONE]" in body
    assert TOKEN_FIXTURE not in body
    assert _FakeAsyncClient.last_request is None


def test_provider_adapter_records_dashboard_events_without_raw_secret(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    set_dependencies(
        None,
        None,
        None,
        settings=_strict_settings(),
        rule_engine=_rule_engine(mode="strict"),
    )
    client = TestClient(create_app())

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Please use this key: {TOKEN_FIXTURE}"}],
    }
    response = client.post("/v1/chat/completions", json=payload)
    overview = client.get("/api/monitor/overview").json()
    events = client.get("/api/monitor/log-stream").json()

    assert response.status_code == 200
    assert overview["block_count"] >= 1
    assert overview["message_count"] >= 1
    serialized_events = json.dumps(events)
    assert TOKEN_FIXTURE not in serialized_events


def test_provider_adapter_records_sanitize_event(monkeypatch) -> None:
    _FakeAsyncClient.last_request = None
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    configure_provider_adapter(ProviderAdapterConfig(upstream_base_url="https://upstream.test/v1"))
    set_dependencies(None, None, None, settings=Settings())
    client = TestClient(create_app())

    response = client.post("/v1/chat/completions", json=_payload())
    overview = client.get("/api/monitor/overview").json()
    events = client.get("/api/monitor/log-stream").json()

    assert response.status_code == 200
    assert overview["sanitize_count"] >= 1
    assert overview["message_count"] >= 1
    assert "alice@example.com" not in json.dumps(events)
