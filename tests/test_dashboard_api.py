from __future__ import annotations

from datetime import datetime

import pytest
import yaml

from claw_vault import config as config_module
from claw_vault.audit.models import AuditRecord
from claw_vault.audit.store import AuditStore
from claw_vault.config import Settings
from claw_vault.dashboard import api as dashboard_api


def test_push_proxy_event_records_agent_and_session_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])

    record = AuditRecord(
        timestamp=datetime.utcnow(),
        agent_id="agent-007",
        agent_name="ops-agent",
        session_id="sess-123",
        api_endpoint="https://api.openai.com/v1/chat/completions",
        method="POST",
        action_taken="block",
        risk_level="high",
        risk_score=9.1,
        detections=["sensitive:api_key"],
        user_content="sk-test-value",
    )

    dashboard_api.push_proxy_event(record)

    assert len(dashboard_api._scan_history) == 1
    event = dashboard_api._scan_history[0]
    assert event["agent_id"] == "agent-007"
    assert event["agent_name"] == "ops-agent"
    assert event["session_id"] == "sess-123"


@pytest.mark.asyncio
async def test_audit_store_persists_agent_and_session_ids(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    await store.initialize()

    record = AuditRecord(
        timestamp=datetime.utcnow(),
        agent_id="builder",
        agent_name="Builder Agent",
        session_id="sess-77",
        api_endpoint="https://api.anthropic.com/v1/messages",
        method="POST",
        action_taken="sanitize",
        risk_level="medium",
        risk_score=5.5,
    )

    await store.log(record)
    records = await store.query_recent(limit=1)
    await store.close()

    assert len(records) == 1
    assert records[0].agent_id == "builder"
    assert records[0].agent_name == "Builder Agent"
    assert records[0].session_id == "sess-77"


@pytest.mark.asyncio
async def test_update_detection_config_persists_extended_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(dashboard_api, "_persist_config", lambda: None)

    result = await dashboard_api.update_detection_config(
        {
            "aws_credentials": False,
            "blockchain": False,
        }
    )

    assert result["aws_credentials"] is False
    assert result["blockchain"] is False
    assert settings.detection.aws_credentials is False
    assert settings.detection.blockchain is False


class _DummyOpenClawService:
    def __init__(self) -> None:
        self.enabled_updates: list[bool] = []

    def set_enabled(self, enabled: bool) -> None:
        self.enabled_updates.append(enabled)


@pytest.mark.asyncio
async def test_update_openclaw_session_redaction_config_updates_runtime_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    settings.openclaw.session_redaction.enabled = False
    service = _DummyOpenClawService()
    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(dashboard_api, "_openclaw_service", service)
    monkeypatch.setattr(dashboard_api, "_persist_config", lambda: None)

    result = await dashboard_api.update_openclaw_session_redaction_config(
        dashboard_api.OpenClawSessionRedactionUpdate(enabled=True)
    )

    assert settings.openclaw.session_redaction.enabled is True
    assert service.enabled_updates == [True]
    assert result["enabled"] is True


def test_persist_config_writes_safe_yaml_for_path_values(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings()
    settings.proxy.traffic_log_path = tmp_path / "proxy_traffic.jsonl"
    settings.openclaw.session_redaction.state_file = tmp_path / "openclaw_state.json"
    config_file = tmp_path / "config.yaml"

    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(config_module, "DEFAULT_CONFIG_FILE", config_file)

    dashboard_api._persist_config()

    content = config_file.read_text(encoding="utf-8")
    payload = yaml.safe_load(content)

    assert "python/object/apply:pathlib.PosixPath" not in content
    assert payload["proxy"]["traffic_log_path"] == str(settings.proxy.traffic_log_path)
    assert payload["openclaw"]["session_redaction"]["state_file"] == str(
        settings.openclaw.session_redaction.state_file
    )
