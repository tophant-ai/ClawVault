from __future__ import annotations

from datetime import datetime

import json

import pytest
import yaml

from claw_vault import config as config_module
from claw_vault.audit.models import AuditRecord
from claw_vault.audit.store import AuditStore
from claw_vault.config import Settings
from claw_vault.dashboard import api as dashboard_api


def test_push_external_event_inserts_scan_history_with_plugin_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])
    monkeypatch.setattr(dashboard_api, "_analysis_log", [])

    payload = dashboard_api.ExternalEventPayload(
        source="plugin",
        category="file_access_blocked",
        threat_level="high",
        action="block",
        tool_name="read",
        file_path="/home/user/.ssh/id_rsa",
        matched_rule=".ssh/**",
        agent_id="openclaw",
        message="blocked sensitive path",
        risk_score=9.0,
    )

    result = dashboard_api.push_external_event(payload)

    assert result["ok"] is True
    assert len(dashboard_api._scan_history) == 1
    entry = dashboard_api._scan_history[0]
    assert entry["source"] == "plugin"
    assert entry["action"] == "block"
    assert entry["threat_level"] == "high"
    assert entry["has_threats"] is True
    assert entry["agent_id"] == "openclaw"
    assert "/home/user/.ssh/id_rsa" in entry["input_preview"]
    assert "[READ]" in entry["input_preview"]
    assert "(rule: .ssh/**)" in entry["input_preview"]
    assert len(entry["sensitive"]) == 1
    assert entry["sensitive"][0]["type"] == "file_access_blocked"

    assert len(dashboard_api._analysis_log) == 1
    log_entry = dashboard_api._analysis_log[0]
    assert log_entry["level"] == "warn"
    assert "[PLUGIN BLOCK]" in log_entry["message"]


def test_push_external_event_log_mode_does_not_flag_threats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])
    monkeypatch.setattr(dashboard_api, "_analysis_log", [])

    payload = dashboard_api.ExternalEventPayload(
        source="plugin",
        action="log",
        threat_level="low",
        tool_name="read",
        file_path="/tmp/foo",
    )
    dashboard_api.push_external_event(payload)

    entry = dashboard_api._scan_history[0]
    assert entry["has_threats"] is False
    assert entry["action"] == "log"
    assert dashboard_api._analysis_log[0]["level"] == "info"


def test_push_external_event_uses_timestamp_when_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])
    monkeypatch.setattr(dashboard_api, "_analysis_log", [])

    payload = dashboard_api.ExternalEventPayload(
        timestamp="2026-05-07T12:00:00.000Z",
        action="log",
    )
    dashboard_api.push_external_event(payload)

    assert dashboard_api._scan_history[0]["timestamp"] == "2026-05-07T12:00:00.000Z"


@pytest.mark.asyncio
async def test_receive_external_event_route_surfaces_event_in_feed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])
    monkeypatch.setattr(dashboard_api, "_analysis_log", [])

    payload = dashboard_api.ExternalEventPayload(
        source="plugin",
        action="block",
        threat_level="critical",
        tool_name="exec",
        file_path="/etc/shadow",
    )
    result = await dashboard_api.receive_external_event(payload)

    assert result["ok"] is True
    assert "event_id" in result
    assert len(dashboard_api._scan_history) == 1
    assert dashboard_api._scan_history[0]["source"] == "plugin"


@pytest.mark.asyncio
async def test_openclaw_sanitize_endpoint_returns_sanitized_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_api, "_scan_history", [])
    monkeypatch.setattr(dashboard_api, "_analysis_log", [])

    result = await dashboard_api.sanitize_openclaw_prompt(
        dashboard_api.OpenClawSanitizePayload(text="email=alice@example.com")
    )

    assert result.success is True
    assert result.sanitized == "email=[EMAIL_1]"
    assert len(dashboard_api._scan_history) == 1
    assert dashboard_api._scan_history[0]["source"] == "openclaw-local-sanitize"


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
        self.running = True
        self.sessions_root = "/tmp/openclaw-agents"
        self.watch_roots = ("/tmp/openclaw-agents", "/root/.openclaw/agents")
        self.last_watch_error = "watch loop failed"

    def set_enabled(self, enabled: bool) -> None:
        self.enabled_updates.append(enabled)


@pytest.mark.asyncio
async def test_health_exposes_openclaw_runtime_state(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.openclaw.session_redaction.enabled = False
    service = _DummyOpenClawService()
    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(dashboard_api, "_openclaw_service", service)

    result = await dashboard_api.health()

    assert result["status"] == "ok"
    assert result["openclaw_session_redaction"] == {
        "enabled": False,
        "running": True,
        "sessions_root": "/tmp/openclaw-agents",
        "watch_roots": ["/tmp/openclaw-agents", "/root/.openclaw/agents"],
        "last_watch_error": "watch loop failed",
    }


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
    assert result["running"] is True
    assert result["sessions_root"] == "/tmp/openclaw-agents"
    assert result["watch_roots"] == ["/tmp/openclaw-agents", "/root/.openclaw/agents"]
    assert result["last_watch_error"] == "watch loop failed"


@pytest.mark.asyncio
async def test_agent_integrations_lists_openclaw_and_claude_code() -> None:
    from claw_vault.proxy.server import ProxyServer

    settings = Settings()
    proxy = ProxyServer(settings)
    dashboard_api.set_dependencies(
        audit_store=None,
        token_counter=None,
        budget_manager=None,
        settings=settings,
        rule_engine=proxy.rule_engine,
        openclaw_service=proxy.openclaw_service,
        proxy_server=proxy,
    )

    result = await dashboard_api.get_agent_integrations()
    statuses = {status["key"]: status for status in result}

    assert statuses["openclaw"]["enabled"] is True
    assert statuses["openclaw"]["capabilities"] == {"session_redaction": True}
    assert statuses["claude_code"]["name"] == "Claude Code"
    assert statuses["claude_code"]["enabled"] is False
    assert statuses["claude_code"]["capabilities"] == {"session_redaction": False}
    assert set(proxy.session_redaction_services) == {"openclaw"}


@pytest.mark.asyncio
async def test_generic_openclaw_session_redaction_matches_legacy_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    settings.openclaw.session_redaction.enabled = False
    service = _DummyOpenClawService()
    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(dashboard_api, "_openclaw_service", service)

    legacy = await dashboard_api.get_openclaw_session_redaction_config()
    generic = await dashboard_api.get_openclaw_integration_session_redaction_config()

    assert generic == legacy


@pytest.mark.asyncio
async def test_generic_openclaw_session_redaction_update_matches_legacy_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    settings.openclaw.session_redaction.enabled = False
    service = _DummyOpenClawService()
    monkeypatch.setattr(dashboard_api, "_settings", settings)
    monkeypatch.setattr(dashboard_api, "_openclaw_service", service)
    monkeypatch.setattr(dashboard_api, "_persist_config", lambda: None)

    result = await dashboard_api.update_openclaw_integration_session_redaction_config(
        dashboard_api.OpenClawSessionRedactionUpdate(enabled=True)
    )

    assert settings.openclaw.session_redaction.enabled is True
    assert service.enabled_updates == [True]
    assert result == await dashboard_api.get_openclaw_session_redaction_config()


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


@pytest.mark.asyncio
async def test_scan_history_includes_runtime_action_events(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from claw_vault.guard.runtime_action import (
        RuntimeAction,
        RuntimeActionType,
        SourceAgent,
        evaluate_runtime_action,
        runtime_action_audit_record,
    )

    store = AuditStore(tmp_path / "audit.db")
    await store.initialize()
    action = RuntimeAction(
        source_agent=SourceAgent.CLAUDE_CODE,
        tool_name="Bash",
        action_type=RuntimeActionType.SHELL_EXECUTE,
        input_summary="shell.execute",
        raw_input_for_local_detection="pwd",
        target="shell.execute",
        initiator_id="claude-code-hook",
        session_id="session-1",
    )
    await store.log(runtime_action_audit_record(action, evaluate_runtime_action(action)))

    monkeypatch.setattr(dashboard_api, "_audit_store", store)
    monkeypatch.setattr(dashboard_api, "_scan_history", [])

    result = await dashboard_api.get_scan_history(limit=10)
    await store.close()

    assert len(result) == 1
    event = result[0]
    assert event["source"] == "runtime_action"
    assert event["agent_name"] == "claude-code"
    assert event["tool_calls"][0]["name"] == "Bash"
    assert event["action"] == "allow"


@pytest.mark.asyncio
async def test_scan_history_runtime_action_redacts_sensitive_details(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from claw_vault.guard.runtime_action import (
        RuntimeAction,
        RuntimeActionType,
        SourceAgent,
        evaluate_runtime_action,
        runtime_action_audit_record,
    )

    secret = "sk" + "-proj-" + "abc123xyz456def789ghi012jkl345"
    store = AuditStore(tmp_path / "audit.db")
    await store.initialize()
    action = RuntimeAction(
        source_agent=SourceAgent.OPENCLAW,
        tool_name="Bash",
        action_type=RuntimeActionType.SHELL_EXECUTE,
        input_summary="shell.execute",
        raw_input_for_local_detection="echo " + secret,
        target="shell.execute",
        initiator_id="openclaw-agent",
        session_id="session-2",
    )
    await store.log(runtime_action_audit_record(action, evaluate_runtime_action(action)))

    monkeypatch.setattr(dashboard_api, "_audit_store", store)
    monkeypatch.setattr(dashboard_api, "_scan_history", [])

    result = await dashboard_api.get_scan_history(limit=10)
    await store.close()

    serialized = json.dumps(result, ensure_ascii=False)
    assert secret not in serialized
    assert result[0]["source"] == "runtime_action"
    assert result[0]["agent_name"] == "openclaw"
    assert result[0]["action"] == "block"
    assert result[0]["has_threats"] is True


@pytest.mark.asyncio
async def test_scan_history_includes_user_prompt_events(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from claw_vault.claude_code.user_prompt_api import (
        ClaudeCodeUserPromptRequest,
        _audit_record,
        _evaluate_user_prompt,
        set_user_prompt_dependencies,
    )
    from claw_vault.guard.rule_engine import RuleEngine

    clean_rules = RuleEngine()
    clean_rules.set_rules([])
    monkeypatch.setattr(
        dashboard_api,
        "get_agent_config",
        lambda agent_id: {
            "enabled": True,
            "guard_mode": "interactive",
            "auto_sanitize": True,
            "detection": {
                "enabled": True,
                "api_keys": True,
                "aws_credentials": True,
                "blockchain": True,
                "passwords": True,
                "private_ips": True,
                "pii": True,
                "jwt_tokens": True,
                "ssh_keys": True,
                "credit_cards": True,
                "emails": True,
                "generic_secrets": True,
                "dangerous_commands": True,
                "prompt_injection": True,
            },
        },
    )
    set_user_prompt_dependencies(rule_engine=clean_rules)
    secret = "sk" + "-proj-" + "abc123xyz456def789ghi012jkl345"
    store = AuditStore(tmp_path / "audit.db")
    await store.initialize()
    payload = ClaudeCodeUserPromptRequest(
        prompt="Use token " + secret,
        agent_id="claude-code-hook",
        session_id="session-3",
    )
    await store.log(_audit_record(payload, _evaluate_user_prompt(payload)))

    monkeypatch.setattr(dashboard_api, "_audit_store", store)
    monkeypatch.setattr(dashboard_api, "_scan_history", [])

    result = await dashboard_api.get_scan_history(limit=10)
    await store.close()

    serialized = json.dumps(result, ensure_ascii=False)
    assert secret not in serialized
    assert len(result) == 1
    event = result[0]
    assert event["source"] == "user_prompt"
    assert event["agent_name"] == "claude-code"
    assert event["message_count"] == 1
    assert event["tool_call_count"] == 0
    assert event["action"] == "sanitize"
    assert event["has_threats"] is True


@pytest.mark.asyncio
async def test_monitor_overview_includes_user_prompt_and_runtime_action_audit(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from claw_vault.claude_code.user_prompt_api import (
        ClaudeCodeUserPromptRequest,
        _audit_record,
        _evaluate_user_prompt,
        set_user_prompt_dependencies,
    )
    from claw_vault.guard.rule_engine import RuleEngine
    from claw_vault.guard.runtime_action import (
        RuntimeAction,
        RuntimeActionType,
        SourceAgent,
        evaluate_runtime_action,
        runtime_action_audit_record,
    )

    clean_rules = RuleEngine()
    clean_rules.set_rules([])
    monkeypatch.setattr(
        dashboard_api,
        "get_agent_config",
        lambda agent_id: {
            "enabled": True,
            "guard_mode": "interactive",
            "auto_sanitize": True,
            "detection": {
                "enabled": True,
                "api_keys": True,
                "aws_credentials": True,
                "blockchain": True,
                "passwords": True,
                "private_ips": True,
                "pii": True,
                "jwt_tokens": True,
                "ssh_keys": True,
                "credit_cards": True,
                "emails": True,
                "generic_secrets": True,
                "dangerous_commands": True,
                "prompt_injection": True,
            },
        },
    )
    set_user_prompt_dependencies(rule_engine=clean_rules)
    store = AuditStore(tmp_path / "audit.db")
    await store.initialize()
    prompt_payload = ClaudeCodeUserPromptRequest(
        prompt="rm " + "-rf",
        agent_id="claude-code-hook",
        session_id="session-4",
    )
    await store.log(_audit_record(prompt_payload, _evaluate_user_prompt(prompt_payload)))
    action = RuntimeAction(
        source_agent=SourceAgent.CLAUDE_CODE,
        tool_name="Bash",
        action_type=RuntimeActionType.SHELL_EXECUTE,
        input_summary="shell.execute",
        raw_input_for_local_detection="pwd",
        target="shell.execute",
        initiator_id="claude-code-hook",
        session_id="session-4",
    )
    await store.log(runtime_action_audit_record(action, evaluate_runtime_action(action)))

    monkeypatch.setattr(dashboard_api, "_audit_store", store)
    monkeypatch.setattr(dashboard_api, "_scan_history", [])

    overview = await dashboard_api.get_monitor_overview()
    log_stream = await dashboard_api.get_monitor_log_stream(limit=10)
    security_events = await dashboard_api.get_monitor_security_events(limit=10)
    await store.close()

    assert overview["scan_count"] == 2
    assert overview["message_count"] == 1
    assert overview["tool_call_count"] == 1
    assert overview["warning_count"] == 1
    assert overview["block_count"] == 0
    assert overview["allow_count"] == 1
    assert any("user_prompt" in item["message"] for item in log_stream)
    assert any("runtime_action" in item["message"] for item in log_stream)
    assert any("[PROMPT]" in item["summary"] for item in security_events)


def test_run_scan_returns_block_action_for_strict_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from claw_vault.guard.rule_engine import RuleEngine

    clean_re = RuleEngine()
    clean_re.set_rules([])
    monkeypatch.setattr(dashboard_api, "_rule_engine", clean_re)
    monkeypatch.setattr(
        dashboard_api,
        "get_agent_config",
        lambda agent_id: {
            "enabled": True,
            "guard_mode": "strict",
            "auto_sanitize": True,
            "detection": {
                "enabled": True,
                "api_keys": True,
                "aws_credentials": True,
                "blockchain": True,
                "passwords": True,
                "private_ips": True,
                "pii": True,
                "jwt_tokens": True,
                "ssh_keys": True,
                "credit_cards": True,
                "emails": True,
                "generic_secrets": True,
                "dangerous_commands": True,
                "prompt_injection": True,
            },
        },
    )
    sample = "password=" + "MyS3cret" + "P@ssw0rd"

    result = dashboard_api._run_scan(sample)

    assert result["has_threats"] is True
    assert result["action"] == "block"
    assert "Strict mode" in result["reason"]
