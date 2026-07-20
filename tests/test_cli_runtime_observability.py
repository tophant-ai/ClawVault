from __future__ import annotations

# ruff: noqa: S101, S105
import asyncio
import json
from datetime import datetime

from typer.testing import CliRunner

from claw_vault.audit.models import AuditRecord
from claw_vault.audit.store import AuditStore
from claw_vault.cli import app

SECRET = "sk-proj-cli-observability-secret"


def _write_records(db_path, records: list[AuditRecord]) -> None:
    async def _write() -> None:
        store = AuditStore(db_path)
        await store.initialize()
        for record in records:
            await store.log(record)
        await store.close()

    asyncio.run(_write())


def _runtime_record(**details):
    payload = {
        "event_type": "runtime_action_guard",
        "source_agent": "openclaw",
        "tool_name": "Write",
        "action_type": "file.write",
        "decision": "block",
        "risk_level": "high",
        "target_summary": "write .env",
        "redacted_summary": "write .env",
        "categories": ["sensitive_path"],
        "reasons": ["Sensitive file path"],
        "raw_payload": SECRET,
    }
    payload.update(details)
    return AuditRecord(
        timestamp=datetime(2026, 1, 2, 3, 4, 5),
        session_id="session-1",
        direction="runtime_action",
        risk_level="high",
        action_taken=payload["decision"],
        details=json.dumps(payload),
        agent_name="openclaw",
    )


def test_events_filters_runtime_action_guard_and_redacts_details(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(
        db_path,
        [
            AuditRecord(
                timestamp=datetime(2026, 1, 2, 3, 4, 4),
                details=json.dumps({"event_type": "provider_proxy", "raw_payload": SECRET}),
            ),
            _runtime_record(),
        ],
    )
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)

    result = CliRunner().invoke(app, ["events", "--type", "runtime_action_guard", "--last", "20"])

    assert result.exit_code == 0
    assert "Runtime Action Guard Events" in result.output
    assert "Write" in result.output
    assert "write" in result.output
    assert ".env" in result.output
    assert "provider_proxy" not in result.output
    assert SECRET not in result.output
    assert "raw_payload" not in result.output


def test_events_never_outputs_shell_command_summary(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    command = "echo sk-proj-cli-command-secret"
    _write_records(
        db_path,
        [
            _runtime_record(
                tool_name="Bash",
                action_type="shell.execute",
                target_summary=command,
                redacted_summary=command,
            )
        ],
    )
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)

    result = CliRunner().invoke(app, ["events", "--type", "runtime_action_guard", "--last", "1"])

    assert result.exit_code == 0
    assert "Bash" in result.output
    assert command not in result.output
    assert "sk-proj-cli-command-secret" not in result.output


def test_events_json_outputs_only_safe_fields(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(db_path, [_runtime_record()])
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)

    result = CliRunner().invoke(
        app,
        ["events", "--type", "runtime_action_guard", "--last", "1", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["tool_name"] == "Write"
    assert payload[0]["redacted_summary"] == "write .env"
    assert "raw_payload" not in payload[0]
    assert SECRET not in result.output


def test_events_handles_empty_audit_store(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(db_path, [])
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)

    result = CliRunner().invoke(app, ["events", "--type", "runtime_action_guard", "--last", "5"])

    assert result.exit_code == 0
    assert "No runtime_action_guard events found" in result.output


def test_events_handles_missing_audit_store(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "missing-audit.db"
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)

    result = CliRunner().invoke(app, ["events", "--type", "runtime_action_guard", "--last", "5"])

    assert result.exit_code == 0
    assert "No runtime_action_guard events found" in result.output
    assert not db_path.exists()


def test_runtime_status_uses_get_route_probe_and_reads_latest_event(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(db_path, [_runtime_record(tool_name="Bash", action_type="shell.execute")])
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)
    monkeypatch.setattr("claw_vault.cli._socket_open", lambda host, port: True)

    requested_urls = []

    def fake_get_status(url: str, timeout: float = 1.5) -> int:
        requested_urls.append(url)
        if url.endswith("/api/openclaw/runtime-action"):
            return 405
        return 200

    monkeypatch.setattr("claw_vault.cli._http_get_status", fake_get_status)

    result = CliRunner().invoke(app, ["runtime", "status"])

    assert result.exit_code == 0
    assert "Runtime Action Guard Status" in result.output
    assert "mounted" in result.output
    assert "Bash block (high)" in result.output
    assert requested_urls == [
        "http://127.0.0.1:8766/api/health",
        "http://127.0.0.1:8766/api/openclaw/runtime-action",
    ]


def test_runtime_status_handles_unreachable_health_and_runtime_route(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(db_path, [])
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)
    monkeypatch.setattr("claw_vault.cli._socket_open", lambda host, port: True)
    monkeypatch.setattr("claw_vault.cli._http_get_status", lambda url, timeout=1.5: None)

    result = CliRunner().invoke(app, ["runtime", "status"])

    assert result.exit_code == 0
    assert "Health endpoint" in result.output
    assert "unreachable" in result.output
    assert "Runtime API route" in result.output
    assert "unknown" in result.output


def test_runtime_status_ignores_openclaw_absence(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "missing-audit.db"
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)
    monkeypatch.setattr("claw_vault.cli._socket_open", lambda host, port: False)

    result = CliRunner().invoke(app, ["runtime", "status"])

    assert result.exit_code == 0
    assert "Runtime Action Guard Status" in result.output
    assert "Stopped" in result.output
    assert "none found" in result.output
    assert not db_path.exists()


def test_runtime_status_json_does_not_probe_with_post(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "audit.db"
    _write_records(db_path, [])
    monkeypatch.setattr("claw_vault.cli._audit_db_path", lambda config_file=None: db_path)
    monkeypatch.setattr("claw_vault.cli._socket_open", lambda host, port: False)

    def fail_if_called(url: str, timeout: float = 1.5) -> int:
        raise AssertionError("HTTP probe should not run when dashboard socket is closed")

    monkeypatch.setattr("claw_vault.cli._http_get_status", fail_if_called)

    result = CliRunner().invoke(app, ["runtime", "status", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["dashboard"]["running"] is False
    assert payload["runtime_action_api"]["get_status"] is None
    assert payload["audit"]["latest_runtime_action_event"] is None
