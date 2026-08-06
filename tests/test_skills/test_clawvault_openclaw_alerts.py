from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "skills" / "tophant-clawvault-openclaw-alerts" / "clawvault_openclaw_alerts.py"
spec = importlib.util.spec_from_file_location("clawvault_openclaw_alerts", MODULE_PATH)
alerts = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(alerts)


def test_default_config_contains_privacy_defaults():
    cfg = alerts.default_config()

    assert cfg["alerts"]["include_input_preview"] is False
    assert cfg["alerts"]["include_file_path"] is False
    assert cfg["alerts"]["risk_threshold"] == 7.0
    assert cfg["openclaw"]["agent_id"] == "main"


def test_deep_merge_preserves_unspecified_defaults():
    cfg = alerts.default_config()
    alerts.deep_merge(cfg, {"openclaw": {"agent_id": "security"}})

    assert cfg["openclaw"]["agent_id"] == "security"
    assert cfg["openclaw"]["session_id"] == "clawvault-alerts"


def test_high_risk_detection_by_level_risk_and_action():
    classifier = alerts.EventClassifier(alerts.default_config())

    assert classifier.is_high_risk({"source": "proxy", "threat_level": "high", "action": "allow", "max_risk_score": 1})
    assert classifier.is_high_risk({"source": "proxy", "threat_level": "low", "action": "allow", "max_risk_score": 8})
    assert classifier.is_high_risk({"source": "proxy", "threat_level": "low", "action": "block", "max_risk_score": 1})
    assert not classifier.is_high_risk({"source": "proxy", "threat_level": "low", "action": "allow", "max_risk_score": 1})


def test_source_filter_blocks_unknown_sources():
    classifier = alerts.EventClassifier(alerts.default_config())

    assert not classifier.is_high_risk({"source": "unknown", "threat_level": "critical", "action": "block", "max_risk_score": 10})


def test_dedup_key_prefers_event_id():
    classifier = alerts.EventClassifier(alerts.default_config())

    assert classifier.dedup_key({"source": "proxy", "id": "abc"}) == "proxy:abc"


def test_dedup_key_hashes_without_storing_preview():
    classifier = alerts.EventClassifier(alerts.default_config())
    event = {"source": "proxy", "timestamp": "now", "input_preview": "secret sk-proj-abcdef1234567890"}

    key = classifier.dedup_key(event)

    assert key.startswith("hash:")
    assert "sk-proj" not in key


def test_redact_removes_common_secrets():
    classifier = alerts.EventClassifier(alerts.default_config())
    text = "key sk-proj-abcdef1234567890 aws AKIAIOSFODNN7EXAMPLE db postgresql://user:pass@example/db"

    redacted = classifier.redact(text)

    assert "sk-proj-abcdef" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "user:pass" not in redacted


def test_summarize_event_hides_preview_and_path_by_default():
    classifier = alerts.EventClassifier(alerts.default_config())
    event = {
        "source": "openclaw-file-guard",
        "threat_level": "high",
        "action": "block",
        "max_risk_score": 8.5,
        "total_detections": 1,
        "agent_id": "main",
        "session_id": "abcdef1234567890",
        "timestamp": "2026-05-28T00:00:00Z",
        "file_path": "/home/user/.ssh/id_rsa",
        "input_preview": "secret sk-proj-abcdef1234567890",
    }

    message = classifier.summarize_event(event)

    assert "/home/user" not in message
    assert "sk-proj" not in message
    assert "OpenClaw" not in message or "ClawVault" in message


def test_rate_limiter_limits_per_minute(tmp_path):
    cfg = alerts.default_config()
    cfg["alerts"]["max_alerts_per_minute"] = 1
    cfg["alerts"]["max_alerts_per_hour"] = 10
    state = alerts.StateStore(tmp_path / "state.json")
    limiter = alerts.RateLimiter(cfg, state)

    assert limiter.allow(1000)[0] is True
    state.record_send(1000)
    allowed, reason = limiter.allow(1001)

    assert allowed is False
    assert reason == "minute_rate_limit"


def test_openclaw_notifier_uses_argv_not_shell(monkeypatch):
    cfg = alerts.default_config()
    cfg["openclaw"]["deliver"] = True
    cfg["openclaw"]["channel"] = "slack"
    cfg["openclaw"]["reply_to"] = "#security"
    calls = []

    def fake_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setattr(alerts.subprocess, "run", fake_run)

    result = alerts.OpenClawNotifier(cfg).send_message("hello")

    assert result["success"] is True
    assert isinstance(calls[0], list)
    assert "--message" in calls[0]
    assert "hello" in calls[0]
    assert "--deliver" in calls[0]
    assert "--channel" in calls[0]
    assert "slack" in calls[0]
    assert "--reply-to" in calls[0]


def test_run_once_dry_run_does_not_write_state(tmp_path):
    cfg = alerts.default_config()
    cfg["daemon"]["state_file"] = str(tmp_path / "state.json")
    daemon = alerts.AlertDaemon(cfg, tmp_path / "config.yaml")
    daemon.client.get_scan_history = lambda limit: [
        {"source": "proxy", "id": "e1", "threat_level": "high", "action": "block", "max_risk_score": 9}
    ]

    result = daemon.run_once(dry_run=True)

    assert result["sent_count"] == 1
    assert not (tmp_path / "state.json").exists()


def test_daily_report_redacts_sensitive_event_data():
    cfg = alerts.default_config()
    classifier = alerts.EventClassifier(cfg)

    class Client:
        def get_summary(self):
            return {"total_requests": 1, "blocks": 1, "max_risk_score": 9}

        def get_budget(self):
            return {"daily_used": 10, "daily_limit": 100, "cost_usd": 0.01}

        def get_monitor_overview(self):
            return {}

        def get_scan_history(self, limit):
            return [{"source": "proxy", "id": "e1", "threat_level": "high", "action": "block", "max_risk_score": 9, "input_preview": "sk-proj-abcdef1234567890"}]

        def get_local_scan_history(self, limit):
            return []

        def get_file_monitor_alerts(self, limit):
            return []

    report = alerts.DailyReportBuilder(cfg, Client(), classifier).build("2026-05-28")

    assert "sk-proj" not in report
    assert "ClawVault 安全日报 2026-05-28" in report


def test_state_cleanup_expires_old_events(tmp_path):
    state = alerts.StateStore(tmp_path / "state.json")
    state.state["sent_events"]["old"] = {"sent_at": 0}
    state.state["sent_events"]["new"] = {"sent_at": 100}

    state.cleanup(now=120, ttl_seconds=60)

    assert "old" not in state.state["sent_events"]
    assert "new" in state.state["sent_events"]


def test_status_reports_dashboard_unreachable(tmp_path):
    cfg = alerts.default_config()
    cfg["daemon"]["state_file"] = str(tmp_path / "state.json")
    cfg["daemon"]["pid_file"] = str(tmp_path / "daemon.pid")
    daemon = alerts.AlertDaemon(cfg, tmp_path / "config.yaml")
    daemon.client.health_check = lambda: {"reachable": False, "error": "down"}

    status = daemon.status()

    assert status["success"] is True
    assert status["dashboard"]["reachable"] is False
