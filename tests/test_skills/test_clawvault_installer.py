"""Tests for the ClawVault installer Skill."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

from claw_vault.skills.clawvault_installer import (
    CLAWVAULT_GITHUB_REF,
    CLAWVAULT_GITHUB_SPEC,
    CLAWVAULT_PIP_SPEC,
    DEFAULT_DASHBOARD_HOST,
    ClawVaultInstallerSkill,
)


class _RunRecorder:
    def __init__(self, returncodes: list[int], stderrs: list[str] | None = None) -> None:
        self.returncodes = returncodes
        self.stderrs = stderrs or []
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        index = len(self.calls) - 1
        returncode = self.returncodes[index] if index < len(self.returncodes) else 0
        stderr = self.stderrs[index] if index < len(self.stderrs) else ""
        return subprocess.CompletedProcess(command, returncode, stdout="", stderr=stderr)


def test_install_package_uses_pinned_pypi_spec(monkeypatch):
    skill = ClawVaultInstallerSkill()
    recorder = _RunRecorder([0])
    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(skill, "_get_installed_version", lambda: "0.1.0")

    result = skill._install_package()

    assert result["success"] is True
    assert result["source"] == "pypi"
    assert result["spec"] == CLAWVAULT_PIP_SPEC
    assert recorder.calls[0][-1] == CLAWVAULT_PIP_SPEC


def test_install_package_falls_back_to_pinned_github_ref(monkeypatch):
    skill = ClawVaultInstallerSkill()
    recorder = _RunRecorder([1, 0], ["pypi unavailable", ""])
    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(skill, "_get_installed_version", lambda: "0.1.0")

    result = skill._install_package()

    assert result["success"] is True
    assert result["source"] == "github"
    assert result["spec"] == CLAWVAULT_GITHUB_SPEC
    assert result["github_ref"] == CLAWVAULT_GITHUB_REF
    assert recorder.calls[1][-1] == CLAWVAULT_GITHUB_SPEC


def test_install_package_reports_all_failed_attempts(monkeypatch):
    skill = ClawVaultInstallerSkill()
    recorder = _RunRecorder([1, 1], ["pypi failed", "github failed"])
    monkeypatch.setattr(subprocess, "run", recorder)

    result = skill._install_package()

    assert result["success"] is False
    assert CLAWVAULT_PIP_SPEC in result["attempts"][0]["command"]
    assert CLAWVAULT_GITHUB_SPEC in result["attempts"][1]["command"]
    assert result["stderr"] == "github failed"


def test_initialize_config_uses_localhost_dashboard(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    skill = ClawVaultInstallerSkill()

    result = skill._initialize_config("quick", None)

    assert result["success"] is True
    config = yaml.safe_load(Path(result["config_path"]).read_text())
    assert config["dashboard"]["host"] == DEFAULT_DASHBOARD_HOST
    assert config["proxy"]["host"] == "127.0.0.1"


def test_install_clawvault_fails_when_config_initialization_fails(monkeypatch):
    skill = ClawVaultInstallerSkill()
    monkeypatch.setattr(skill, "_is_clawvault_installed", lambda: False)
    monkeypatch.setattr(skill, "_check_prerequisites", lambda: {"success": True})
    monkeypatch.setattr(skill, "_quick_install", lambda: {"success": True, "version": "0.1.0"})
    monkeypatch.setattr(
        skill,
        "_initialize_config",
        lambda mode, config: {"success": False, "error": "permission denied"},
    )

    result = skill.install_clawvault("quick")

    assert result.success is False
    assert "configuration failed" in result.message
    assert result.data["config"]["error"] == "permission denied"
