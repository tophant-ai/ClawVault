"""Tests for canonical ClawVault config template loading."""
# ruff: noqa: S101

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from claw_vault.config_template import get_default_config, get_default_config_text

REQUIRED_SECTIONS = {
    "proxy",
    "detection",
    "guard",
    "monitor",
    "audit",
    "dashboard",
    "cloud",
    "openclaw",
    "file_monitor",
    "rules",
    "agents",
    "vaults",
}


def test_default_config_template_loads_complete_yaml():
    config = get_default_config()

    assert REQUIRED_SECTIONS <= set(config)
    assert config["file_monitor"]["watch_project_sensitive"] is True
    assert config["detection"]["api_keys"] is True
    assert "check_sensitive" not in config["detection"]


def test_default_config_template_intercepts_minimax_hosts():
    config = get_default_config()

    intercept_hosts = config["proxy"]["intercept_hosts"]
    assert "api.minimax.io" in intercept_hosts
    assert "api.minimaxi.com" in intercept_hosts


def test_default_config_text_is_parseable_yaml():
    text = get_default_config_text()
    config = yaml.safe_load(text)

    assert isinstance(config, dict)
    assert config["file_monitor"]["watch_project_sensitive"] is True


def test_package_resource_contains_config_template():
    template = resources.files("claw_vault").joinpath("config.example.yaml")

    assert template.is_file()
    assert "watch_project_sensitive" in template.read_text(encoding="utf-8")


def test_root_and_package_config_templates_match():
    repo_root = Path(__file__).resolve().parents[1]
    root_template = repo_root / "config.example.yaml"
    package_template = repo_root / "src" / "claw_vault" / "config.example.yaml"

    assert root_template.read_text(encoding="utf-8") == package_template.read_text(encoding="utf-8")
