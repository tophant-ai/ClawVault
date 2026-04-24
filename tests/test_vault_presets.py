"""Tests for builtin vault presets."""

import pytest

from claw_vault.config import VaultPreset, get_builtin_presets


VALID_GUARD_MODES = {"permissive", "interactive", "strict"}
VALID_ACTIONS = {"allow", "block", "sanitize", "ask_user"}


@pytest.fixture(scope="module")
def presets() -> list[VaultPreset]:
    return get_builtin_presets()


def test_presets_load_and_have_unique_ids(presets: list[VaultPreset]) -> None:
    assert len(presets) >= 5, "expected at least the 5 original presets"
    ids = [p.id for p in presets]
    assert len(ids) == len(set(ids)), f"duplicate preset ids: {ids}"


def test_all_presets_are_builtin_and_validate(presets: list[VaultPreset]) -> None:
    for p in presets:
        assert p.builtin is True, f"{p.id} should be builtin"
        VaultPreset.model_validate(p.model_dump())


def test_all_guard_modes_valid(presets: list[VaultPreset]) -> None:
    for p in presets:
        assert p.guard["mode"] in VALID_GUARD_MODES, (
            f"{p.id} has invalid guard mode {p.guard['mode']!r}"
        )


def test_all_detection_configs_have_enabled_flag(presets: list[VaultPreset]) -> None:
    for p in presets:
        assert isinstance(p.detection.get("enabled"), bool), (
            f"{p.id} detection.enabled missing or not bool"
        )


def test_all_rule_actions_valid_and_unique(presets: list[VaultPreset]) -> None:
    for p in presets:
        rule_ids = [r["id"] for r in p.rules]
        assert len(rule_ids) == len(set(rule_ids)), f"{p.id} has duplicate rule ids"
        for rule in p.rules:
            assert rule["action"] in VALID_ACTIONS, (
                f"{p.id} rule {rule.get('id')} has invalid action {rule['action']!r}"
            )


def test_strict_presets_block_or_sanitize(presets: list[VaultPreset]) -> None:
    """Strict-mode presets should enforce at least one blocking/sanitizing rule."""
    strict_presets = [p for p in presets if p.guard.get("mode") == "strict"]
    assert strict_presets, "expected at least one strict preset"
    for p in strict_presets:
        actions = {r["action"] for r in p.rules}
        assert actions & {"block", "sanitize"}, (
            f"{p.id} is strict but has no blocking/sanitizing rules"
        )


def test_audit_only_is_permissive(presets: list[VaultPreset]) -> None:
    p = next(p for p in presets if p.id == "audit-only")
    assert p.guard["mode"] == "permissive"
    actions = {r["action"] for r in p.rules}
    assert "allow" in actions
