"""Shared test fixtures for ClawVault tests."""

import pytest

from claw_vault.detector.engine import DetectionEngine
from claw_vault.detector.sensitive import SensitiveDetector
from claw_vault.detector.command import CommandDetector
from claw_vault.detector.injection import InjectionDetector
from claw_vault.sanitizer.replacer import Sanitizer
from claw_vault.sanitizer.restorer import Restorer
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.monitor.token_counter import TokenCounter


@pytest.fixture(autouse=True)
def _isolate_user_rules(monkeypatch):
    """Prevent tests from accidentally loading user rules from ~/.ClawVault/."""
    monkeypatch.setattr("claw_vault.guard.rule_engine.load_rules", lambda: [])


@pytest.fixture
def sensitive_detector():
    return SensitiveDetector()


@pytest.fixture
def command_detector():
    return CommandDetector()


@pytest.fixture
def injection_detector():
    return InjectionDetector()


@pytest.fixture
def detection_engine():
    return DetectionEngine()


@pytest.fixture
def sanitizer():
    return Sanitizer()


@pytest.fixture
def restorer():
    return Restorer()


@pytest.fixture
def rule_engine():
    return RuleEngine(mode="interactive")


@pytest.fixture
def token_counter():
    return TokenCounter()
