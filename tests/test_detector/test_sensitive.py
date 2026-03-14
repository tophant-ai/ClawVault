"""Tests for sensitive data detection."""

import pytest

from claw_vault.detector.sensitive import SensitiveDetector
from claw_vault.detector.patterns import PatternCategory


class TestSensitiveDetector:
    def test_detect_openai_key(self, sensitive_detector):
        text = "My key is sk-proj-abc123xyz456def789ghi012jkl345"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.API_KEY for r in results)

    def test_detect_aws_access_key(self, sensitive_detector):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.AWS_CREDENTIAL for r in results)

    def test_detect_password(self, sensitive_detector):
        text = 'password = "MyS3cretP@ssw0rd"'
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.PASSWORD for r in results)

    def test_detect_private_ip(self, sensitive_detector):
        text = "Server is at 192.168.1.100"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.PRIVATE_IP for r in results)

    def test_detect_jwt_token(self, sensitive_detector):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.JWT_TOKEN for r in results)

    def test_detect_database_uri(self, sensitive_detector):
        text = "mongodb://admin:secretPass@prod-db.company.com:27017/production"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1

    def test_detect_github_token(self, sensitive_detector):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.API_KEY for r in results)

    def test_detect_ssh_key(self, sensitive_detector):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.SSH_KEY for r in results)

    def test_detect_china_phone(self, sensitive_detector):
        text = "联系电话：13812345678"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.PHONE_CN for r in results)

    def test_detect_china_id_card(self, sensitive_detector):
        text = "身份证号：320123199001011234"
        results = sensitive_detector.detect(text)
        assert len(results) >= 1
        assert any(r.category == PatternCategory.ID_CARD_CN for r in results)

    def test_no_false_positive_on_clean_text(self, sensitive_detector):
        text = "Hello, please help me write a Python function to sort a list."
        results = sensitive_detector.detect(text)
        assert len(results) == 0

    def test_multiple_detections(self, sensitive_detector):
        text = (
            "Connect to 192.168.1.100 with password=MyP@ss123 "
            "using key sk-proj-abc123xyz456def789ghi012jkl345"
        )
        results = sensitive_detector.detect(text)
        assert len(results) >= 2

    def test_custom_pattern(self, sensitive_detector):
        sensitive_detector.add_custom_pattern("internal_id", r"INTERNAL-\d{8}", risk_score=6.0)
        results = sensitive_detector.detect("ID is INTERNAL-12345678")
        assert len(results) >= 1
        assert any("custom" in r.pattern_type for r in results)

    def test_deduplication(self, sensitive_detector):
        text = "sk-proj-abc123xyz456def789ghi012jkl345"
        results = sensitive_detector.detect(text)
        # Should not have duplicate detections for the same position
        positions = [(r.start, r.end) for r in results]
        assert len(positions) == len(set(positions))
