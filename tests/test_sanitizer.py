"""Tests for sanitizer (replace) and restorer (restore) modules."""

import pytest

from claw_vault.detector.sensitive import SensitiveDetector
from claw_vault.sanitizer.replacer import Sanitizer
from claw_vault.sanitizer.restorer import Restorer


class TestSanitizer:
    def test_sanitize_api_key(self, sensitive_detector, sanitizer):
        text = "My key is sk-proj-abc123xyz456def789ghi012jkl345"
        detections = sensitive_detector.detect(text)
        sanitized = sanitizer.sanitize(text, detections)
        assert "sk-proj-abc123xyz456def789ghi012jkl345" not in sanitized
        assert "[API_KEY_" in sanitized

    def test_sanitize_multiple(self, sensitive_detector, sanitizer):
        text = "password=Secret123 server=192.168.1.100"
        detections = sensitive_detector.detect(text)
        sanitized = sanitizer.sanitize(text, detections)
        assert "Secret123" not in sanitized
        assert "192.168.1.100" not in sanitized

    def test_sanitize_preserves_clean_text(self, sanitizer):
        text = "Hello, this is normal text."
        sanitized = sanitizer.sanitize(text, [])
        assert sanitized == text

    def test_mapping_created(self, sensitive_detector, sanitizer):
        text = "key: sk-proj-abc123xyz456def789ghi012jkl345"
        detections = sensitive_detector.detect(text)
        sanitizer.sanitize(text, detections)
        mapping = sanitizer.mapping
        assert len(mapping) >= 1
        assert any("sk-proj" in v for v in mapping.values())

    def test_same_value_reuses_placeholder(self, sensitive_detector, sanitizer):
        text1 = "Use sk-proj-abc123xyz456def789ghi012jkl345 here"
        text2 = "Also sk-proj-abc123xyz456def789ghi012jkl345 there"
        det1 = sensitive_detector.detect(text1)
        det2 = sensitive_detector.detect(text2)
        sanitizer.sanitize(text1, det1)
        san2 = sanitizer.sanitize(text2, det2)
        # Should reuse same placeholder
        assert len(sanitizer.mapping) == 1

    def test_clear(self, sanitizer):
        sanitizer._mapping["[TEST_1]"] = "secret"
        sanitizer.clear()
        assert len(sanitizer.mapping) == 0


class TestRestorer:
    def test_restore_placeholders(self, restorer):
        text = "Check [API_KEY_1] and [IP_ADDR_1]"
        mapping = {"[API_KEY_1]": "sk-test-123", "[IP_ADDR_1]": "10.0.0.1"}
        restored = restorer.restore(text, mapping)
        assert "sk-test-123" in restored
        assert "10.0.0.1" in restored
        assert "[API_KEY_1]" not in restored

    def test_restore_empty_mapping(self, restorer):
        text = "No placeholders here"
        restored = restorer.restore(text, {})
        assert restored == text

    def test_find_placeholders(self, restorer):
        text = "Found [API_KEY_1] and [CREDENTIAL_2] in text"
        found = restorer.find_placeholders(text)
        assert len(found) == 2


class TestSanitizeRestoreRoundtrip:
    def test_roundtrip(self, sensitive_detector, sanitizer, restorer):
        original = "Connect with password=MyS3cret and key sk-proj-abc123xyz456def789ghi012jkl345"
        detections = sensitive_detector.detect(original)
        sanitized = sanitizer.sanitize(original, detections)

        # Verify sanitization produced placeholders
        assert sanitizer.mapping, "Sanitizer should have created placeholder mappings"

        # Simulate AI response that includes a placeholder from the mapping
        placeholder = next(iter(sanitizer.mapping))
        ai_response = f"The issue is with your credentials: check {placeholder} validity"
        restored = restorer.restore(ai_response, sanitizer.mapping)

        # Original value should be restored
        assert sanitizer.mapping[placeholder] in restored
