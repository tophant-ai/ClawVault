"""Tests for deleting ClawVault transcript error blocks."""

from __future__ import annotations

from claw_vault.openclaw.file_redactor import SessionFileRedactor


class TestSessionFileRedactor:
    """Verify the target line and its predecessor are removed together."""

    def test_redact_clawvault_error_pairs_deletes_current_and_previous_lines(self) -> None:
        content = (
            b'{"type":"user","content":"hello"}\n'
            b'{"type":"assistant","content":"working"}\n'
            b'{"errorMessage":"403 [ClawVault] blocked"}\n'
            b'{"type":"assistant","content":"after"}\n'
        )
        redactor = SessionFileRedactor()

        result = redactor.redact_clawvault_error_pairs(content)

        assert result.changed is True
        assert result.deleted_line_count == 2
        assert result.scanned_line_count == 4
        assert result.content == (
            b'{"type":"user","content":"hello"}\n{"type":"assistant","content":"after"}\n'
        )

    def test_redact_clawvault_error_pairs_json_spacing_expected_deleted(self) -> None:
        content = (
            b'{"type":"assistant","content":"before"}\n'
            b'{"event": {"errorMessage": "403 [ClawVault] blocked by policy"}}\n'
        )
        redactor = SessionFileRedactor()

        result = redactor.redact_clawvault_error_pairs(content)

        assert result.changed is True
        assert result.deleted_line_count == 2
        assert result.content == b""

    def test_redact_clawvault_error_pairs_partial_tail_expected_wait_for_newline(self) -> None:
        content = (
            b'{"type":"assistant","content":"before"}\n{"errorMessage":"403 [ClawVault] blocked"}'
        )
        redactor = SessionFileRedactor()

        result = redactor.redact_clawvault_error_pairs(content)

        assert result.changed is False
        assert result.deleted_line_count == 0
        assert result.scanned_line_count == 1
        assert result.content == content
