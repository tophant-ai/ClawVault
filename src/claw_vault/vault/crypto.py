"""Encryption utilities for credential storage."""

from __future__ import annotations

import base64
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import structlog

logger = structlog.get_logger()


class CryptoEngine:
    """AES-256 encryption engine for credential storage.

    Uses Fernet (AES-128-CBC with HMAC-SHA256) for symmetric encryption.
    Key is derived from a master password using PBKDF2.
    """

    def __init__(self, master_password: str | None = None) -> None:
        if master_password:
            self._fernet = self._derive_key(master_password)
        else:
            # Generate a random key for session-only encryption
            self._fernet = Fernet(Fernet.generate_key())

    @staticmethod
    def _derive_key(password: str, salt: bytes | None = None) -> Fernet:
        """Derive encryption key from master password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string value. Returns base64-encoded ciphertext."""
        return str(self._fernet.encrypt(plaintext.encode()).decode())

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64-encoded ciphertext. Returns plaintext string."""
        return str(self._fernet.decrypt(ciphertext.encode()).decode())

    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(16)

    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token."""
        return secrets.token_urlsafe(length)
