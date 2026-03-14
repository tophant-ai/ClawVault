"""Detection pattern definitions for sensitive data identification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    API_KEY = "api_key"
    AWS_CREDENTIAL = "aws_credential"
    PASSWORD = "password"
    PRIVATE_IP = "private_ip"
    JWT_TOKEN = "jwt_token"
    SSH_KEY = "ssh_key"
    DATABASE_URI = "database_uri"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE_CN = "phone_cn"
    ID_CARD_CN = "id_card_cn"
    BLOCKCHAIN_WALLET = "blockchain_wallet"
    BLOCKCHAIN_PRIVATE_KEY = "blockchain_private_key"
    BLOCKCHAIN_MNEMONIC = "blockchain_mnemonic"
    GENERIC_SECRET = "generic_secret"


@dataclass
class DetectionPattern:
    category: PatternCategory
    name: str
    regex: re.Pattern[str]
    risk_score: float
    description: str
    enabled: bool = True


@dataclass
class DetectionResult:
    pattern_type: str
    category: PatternCategory
    value: str
    masked_value: str
    start: int
    end: int
    risk_score: float
    confidence: float
    description: str


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


BUILTIN_PATTERNS: list[DetectionPattern] = [
    # API Keys
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="openai_api_key",
        regex=_compile(r"sk-(?:proj-)?[a-zA-Z0-9]{10,}"),
        risk_score=9.0,
        description="OpenAI API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="anthropic_api_key",
        regex=_compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"),
        risk_score=9.0,
        description="Anthropic API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="github_token",
        regex=_compile(r"ghp_[a-zA-Z0-9]{36}"),
        risk_score=8.5,
        description="GitHub Personal Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="github_fine_grained",
        regex=_compile(r"github_pat_[a-zA-Z0-9_]{22,}"),
        risk_score=8.5,
        description="GitHub Fine-Grained Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="stripe_key",
        regex=_compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        risk_score=9.0,
        description="Stripe Secret Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="slack_token",
        regex=_compile(r"xox[bpors]-[a-zA-Z0-9\-]{10,}"),
        risk_score=7.5,
        description="Slack Token",
    ),
    # AWS Credentials
    DetectionPattern(
        category=PatternCategory.AWS_CREDENTIAL,
        name="aws_access_key",
        regex=_compile(r"AKIA[0-9A-Z]{16}"),
        risk_score=9.5,
        description="AWS Access Key ID",
    ),
    DetectionPattern(
        category=PatternCategory.AWS_CREDENTIAL,
        name="aws_secret_key",
        regex=_compile(
            r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'
        ),
        risk_score=9.5,
        description="AWS Secret Access Key",
    ),
    # Passwords
    DetectionPattern(
        category=PatternCategory.PASSWORD,
        name="password_assignment",
        regex=_compile(
            r'(?:password|passwd|pwd|pass)["\']?\s*[=:]\s*["\']?([^\s"\']{6,})["\']?', re.IGNORECASE
        ),
        risk_score=8.0,
        description="Password in assignment",
    ),
    DetectionPattern(
        category=PatternCategory.PASSWORD,
        name="database_uri",
        regex=_compile(r"(?:mysql|postgres|postgresql|mongodb|redis)://[^@]+:([^@]+)@[^\s]+"),
        risk_score=8.5,
        description="Database connection URI with password",
    ),
    # Network
    DetectionPattern(
        category=PatternCategory.PRIVATE_IP,
        name="private_ipv4",
        regex=_compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        risk_score=5.0,
        description="Private IPv4 address",
    ),
    # Tokens
    DetectionPattern(
        category=PatternCategory.JWT_TOKEN,
        name="jwt_token",
        regex=_compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        risk_score=7.0,
        description="JWT Token",
    ),
    # SSH Keys
    DetectionPattern(
        category=PatternCategory.SSH_KEY,
        name="ssh_private_key",
        regex=_compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        risk_score=9.5,
        description="SSH Private Key header",
    ),
    # PII - Chinese specific
    DetectionPattern(
        category=PatternCategory.PHONE_CN,
        name="china_mobile",
        regex=_compile(r"\b1[3-9]\d{9}\b"),
        risk_score=6.0,
        description="China mobile phone number",
    ),
    DetectionPattern(
        category=PatternCategory.ID_CARD_CN,
        name="china_id_card",
        regex=_compile(r"\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
        risk_score=8.0,
        description="China ID card number",
    ),
    # Credit Card
    DetectionPattern(
        category=PatternCategory.CREDIT_CARD,
        name="credit_card",
        regex=_compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        risk_score=8.0,
        description="Credit card number",
    ),
    # Email
    DetectionPattern(
        category=PatternCategory.EMAIL,
        name="email_address",
        regex=_compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        risk_score=4.0,
        description="Email address",
    ),
    # Blockchain — Wallet Addresses
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_WALLET,
        name="ethereum_address",
        regex=_compile(r"\b0x[a-fA-F0-9]{40}\b"),
        risk_score=6.0,
        description="Ethereum wallet address",
    ),
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_WALLET,
        name="bitcoin_address_legacy",
        regex=_compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
        risk_score=6.0,
        description="Bitcoin address (P2PKH/P2SH)",
    ),
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_WALLET,
        name="bitcoin_bech32",
        regex=_compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b"),
        risk_score=6.0,
        description="Bitcoin Bech32 address",
    ),
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_WALLET,
        name="tron_address",
        regex=_compile(r"\bT[a-zA-Z0-9]{33}\b"),
        risk_score=6.0,
        description="TRON wallet address",
    ),
    # Blockchain — Private Keys
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_PRIVATE_KEY,
        name="eth_private_key",
        regex=_compile(
            r'(?:private[_\s]?key|priv[_\s]?key)\s*[=:]\s*["\']?(0x[a-fA-F0-9]{64})["\']?',
            re.IGNORECASE,
        ),
        risk_score=9.5,
        description="Ethereum private key",
    ),
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_PRIVATE_KEY,
        name="hex_private_key_64",
        regex=_compile(
            r'(?:private[_\s]?key|secret[_\s]?key|priv[_\s]?key)\s*[=:]\s*["\']?([a-fA-F0-9]{64})["\']?',
            re.IGNORECASE,
        ),
        risk_score=9.5,
        description="Hex private key (256-bit)",
    ),
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_PRIVATE_KEY,
        name="wif_private_key",
        regex=_compile(r"\b5[HJK][1-9A-HJ-NP-Za-km-z]{49}\b"),
        risk_score=9.5,
        description="Bitcoin WIF private key",
    ),
    # Blockchain — Mnemonic Seed Phrases (12/24 lowercase words)
    DetectionPattern(
        category=PatternCategory.BLOCKCHAIN_MNEMONIC,
        name="mnemonic_seed_phrase",
        regex=_compile(
            r'(?:mnemonic|seed|recovery)\s*(?:phrase|words?)?\s*[=:]\s*["\']?((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})["\']?',
            re.IGNORECASE,
        ),
        risk_score=9.5,
        description="Blockchain mnemonic seed phrase",
    ),
    # Generic secrets
    DetectionPattern(
        category=PatternCategory.GENERIC_SECRET,
        name="generic_secret",
        regex=_compile(
            r'(?:secret|token|api_key|apikey|auth)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        risk_score=7.0,
        description="Generic secret/token pattern",
    ),
    # Additional API Keys (from trufflehog/gitleaks)
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="google_api_key",
        regex=_compile(r"AIza[0-9A-Za-z\-_]{35}"),
        risk_score=8.5,
        description="Google API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="google_oauth",
        regex=_compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
        risk_score=8.0,
        description="Google OAuth Client ID",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="heroku_api_key",
        regex=_compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        risk_score=8.0,
        description="Heroku API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="mailchimp_api_key",
        regex=_compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
        risk_score=7.5,
        description="Mailchimp API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="mailgun_api_key",
        regex=_compile(r"key-[0-9a-zA-Z]{32}"),
        risk_score=7.5,
        description="Mailgun API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="paypal_braintree",
        regex=_compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        risk_score=9.0,
        description="PayPal Braintree Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="picatic_api_key",
        regex=_compile(r"sk_live_[0-9a-z]{32}"),
        risk_score=7.5,
        description="Picatic API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="sendgrid_api_key",
        regex=_compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
        risk_score=8.0,
        description="SendGrid API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="square_access_token",
        regex=_compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
        risk_score=8.5,
        description="Square Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="square_oauth_secret",
        regex=_compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),
        risk_score=9.0,
        description="Square OAuth Secret",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="twilio_api_key",
        regex=_compile(r"SK[0-9a-fA-F]{32}"),
        risk_score=8.0,
        description="Twilio API Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="twitter_access_token",
        regex=_compile(r"[1-9][0-9]+-[0-9a-zA-Z]{40}"),
        risk_score=7.5,
        description="Twitter Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="npm_access_token",
        regex=_compile(r"npm_[a-zA-Z0-9]{36}"),
        risk_score=8.5,
        description="NPM Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="pypi_upload_token",
        regex=_compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"),
        risk_score=8.5,
        description="PyPI Upload Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="gitlab_token",
        regex=_compile(r"glpat-[0-9a-zA-Z\-_]{20}"),
        risk_score=8.5,
        description="GitLab Personal Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="discord_bot_token",
        regex=_compile(r"[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d_\-]{27,}"),
        risk_score=7.5,
        description="Discord Bot Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="discord_webhook",
        regex=_compile(
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}"
        ),
        risk_score=7.0,
        description="Discord Webhook URL",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="shopify_token",
        regex=_compile(r"shpat_[a-fA-F0-9]{32}"),
        risk_score=8.0,
        description="Shopify Access Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="shopify_shared_secret",
        regex=_compile(r"shpss_[a-fA-F0-9]{32}"),
        risk_score=8.5,
        description="Shopify Shared Secret",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="telegram_bot_token",
        regex=_compile(r"[0-9]{8,10}:[0-9A-Za-z_\-]{35}"),
        risk_score=7.5,
        description="Telegram Bot Token",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="azure_storage_key",
        regex=_compile(
            r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88};"
        ),
        risk_score=9.0,
        description="Azure Storage Account Key",
    ),
    DetectionPattern(
        category=PatternCategory.API_KEY,
        name="facebook_access_token",
        regex=_compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
        risk_score=8.0,
        description="Facebook Access Token",
    ),
]


def mask_value(value: str) -> str:
    """Create a masked version of a sensitive value for display."""
    if len(value) <= 8:
        return value[:2] + "***" + value[-1:]
    return value[:4] + "***" + value[-4:]
