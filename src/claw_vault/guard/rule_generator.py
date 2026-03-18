"""LLM-based generative rule engine for creating custom security rules from natural language.

This module allows users to describe security policies in natural language and automatically
generates corresponding YAML-based rules that can be enforced by ClawVault.

Example:
    "Block all requests containing AWS credentials with risk score above 8.0"
    -> Generates a rule that blocks when has_sensitive=true and pattern_types includes aws_access_key
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import structlog
import yaml

from claw_vault.guard.rules_store import RuleCondition, RuleConfig

logger = structlog.get_logger()

# System prompt for LLM rule generation
RULE_GENERATION_SYSTEM_PROMPT = """You are a security rule generator for ClawVault, an AI security gateway.

Your task is to convert natural language security policies into structured YAML rules.

## Available Rule Structure:
```yaml
- id: unique-rule-id
  name: Human-readable rule name
  description: Detailed description of what this rule does
  enabled: true
  action: allow|block|sanitize|ask_user
  when:
    # Optional conditions (all are AND logic):
    has_sensitive: true|false       # Has sensitive data (API keys, passwords, etc.)
    has_commands: true|false         # Has dangerous commands (rm, curl, etc.)
    has_injections: true|false       # Has prompt injection attempts
    threat_levels: [low, medium, high, critical]  # Match specific threat levels
    min_risk_score: 0.0-10.0        # Minimum risk score threshold
    pattern_types: [list]            # Specific pattern types to match
  source: user
```

## Available Pattern Types:
**Sensitive Data:**
- openai_api_key, anthropic_api_key, github_token, github_fine_grained
- stripe_key, slack_token, aws_access_key, aws_secret_key
- google_api_key, google_oauth, heroku_api_key, mailchimp_api_key
- sendgrid_api_key, twilio_api_key, npm_access_token, pypi_upload_token
- gitlab_token, discord_bot_token, shopify_token, telegram_bot_token
- password_assignment, database_uri, private_ipv4, jwt_token
- ssh_private_key, email_address, phone_cn, id_card_cn, credit_card
- ethereum_address, bitcoin_address_legacy, eth_private_key, mnemonic_seed_phrase
- generic_secret

**Threat Types:**
- prompt_injection, jailbreak_attempt, context_manipulation
- dangerous_commands (includes: file_deletion, network_request, system_modification, etc.)

## Actions:
- **allow**: Allow the request to proceed
- **block**: Block the request completely
- **sanitize**: Mask/redact sensitive data and allow
- **ask_user**: Prompt user for decision

## Examples:

User: "Block all requests with AWS credentials"
Response:
```yaml
- id: block-aws-credentials
  name: Block AWS Credentials
  description: Prevents any request containing AWS access keys or secret keys from being processed
  enabled: true
  action: block
  when:
    has_sensitive: true
    pattern_types: [aws_access_key, aws_secret_key]
  source: user
```

User: "Auto-sanitize sensitive data with risk score above 7.0"
Response:
```yaml
- id: auto-sanitize-high-risk
  name: Auto-Sanitize High Risk Data
  description: Automatically masks sensitive information with risk score >= 7.0
  enabled: true
  action: sanitize
  when:
    has_sensitive: true
    min_risk_score: 7.0
  source: user
```

User: "Block prompt injections and jailbreak attempts"
Response:
```yaml
- id: block-injections
  name: Block All Injection Attempts
  description: Blocks any detected prompt injection or jailbreak attempts
  enabled: true
  action: block
  when:
    has_injections: true
  source: user
```

IMPORTANT: 
1. Always respond with ONLY valid YAML (no markdown code blocks, no explanations)
2. Generate a unique ID using kebab-case
3. Be specific in descriptions
4. Use appropriate conditions based on the user's intent
5. Default to enabled: true unless user specifies otherwise
"""


class RuleGenerator:
    """Generates security rules from natural language descriptions using LLM."""

    def __init__(self, llm_client: Optional[Any] = None):
        """Initialize the rule generator.

        Args:
            llm_client: Optional LLM client (OpenAI, Anthropic, etc.).
                       If None, will attempt to use environment variables.
        """
        self.llm_client = llm_client
        self._setup_llm_client()

    def _setup_llm_client(self) -> None:
        """Setup LLM client from environment or provided client."""
        if self.llm_client is not None:
            return

        # Try to import and setup OpenAI client
        try:
            import os
            from openai import OpenAI

            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                self.llm_client = OpenAI(api_key=api_key)
                logger.info("rule_generator.llm_setup", provider="openai")
            else:
                logger.warning(
                    "rule_generator.no_api_key",
                    msg="No OPENAI_API_KEY found, rule generation will fail",
                )
        except ImportError:
            logger.warning(
                "rule_generator.import_error",
                msg="OpenAI package not installed, install with: pip install openai",
            )

    def generate_rule(
        self, natural_language_policy: str, model: str = "gpt-4o-mini", temperature: float = 0.1
    ) -> RuleConfig:
        """Generate a security rule from natural language description.

        Args:
            natural_language_policy: User's security policy in natural language
            model: LLM model to use for generation
            temperature: LLM temperature (lower = more deterministic)

        Returns:
            RuleConfig object representing the generated rule

        Raises:
            ValueError: If rule generation fails or produces invalid output
        """
        if not self.llm_client:
            raise ValueError("LLM client not configured. Set OPENAI_API_KEY environment variable.")

        logger.info("rule_generator.generating", policy=natural_language_policy[:100])

        try:
            # Call LLM to generate rule
            response = self.llm_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": RULE_GENERATION_SYSTEM_PROMPT},
                    {"role": "user", "content": natural_language_policy},
                ],
                temperature=temperature,
                max_tokens=1000,
            )

            yaml_content = response.choices[0].message.content.strip()

            # Remove markdown code blocks if present
            yaml_content = re.sub(r"^```ya?ml\s*\n", "", yaml_content, flags=re.MULTILINE)
            yaml_content = re.sub(r"\n```\s*$", "", yaml_content, flags=re.MULTILINE)

            # Parse YAML
            parsed = yaml.safe_load(yaml_content)

            # Handle both single rule and list of rules
            if isinstance(parsed, list):
                if len(parsed) == 0:
                    raise ValueError("LLM generated empty rule list")
                rule_dict = parsed[0]  # Take first rule
            elif isinstance(parsed, dict):
                rule_dict = parsed
            else:
                raise ValueError(f"Unexpected YAML structure: {type(parsed)}")

            # Validate and create RuleConfig
            rule = RuleConfig(**rule_dict)

            logger.info(
                "rule_generator.success", rule_id=rule.id, rule_name=rule.name, action=rule.action
            )

            return rule

        except Exception as exc:
            logger.error(
                "rule_generator.failed", error=str(exc), policy=natural_language_policy[:100]
            )
            raise ValueError(f"Failed to generate rule: {exc}") from exc

    def generate_multiple_rules(
        self, natural_language_policy: str, model: str = "gpt-4o-mini", temperature: float = 0.1
    ) -> list[RuleConfig]:
        """Generate multiple security rules from a complex policy description.

        This is useful when a single policy statement requires multiple rules.

        Args:
            natural_language_policy: User's security policy in natural language
            model: LLM model to use for generation
            temperature: LLM temperature

        Returns:
            List of RuleConfig objects
        """
        if not self.llm_client:
            raise ValueError("LLM client not configured. Set OPENAI_API_KEY environment variable.")

        logger.info("rule_generator.generating_multiple", policy=natural_language_policy[:100])

        try:
            # Modified prompt for multiple rules
            user_prompt = f"{natural_language_policy}\n\nGenerate one or more rules as a YAML list to implement this policy."

            response = self.llm_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": RULE_GENERATION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=2000,
            )

            yaml_content = response.choices[0].message.content.strip()
            yaml_content = re.sub(r"^```ya?ml\s*\n", "", yaml_content, flags=re.MULTILINE)
            yaml_content = re.sub(r"\n```\s*$", "", yaml_content, flags=re.MULTILINE)

            parsed = yaml.safe_load(yaml_content)

            if isinstance(parsed, dict):
                parsed = [parsed]
            elif not isinstance(parsed, list):
                raise ValueError(f"Unexpected YAML structure: {type(parsed)}")

            rules = [RuleConfig(**rule_dict) for rule_dict in parsed]

            logger.info("rule_generator.multiple_success", count=len(rules))

            return rules

        except Exception as exc:
            logger.error("rule_generator.multiple_failed", error=str(exc))
            raise ValueError(f"Failed to generate rules: {exc}") from exc

    def validate_rule(self, rule: RuleConfig) -> tuple[bool, list[str]]:
        """Validate a generated rule for correctness and security.

        Args:
            rule: The rule to validate

        Returns:
            Tuple of (is_valid, list_of_warnings)
        """
        warnings = []

        # Check action is valid
        valid_actions = ["allow", "block", "sanitize", "ask_user"]
        if rule.action not in valid_actions:
            warnings.append(f"Invalid action '{rule.action}', must be one of {valid_actions}")

        # Check ID format
        if not re.match(r"^[a-z0-9\-]+$", rule.id):
            warnings.append(f"Rule ID '{rule.id}' should use kebab-case (lowercase with hyphens)")

        # Check if condition is too broad
        if rule.when:
            cond = rule.when
            has_any_condition = any(
                [
                    cond.has_sensitive is not None,
                    cond.has_commands is not None,
                    cond.has_injections is not None,
                    cond.threat_levels is not None,
                    cond.min_risk_score is not None,
                    cond.pattern_types is not None,
                ]
            )

            if not has_any_condition:
                warnings.append("Rule has no conditions - it will match everything")

        # Warn about overly permissive rules
        if rule.action == "allow" and rule.when and rule.when.has_injections:
            warnings.append("WARNING: Allowing prompt injections is dangerous")

        is_valid = len([w for w in warnings if w.startswith("Invalid")]) == 0

        return is_valid, warnings

    def explain_rule(self, rule: RuleConfig) -> str:
        """Generate a human-readable explanation of what a rule does.

        Args:
            rule: The rule to explain

        Returns:
            Human-readable explanation string
        """
        parts = [f"**{rule.name}**"]

        if rule.description:
            parts.append(f"\n{rule.description}")

        parts.append(f"\n\nAction: **{rule.action.upper()}**")

        if rule.when:
            parts.append("\n\nConditions:")
            cond = rule.when

            if cond.has_sensitive is not None:
                parts.append(f"- {'Has' if cond.has_sensitive else 'Does not have'} sensitive data")
            if cond.has_commands is not None:
                parts.append(
                    f"- {'Has' if cond.has_commands else 'Does not have'} dangerous commands"
                )
            if cond.has_injections is not None:
                parts.append(
                    f"- {'Has' if cond.has_injections else 'Does not have'} injection attempts"
                )
            if cond.threat_levels:
                parts.append(f"- Threat level is one of: {', '.join(cond.threat_levels)}")
            if cond.min_risk_score is not None:
                parts.append(f"- Risk score >= {cond.min_risk_score}")
            if cond.pattern_types:
                parts.append(f"- Matches pattern types: {', '.join(cond.pattern_types[:5])}")
                if len(cond.pattern_types) > 5:
                    parts.append(f"  (and {len(cond.pattern_types) - 5} more)")

        parts.append(f"\n\nStatus: {'✓ Enabled' if rule.enabled else '✗ Disabled'}")

        return "".join(parts)
