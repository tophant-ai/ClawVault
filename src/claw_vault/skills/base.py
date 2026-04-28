"""Base classes and decorators for ClawVault Skills.

A Skill is an independently distributable unit of security functionality
that can be installed in OpenClaw and invoked by AI Agents or users.

Each Skill:
- Declares metadata (name, version, description, permissions)
- Registers one or more "tools" — callable actions the AI can invoke
- Has access to a shared SkillContext (detectors, sanitizer, audit, etc.)
"""

from __future__ import annotations

import functools
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from collections.abc import Callable as AbcCallable

import structlog

logger = structlog.get_logger()


class SkillPermission(str, Enum):
    """Permissions a Skill may request."""

    READ_CHAT = "read_chat"  # Read user ↔ AI conversation
    MODIFY_CHAT = "modify_chat"  # Modify outgoing/incoming messages
    READ_FILES = "read_files"  # Read local files
    WRITE_FILES = "write_files"  # Write/modify local files
    NETWORK = "network"  # Make network requests
    EXECUTE_COMMAND = "execute_command"  # Execute system commands
    ACCESS_CREDENTIALS = "access_credentials"  # Access vault credentials
    AUDIT_LOG = "audit_log"  # Read/write audit logs


@dataclass
class ToolDefinition:
    """Metadata for a single tool exposed by a Skill."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for parameters
    handler: Callable[..., Any]
    examples: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SkillManifest:
    """Metadata manifest for a Skill."""

    name: str
    version: str
    description: str
    author: str = "Tophant SPAI Lab"
    permissions: list[SkillPermission] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    homepage: str = ""


@dataclass
class SkillResult:
    """Standard result returned by Skill tool invocations."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    warnings: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    action_taken: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "message": self.message,
            "warnings": self.warnings,
            "risk_score": self.risk_score,
            "action_taken": self.action_taken,
        }


class SkillContext:
    """Shared context injected into Skills at runtime.

    Provides access to core claw_vault components without
    requiring Skills to construct them directly.
    """

    def __init__(self) -> None:
        from claw_vault.detector.engine import DetectionEngine
        from claw_vault.sanitizer.replacer import Sanitizer
        from claw_vault.sanitizer.restorer import Restorer
        from claw_vault.guard.rule_engine import RuleEngine
        from claw_vault.monitor.token_counter import TokenCounter
        from claw_vault.vault.file_manager import FileManager

        self.detection_engine = DetectionEngine()
        self.sanitizer = Sanitizer()
        self.restorer = Restorer()
        self.rule_engine = RuleEngine()
        self.token_counter = TokenCounter()
        self.file_manager = FileManager()
        self._audit_records: list[dict] = []

    def log_audit(self, record: dict[str, Any]) -> None:
        """Append an audit record (in-memory; flushed by audit store)."""
        record.setdefault("timestamp", datetime.utcnow().isoformat())
        self._audit_records.append(record)

    def get_audit_records(self) -> list[dict[str, Any]]:
        return list(self._audit_records)

    def clear_audit(self) -> None:
        self._audit_records.clear()


def tool(
    name: str | None = None,
    description: str = "",
    parameters: dict[str, Any] | None = None,
    examples: list[dict[str, Any]] | None = None,
):
    """Decorator to register a method as a Skill tool.

    Usage:
        class MySkill(BaseSkill):
            @tool(name="scan_text", description="Scan text for secrets")
            def scan_text(self, text: str) -> SkillResult:
                ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or func.__name__
        # Auto-generate parameter schema from type hints
        sig = inspect.signature(func)
        auto_params: dict[str, dict[str, str]] = {}
        for pname, param in sig.parameters.items():
            if pname == "self":
                continue
            ptype = "string"
            if param.annotation is int:
                ptype = "integer"
            elif param.annotation is bool:
                ptype = "boolean"
            elif param.annotation is float:
                ptype = "number"
            auto_params[pname] = {
                "type": ptype,
                "description": pname,
            }

        setattr(func, "_tool_def", ToolDefinition(
            name=tool_name,
            description=description or func.__doc__ or "",
            parameters=parameters or auto_params,
            handler=func,
            examples=examples or [],
        ))

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper._tool_def = func._tool_def  # type: ignore[attr-defined]
        return wrapper

    return decorator


class BaseSkill(ABC):
    """Abstract base class for all ClawVault Skills.

    Subclass this and:
    1. Override `manifest()` to declare metadata
    2. Define tool methods decorated with `@tool(...)`
    3. Tools automatically receive `self.ctx` (SkillContext)
    """

    def __init__(self, ctx: SkillContext | None = None) -> None:
        self.ctx = ctx or SkillContext()
        self._tools: dict[str, ToolDefinition] = {}
        self._discover_tools()

    @abstractmethod
    def manifest(self) -> SkillManifest:
        """Return the Skill's metadata manifest."""
        ...

    def _discover_tools(self) -> None:
        """Auto-discover methods decorated with @tool."""
        for attr_name in dir(self):
            attr = getattr(self, attr_name, None)
            if callable(attr) and hasattr(attr, "_tool_def"):
                td: ToolDefinition = attr._tool_def
                # Bind the handler to this instance
                td.handler = attr
                self._tools[td.name] = td

    def list_tools(self) -> list[ToolDefinition]:
        """List all tools exposed by this Skill."""
        return list(self._tools.values())

    def get_tool(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def invoke(self, tool_name: str, **kwargs) -> SkillResult:
        """Invoke a tool by name with the given arguments."""
        td = self._tools.get(tool_name)
        if not td:
            return SkillResult(
                success=False,
                message=f"Tool '{tool_name}' not found in {self.manifest().name}",
            )
        try:
            result = td.handler(**kwargs)
            if not isinstance(result, SkillResult):
                result = SkillResult(success=True, data={"result": result})
            logger.info(
                "skill_tool_invoked",
                skill=self.manifest().name,
                tool=tool_name,
                success=result.success,
            )
            return result
        except Exception as e:
            logger.error(
                "skill_tool_error",
                skill=self.manifest().name,
                tool=tool_name,
                error=str(e),
            )
            return SkillResult(success=False, message=f"Error: {e}")

    def to_openai_tools(self) -> list[dict]:
        """Export tools in OpenAI function-calling format (for MCP/Agent integration)."""
        tools = []
        for td in self._tools.values():
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": f"{self.manifest().name}__{td.name}",
                        "description": td.description,
                        "parameters": {
                            "type": "object",
                            "properties": td.parameters,
                        },
                    },
                }
            )
        return tools

    def to_skill_json(self) -> dict:
        """Export Skill metadata as skill.json format."""
        m = self.manifest()
        return {
            "name": m.name,
            "version": m.version,
            "description": m.description,
            "author": m.author,
            "permissions": [p.value for p in m.permissions],
            "tags": m.tags,
            "homepage": m.homepage,
            "tools": [
                {
                    "name": td.name,
                    "description": td.description,
                    "parameters": td.parameters,
                    "examples": td.examples,
                }
                for td in self._tools.values()
            ],
        }
