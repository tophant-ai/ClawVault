"""Security-Scan Skill: scan text, files, and Skill packages for security risks.

Covers scenarios: A4 (uploaded content scanning) + E2 (supply-chain security scanning)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from claw_vault.skills.base import (
    BaseSkill,
    SkillManifest,
    SkillPermission,
    SkillResult,
    tool,
)


class SecurityScanSkill(BaseSkill):
    """Scan text, files, and Skill packages for security risks.

    Capabilities:
    - Scan arbitrary text for all threat types
    - Scan local files for hardcoded secrets
    - Scan project directories for exposed credentials
    - Assess Skill packages for supply-chain risks
    """

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="security-scan",
            version="0.1.0",
            description="Scan text, files, and Skill packages for security vulnerabilities",
            permissions=[
                SkillPermission.READ_CHAT,
                SkillPermission.READ_FILES,
            ],
            tags=["security", "scanning", "secrets", "supply-chain"],
            homepage="https://github.com/tophant-ai/ClawVault",
        )

    @tool(
        name="scan_text",
        description=(
            "Comprehensive security scan on arbitrary text. Checks for sensitive data, "
            "dangerous commands, and prompt injection patterns. Returns detailed findings."
        ),
    )
    def scan_text(self, text: str) -> SkillResult:
        """Full security scan on text content."""
        scan = self.ctx.detection_engine.scan_full(text)

        findings: list[dict[str, Any]] = []
        for s in scan.sensitive:
            findings.append(
                {
                    "category": "sensitive_data",
                    "type": s.pattern_type,
                    "description": s.description,
                    "masked_value": s.masked_value,
                    "risk_score": s.risk_score,
                    "position": [s.start, s.end],
                }
            )
        for c in scan.commands:
            findings.append(
                {
                    "category": "dangerous_command",
                    "command": c.command[:60],
                    "risk_level": c.risk_level.value,
                    "risk_score": c.risk_score,
                    "reason": c.reason,
                }
            )
        for i in scan.injections:
            findings.append(
                {
                    "category": "prompt_injection",
                    "type": i.injection_type,
                    "matched": i.matched_text[:60],
                    "risk_score": i.risk_score,
                    "description": i.description,
                }
            )

        return SkillResult(
            success=True,
            message=f"Scan complete: {scan.total_detections} finding(s), threat level {scan.threat_level.value}",
            data={
                "threat_level": scan.threat_level.value,
                "total_findings": scan.total_detections,
                "max_risk_score": scan.max_risk_score,
                "findings": findings,
                "summary": scan.summary(),
            },
            risk_score=scan.max_risk_score,
        )

    @tool(
        name="scan_file",
        description=(
            "Scan a local file for hardcoded secrets, API keys, passwords, "
            "and other sensitive data. Supports text files, config files, "
            ".env files, YAML, JSON, etc."
        ),
    )
    def scan_file(self, file_path: str) -> SkillResult:
        """Scan a file for security issues."""
        path = Path(file_path).expanduser()
        if not path.exists():
            return SkillResult(success=False, message=f"File not found: {file_path}")
        if not path.is_file():
            return SkillResult(success=False, message=f"Not a file: {file_path}")
        if path.stat().st_size > 5 * 1024 * 1024:  # 5MB limit
            return SkillResult(success=False, message="File too large (>5MB)")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return SkillResult(success=False, message=f"Cannot read file: {e}")

        scan = self.ctx.detection_engine.scan_full(content)

        findings: list[dict[str, Any]] = []
        for s in scan.sensitive:
            line_num = content[: s.start].count("\n") + 1
            findings.append(
                {
                    "type": s.pattern_type,
                    "description": s.description,
                    "masked_value": s.masked_value,
                    "risk_score": s.risk_score,
                    "line": line_num,
                }
            )

        self.ctx.log_audit(
            {
                "skill": "security-scan",
                "action": "scan_file",
                "file": str(path),
                "findings": len(findings),
            }
        )

        return SkillResult(
            success=True,
            message=f"Scanned {path.name}: {len(findings)} finding(s)",
            data={
                "file": str(path),
                "size_bytes": path.stat().st_size,
                "lines": content.count("\n") + 1,
                "threat_level": scan.threat_level.value,
                "total_findings": len(findings),
                "findings": findings,
            },
            risk_score=scan.max_risk_score,
        )

    @tool(
        name="scan_directory",
        description=(
            "Scan a project directory for exposed secrets. "
            "Checks .env files, config files, YAML, JSON, and other common secret locations."
        ),
    )
    def scan_directory(self, directory: str, max_files: int = 50) -> SkillResult:
        """Scan a directory for files containing secrets."""
        dir_path = Path(directory).expanduser()
        if not dir_path.exists() or not dir_path.is_dir():
            return SkillResult(success=False, message=f"Directory not found: {directory}")

        target_patterns = [
            "*.env",
            "*.env.*",
            "*.yaml",
            "*.yml",
            "*.json",
            "*.toml",
            "*.ini",
            "*.cfg",
            "*.conf",
            "*.properties",
            "*.pem",
            "*.key",
        ]

        files_scanned = 0
        total_findings = 0
        file_results: list[dict[str, Any]] = []

        for pattern in target_patterns:
            for file_path in dir_path.rglob(pattern):
                if files_scanned >= max_files:
                    break
                if file_path.stat().st_size > 1024 * 1024:  # Skip >1MB
                    continue
                # Skip common non-secret directories
                parts = file_path.parts
                if any(
                    skip in parts
                    for skip in ["node_modules", ".git", "venv", "__pycache__", ".venv"]
                ):
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                detections = self.ctx.detection_engine.sensitive_detector.detect(content)
                files_scanned += 1

                if detections:
                    total_findings += len(detections)
                    file_results.append(
                        {
                            "file": str(file_path.relative_to(dir_path)),
                            "findings": len(detections),
                            "max_risk": max(float(d.risk_score) for d in detections),
                            "types": list({d.category.value for d in detections}),
                        }
                    )

        file_results.sort(key=lambda r: float(r["max_risk"]), reverse=True)

        return SkillResult(
            success=True,
            message=f"Scanned {files_scanned} files: {total_findings} finding(s) in {len(file_results)} file(s)",
            data={
                "directory": str(dir_path),
                "files_scanned": files_scanned,
                "files_with_findings": len(file_results),
                "total_findings": total_findings,
                "results": file_results,
            },
            risk_score=float(max((float(r["max_risk"]) for r in file_results), default=0.0))
        )

    @tool(
        name="assess_skill_risk",
        description=(
            "Assess the security risk of an OpenClaw Skill package. "
            "Checks for obfuscated code, broad permissions, known malicious patterns, "
            "and suspicious network access."
        ),
    )
    def assess_skill_risk(self, skill_name: str, skill_code: str) -> SkillResult:
        """Assess security risk of a Skill's source code."""
        scan = self.ctx.detection_engine.scan_full(skill_code)

        risk_factors: list[dict[str, Any]] = []

        # Check for obfuscation patterns
        import re

        if re.search(r"exec\s*\(", skill_code):
            risk_factors.append(
                {"factor": "dynamic_execution", "detail": "Uses exec()", "score": 7.5}
            )
        if re.search(r"eval\s*\(", skill_code):
            risk_factors.append({"factor": "dynamic_eval", "detail": "Uses eval()", "score": 7.5})
        if re.search(r"base64\.(b64)?decode", skill_code):
            risk_factors.append(
                {"factor": "base64_decode", "detail": "Decodes base64 data", "score": 6.0}
            )
        if re.search(r"\\x[0-9a-f]{2}", skill_code, re.IGNORECASE):
            risk_factors.append(
                {"factor": "hex_encoding", "detail": "Contains hex-encoded strings", "score": 5.0}
            )

        # Check for suspicious network access
        if re.search(r"requests\.(get|post|put|delete)", skill_code):
            risk_factors.append(
                {"factor": "network_requests", "detail": "Makes HTTP requests", "score": 4.0}
            )
        if re.search(r"urllib|httpx|aiohttp", skill_code):
            risk_factors.append(
                {"factor": "network_library", "detail": "Imports network library", "score": 3.0}
            )

        # Check for file system access
        if re.search(r'open\s*\(.*["\']w', skill_code):
            risk_factors.append({"factor": "file_write", "detail": "Writes to files", "score": 5.0})
        if re.search(r"os\.(system|popen|exec)", skill_code):
            risk_factors.append(
                {"factor": "os_command", "detail": "Executes OS commands", "score": 8.0}
            )
        if re.search(r"subprocess", skill_code):
            risk_factors.append(
                {"factor": "subprocess", "detail": "Runs subprocesses", "score": 6.0}
            )

        # Check for credential access patterns
        if re.search(r"(credentials|password|secret|api.?key)", skill_code, re.IGNORECASE):
            risk_factors.append(
                {"factor": "credential_access", "detail": "References credentials", "score": 5.0}
            )

        # Add findings from detection engine
        for s in scan.sensitive:
            risk_factors.append(
                {
                    "factor": "hardcoded_secret",
                    "detail": f"Hardcoded {s.description}",
                    "score": float(s.risk_score),
                }
            )

        max_score = float(max((float(f["score"]) for f in risk_factors), default=0.0))

        if max_score >= 8.0:
            risk_level = "high"
            recommendation = "BLOCK — This Skill contains high-risk patterns"
        elif max_score >= 5.0:
            risk_level = "medium"
            recommendation = "REVIEW — Manual review recommended before installation"
        elif max_score > 0:
            risk_level = "low"
            recommendation = "ALLOW — Low risk, standard precautions apply"
        else:
            risk_level = "safe"
            recommendation = "ALLOW — No risk factors detected"

        self.ctx.log_audit(
            {
                "skill": "security-scan",
                "action": "assess_skill",
                "target_skill": skill_name,
                "risk_level": risk_level,
                "factors": len(risk_factors),
            }
        )

        return SkillResult(
            success=True,
            message=f"Skill '{skill_name}' risk: {risk_level.upper()} ({len(risk_factors)} factor(s))",
            data={
                "skill_name": skill_name,
                "risk_level": risk_level,
                "max_risk_score": max_score,
                "risk_factors": risk_factors,
                "recommendation": recommendation,
                "code_lines": skill_code.count("\n") + 1,
            },
            risk_score=max_score,
            action_taken=risk_level,
            warnings=[f["detail"] for f in risk_factors if f["score"] >= 6.0],
        )
