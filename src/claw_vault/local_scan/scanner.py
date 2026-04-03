"""Local filesystem scanner — credential, vulnerability, and skill audit scans."""

from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path

import structlog

from claw_vault.config import LocalScanConfig
from claw_vault.detector.engine import DetectionEngine
from claw_vault.local_scan.models import (
    LocalScanResult,
    ScanFinding,
    ScanStatus,
    ScanType,
)

logger = structlog.get_logger()

# Well-known sensitive file paths (from vault/file_manager.py)
_HOME_SENSITIVE_PATHS = [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/config",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.gitconfig",
    "~/.netrc",
    "~/.env",
]

# Risk factor patterns for skill code audit (from skills/security_scan.py)
_SKILL_RISK_PATTERNS: list[tuple[str, str, str, float]] = [
    # (regex, factor_name, description, risk_score)
    (r"exec\s*\(", "dynamic_execution", "Uses exec()", 7.5),
    (r"eval\s*\(", "dynamic_eval", "Uses eval()", 7.5),
    (r"os\.(system|popen|exec)", "os_command", "Executes OS commands", 8.0),
    (r"subprocess", "subprocess", "Runs subprocesses", 6.0),
    (r"base64\.(b64)?decode", "base64_decode", "Decodes base64 data", 6.0),
    (r"\\x[0-9a-f]{2}", "hex_encoding", "Contains hex-encoded strings", 5.0),
    (r"requests\.(get|post|put|delete)", "network_requests", "Makes HTTP requests", 4.0),
    (r"urllib|httpx|aiohttp", "network_library", "Imports network library", 3.0),
    (r'open\s*\(.*["\']w', "file_write", "Writes to files", 5.0),
    (r"(credentials|password|secret|api.?key)", "credential_access", "References credentials", 5.0),
]


class LocalScanner:
    """Scans local filesystem for credentials, vulnerabilities, and skill risks."""

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        config: LocalScanConfig | None = None,
    ) -> None:
        self._engine = detection_engine or DetectionEngine()
        self._config = config or LocalScanConfig()

    def run_scan(
        self,
        scan_type: ScanType,
        path: str,
        max_files: int | None = None,
    ) -> LocalScanResult:
        """Dispatch to the appropriate scan method."""
        if scan_type == ScanType.CREDENTIAL:
            return self.scan_credentials(path, max_files or self._config.max_files_per_scan)
        elif scan_type == ScanType.VULNERABILITY:
            return self.scan_vulnerabilities(path)
        elif scan_type == ScanType.SKILL_AUDIT:
            return self.scan_skills(path)
        else:
            return LocalScanResult(
                scan_type=scan_type,
                path=path,
                status=ScanStatus.FAILED,
                error=f"Unknown scan type: {scan_type}",
            )

    def scan_credentials(self, path: str, max_files: int = 200) -> LocalScanResult:
        """Scan directory tree for hardcoded credentials using DetectionEngine."""
        start = time.monotonic()
        result = LocalScanResult(
            scan_type=ScanType.CREDENTIAL,
            path=path,
            status=ScanStatus.RUNNING,
        )
        dir_path = Path(path).expanduser().resolve()
        if not dir_path.exists() or not dir_path.is_dir():
            result.status = ScanStatus.FAILED
            result.error = f"Directory not found: {path}"
            return result

        skip_dirs = set(self._config.skip_dirs)
        max_size = self._config.max_file_size_kb * 1024
        files_scanned = 0
        findings: list[ScanFinding] = []

        for pattern in self._config.scan_file_patterns:
            if files_scanned >= max_files:
                break
            for file_path in dir_path.rglob(pattern):
                if files_scanned >= max_files:
                    break
                if not file_path.is_file():
                    continue
                # Skip excluded directories
                if skip_dirs.intersection(file_path.parts):
                    continue
                try:
                    if file_path.stat().st_size > max_size:
                        continue
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                except (OSError, PermissionError):
                    continue

                scan = self._engine.scan_full(content)
                files_scanned += 1

                if not scan.has_threats:
                    continue

                rel = str(file_path.relative_to(dir_path)) if file_path.is_relative_to(dir_path) else str(file_path)
                for s in scan.sensitive:
                    findings.append(ScanFinding(
                        file_path=rel,
                        finding_type="sensitive",
                        description=s.description,
                        risk_score=s.risk_score,
                        detail={"masked_value": s.masked_value, "category": s.category.value},
                    ))
                for c in scan.commands:
                    findings.append(ScanFinding(
                        file_path=rel,
                        finding_type="command",
                        description=c.reason,
                        risk_score=c.risk_score,
                        detail={"command": c.command[:100]},
                    ))
                for i in scan.injections:
                    findings.append(ScanFinding(
                        file_path=rel,
                        finding_type="injection",
                        description=i.description,
                        risk_score=i.risk_score,
                    ))

        result.files_scanned = files_scanned
        result.findings = findings
        result.max_risk_score = max((f.risk_score for f in findings), default=0.0)
        result.threat_level = _threat_level(result.max_risk_score)
        result.status = ScanStatus.COMPLETED
        result.duration_seconds = round(time.monotonic() - start, 2)

        logger.info(
            "local_scan.credential_complete",
            path=path,
            files_scanned=files_scanned,
            findings=len(findings),
            max_risk=result.max_risk_score,
        )
        return result

    def scan_vulnerabilities(self, path: str) -> LocalScanResult:
        """Check filesystem for security misconfigurations."""
        start = time.monotonic()
        result = LocalScanResult(
            scan_type=ScanType.VULNERABILITY,
            path=path,
            status=ScanStatus.RUNNING,
        )
        dir_path = Path(path).expanduser().resolve()
        if not dir_path.exists():
            result.status = ScanStatus.FAILED
            result.error = f"Path not found: {path}"
            return result

        findings: list[ScanFinding] = []
        files_checked = 0

        # Check well-known home sensitive files for weak permissions
        for pattern in _HOME_SENSITIVE_PATHS:
            fp = Path(pattern).expanduser()
            if not fp.exists():
                continue
            files_checked += 1
            try:
                mode = fp.stat().st_mode
                # World-readable sensitive file
                if mode & stat.S_IROTH:
                    findings.append(ScanFinding(
                        file_path=str(fp),
                        finding_type="vulnerability",
                        description=f"World-readable sensitive file: {fp.name}",
                        risk_score=7.0,
                        detail={"permission": oct(mode), "fix": f"chmod 600 {fp}"},
                    ))
                # Group-readable key files
                if fp.suffix in (".pem", ".key", "") and fp.name.startswith("id_") and (mode & stat.S_IRGRP):
                    findings.append(ScanFinding(
                        file_path=str(fp),
                        finding_type="vulnerability",
                        description=f"Group-readable key file: {fp.name}",
                        risk_score=6.0,
                        detail={"permission": oct(mode), "fix": f"chmod 600 {fp}"},
                    ))
            except (OSError, PermissionError):
                continue

        # Check for exposed .git directory
        git_config = dir_path / ".git" / "config"
        if git_config.exists():
            files_checked += 1
            try:
                mode = git_config.stat().st_mode
                if mode & stat.S_IROTH:
                    findings.append(ScanFinding(
                        file_path=str(git_config),
                        finding_type="vulnerability",
                        description="World-readable .git/config — may expose repository metadata",
                        risk_score=5.0,
                        detail={"permission": oct(mode)},
                    ))
            except (OSError, PermissionError):
                pass

        # Check for exposed docker.sock
        docker_sock = Path("/var/run/docker.sock")
        if docker_sock.exists():
            files_checked += 1
            try:
                mode = docker_sock.stat().st_mode
                if mode & stat.S_IWOTH:
                    findings.append(ScanFinding(
                        file_path=str(docker_sock),
                        finding_type="vulnerability",
                        description="Docker socket is world-writable — container escape risk",
                        risk_score=9.0,
                        detail={"permission": oct(mode)},
                    ))
            except (OSError, PermissionError):
                pass

        # Check for sensitive files in the scanned directory with weak permissions
        skip_dirs = set(self._config.skip_dirs)
        sensitive_patterns = ["*.pem", "*.key", "*.p12", "*.pfx", ".env", ".env.*"]
        for pattern in sensitive_patterns:
            for fp in dir_path.rglob(pattern):
                if not fp.is_file() or skip_dirs.intersection(fp.parts):
                    continue
                files_checked += 1
                try:
                    mode = fp.stat().st_mode
                    if mode & stat.S_IROTH:
                        rel = str(fp.relative_to(dir_path)) if fp.is_relative_to(dir_path) else str(fp)
                        findings.append(ScanFinding(
                            file_path=rel,
                            finding_type="vulnerability",
                            description=f"World-readable sensitive file: {fp.name}",
                            risk_score=7.0,
                            detail={"permission": oct(mode), "fix": f"chmod 600 {fp}"},
                        ))
                except (OSError, PermissionError):
                    continue

        result.files_scanned = files_checked
        result.findings = findings
        result.max_risk_score = max((f.risk_score for f in findings), default=0.0)
        result.threat_level = _threat_level(result.max_risk_score)
        result.status = ScanStatus.COMPLETED
        result.duration_seconds = round(time.monotonic() - start, 2)

        logger.info(
            "local_scan.vulnerability_complete",
            path=path,
            files_checked=files_checked,
            findings=len(findings),
        )
        return result

    def scan_skills(self, skills_dir: str | None = None) -> LocalScanResult:
        """Audit installed skills for supply-chain risks."""
        start = time.monotonic()

        # Default to the project's skills directory
        if skills_dir:
            dir_path = Path(skills_dir).expanduser().resolve()
        else:
            dir_path = Path(__file__).parent.parent / "skills"

        result = LocalScanResult(
            scan_type=ScanType.SKILL_AUDIT,
            path=str(dir_path),
            status=ScanStatus.RUNNING,
        )

        if not dir_path.exists() or not dir_path.is_dir():
            result.status = ScanStatus.FAILED
            result.error = f"Skills directory not found: {dir_path}"
            return result

        findings: list[ScanFinding] = []
        files_scanned = 0

        for py_file in dir_path.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            try:
                code = py_file.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue

            files_scanned += 1
            rel = str(py_file.relative_to(dir_path)) if py_file.is_relative_to(dir_path) else str(py_file)

            # Check risk patterns
            for regex, factor, desc, score in _SKILL_RISK_PATTERNS:
                flags = re.IGNORECASE if factor == "credential_access" else 0
                if re.search(regex, code, flags):
                    findings.append(ScanFinding(
                        file_path=rel,
                        finding_type="skill_risk",
                        description=desc,
                        risk_score=score,
                        detail={"factor": factor},
                    ))

            # Also run detection engine for hardcoded secrets
            scan = self._engine.scan_full(code)
            for s in scan.sensitive:
                findings.append(ScanFinding(
                    file_path=rel,
                    finding_type="sensitive",
                    description=f"Hardcoded {s.description}",
                    risk_score=s.risk_score,
                    detail={"masked_value": s.masked_value, "category": s.category.value},
                ))

        result.files_scanned = files_scanned
        result.findings = findings
        result.max_risk_score = max((f.risk_score for f in findings), default=0.0)
        result.threat_level = _threat_level(result.max_risk_score)
        result.status = ScanStatus.COMPLETED
        result.duration_seconds = round(time.monotonic() - start, 2)

        logger.info(
            "local_scan.skill_audit_complete",
            path=str(dir_path),
            files_scanned=files_scanned,
            findings=len(findings),
        )
        return result


def _threat_level(max_score: float) -> str:
    """Map max risk score to threat level string."""
    if max_score >= 9.0:
        return "critical"
    elif max_score >= 7.0:
        return "high"
    elif max_score >= 4.0:
        return "medium"
    elif max_score > 0:
        return "low"
    return "safe"
