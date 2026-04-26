"""Gitleaks secret detection scanner."""

from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

from ..config import Settings
from ..models import (
    CodeLocation,
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)
from .base import BaseScanner

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

SECRET_TYPE_SEVERITY = {
    "aws-access-key": Severity.CRITICAL,
    "aws-secret-key": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "github-pat": Severity.HIGH,
    "generic-api-key": Severity.MEDIUM,
    "password": Severity.HIGH,
    "jwt": Severity.HIGH,
}


class GitleaksScanner(BaseScanner):
    name = "gitleaks"

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(
        self,
        settings: Settings,
        target_dir: Path | None = None,
        scan_git_history: bool = False,
        config_file: str | None = None,
    ) -> ScanResult:
        self._require_available()

        scan_id = uuid.uuid4().hex[:12]
        target = target_dir or settings.project_root
        report_path = settings.cache_dir / "gitleaks" / f"{scan_id}.json"
        (settings.cache_dir / "gitleaks").mkdir(parents=True, exist_ok=True)

        cmd = ["gitleaks"]
        if scan_git_history:
            cmd.append("git")
        else:
            cmd.append("dir")

        cmd.extend([
            str(target),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--exit-code", "0",
        ])

        if config_file:
            cmd.extend(["--config", config_file])

        start = time.monotonic()
        errors: list[str] = []

        try:
            self._run_cmd(cmd, timeout=settings.semgrep_timeout, accept_codes=(0, 1))
        except Exception as e:
            errors.append(str(e))

        findings: list[Finding] = []
        if report_path.exists():
            findings = self._parse_report(report_path, settings.project_root)

        if len(findings) > settings.scanner_max_findings:
            findings = findings[:settings.scanner_max_findings]

        elapsed = round(time.monotonic() - start, 2)

        return ScanResult(
            scan_id=scan_id,
            scanner=self.name,
            category=FindingCategory.SECRET,
            total_findings=len(findings),
            findings=findings,
            run_time_seconds=elapsed,
            commit_hash=self._get_commit(settings.project_root),
            errors=errors,
        )

    def _parse_report(self, report_path: Path, project_root: Path) -> list[Finding]:
        with report_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            return []

        findings: list[Finding] = []
        for entry in data:
            rule_id = entry.get("RuleID", "unknown")
            description = entry.get("Description", "")
            file_path = entry.get("File", "")
            line = entry.get("StartLine", 0)
            end_line = entry.get("EndLine", line)
            match_text = entry.get("Match", "")
            secret = entry.get("Secret", "")
            commit = entry.get("Commit", "")

            try:
                file_path = str(Path(file_path).relative_to(project_root))
            except (ValueError, TypeError):
                pass

            severity = SECRET_TYPE_SEVERITY.get(rule_id, Severity.HIGH)

            finding_id = hashlib.sha256(
                f"gitleaks:{rule_id}:{file_path}:{line}:{secret[:8]}".encode()
            ).hexdigest()[:16]

            redacted = self._redact(secret)

            findings.append(Finding(
                finding_id=finding_id,
                scanner="gitleaks",
                category=FindingCategory.SECRET,
                severity=severity,
                title=f"Secret detected: {description}",
                description=f"Rule: {rule_id}. Redacted match: {redacted}",
                location=CodeLocation(file_path=file_path, line_start=line, line_end=end_line),
                code_snippet=self._redact_in_text(match_text, secret),
                rule_id=rule_id,
                metadata={"commit": commit} if commit else {},
            ))

        return findings

    @staticmethod
    def _redact(secret: str) -> str:
        if len(secret) <= 6:
            return "***"
        return secret[:3] + "***" + secret[-3:]

    @staticmethod
    def _redact_in_text(text: str, secret: str) -> str:
        if not secret or not text:
            return text
        redacted = secret[:3] + "***" + secret[-3:] if len(secret) > 6 else "***"
        return text.replace(secret, redacted)

    @staticmethod
    def _get_commit(project_root: Path) -> str | None:
        import subprocess
        try:
            r = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=project_root, check=False,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None
