"""OSV-Scanner / Grype SCA scanner for dependency vulnerabilities."""

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

_SEVERITY_MAP_CVSS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]


def _cvss_to_severity(score: float) -> Severity:
    for threshold, sev in _SEVERITY_MAP_CVSS:
        if score >= threshold:
            return sev
    return Severity.INFO


class OsvScanner(BaseScanner):
    name = "osv-scanner"

    def is_available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    def scan(
        self,
        settings: Settings,
        target_dir: Path | None = None,
        lockfile: str | None = None,
    ) -> ScanResult:
        self._require_available()

        scan_id = uuid.uuid4().hex[:12]
        target = target_dir or settings.project_root
        report_path = settings.cache_dir / "osv" / f"{scan_id}.json"
        (settings.cache_dir / "osv").mkdir(parents=True, exist_ok=True)

        cmd = ["osv-scanner", "--format", "json"]
        if lockfile:
            cmd.extend(["--lockfile", lockfile])
        else:
            cmd.extend(["--recursive", str(target)])

        start = time.monotonic()
        errors: list[str] = []

        try:
            proc = self._run_cmd(cmd, timeout=120, accept_codes=(0, 1))
            raw_output = proc.stdout
        except Exception as e:
            errors.append(str(e))
            raw_output = ""

        findings: list[Finding] = []
        if raw_output.strip():
            try:
                data = json.loads(raw_output)
                findings = self._parse_results(data, settings.project_root)
            except json.JSONDecodeError as e:
                errors.append(f"Failed to parse osv-scanner output: {e}")

        if len(findings) > settings.scanner_max_findings:
            findings = findings[:settings.scanner_max_findings]

        elapsed = round(time.monotonic() - start, 2)

        return ScanResult(
            scan_id=scan_id,
            scanner=self.name,
            category=FindingCategory.SCA,
            total_findings=len(findings),
            findings=findings,
            run_time_seconds=elapsed,
            commit_hash=self._get_commit(settings.project_root),
            errors=errors,
        )

    def _parse_results(self, data: dict, project_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        results = data.get("results", [])

        for result in results:
            source_path = result.get("source", {}).get("path", "")
            try:
                source_path = str(Path(source_path).relative_to(project_root))
            except (ValueError, TypeError):
                pass

            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                pkg_name = pkg_info.get("name", "unknown")
                pkg_version = pkg_info.get("version", "")
                pkg_ecosystem = pkg_info.get("ecosystem", "")

                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "unknown")
                    summary = vuln.get("summary", "")
                    details = vuln.get("details", summary)
                    aliases = vuln.get("aliases", [])

                    severity = Severity.MEDIUM
                    for sev_entry in vuln.get("severity", []):
                        score_str = sev_entry.get("score", "")
                        try:
                            parts = score_str.split("/")
                            score = float(parts[-1]) if len(parts) > 1 else float(score_str)
                            severity = _cvss_to_severity(score)
                            break
                        except (ValueError, IndexError):
                            pass

                    for db_sev in vuln.get("database_specific", {}).get("severity", []):
                        if db_sev.get("type") == "CVSS_V3":
                            try:
                                severity = _cvss_to_severity(float(db_sev.get("score", 0)))
                            except (ValueError, TypeError):
                                pass

                    finding_id = hashlib.sha256(
                        f"osv:{vuln_id}:{pkg_name}:{pkg_version}".encode()
                    ).hexdigest()[:16]

                    refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

                    cwe = []
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cwe.append(alias)

                    findings.append(Finding(
                        finding_id=finding_id,
                        scanner="osv-scanner",
                        category=FindingCategory.SCA,
                        severity=severity,
                        title=f"{vuln_id}: {pkg_name}@{pkg_version}",
                        description=f"{summary}\n\nPackage: {pkg_name} {pkg_version} ({pkg_ecosystem})\n{details[:500]}",
                        location=CodeLocation(file_path=source_path, line_start=0, line_end=0),
                        rule_id=vuln_id,
                        cwe=cwe,
                        references=refs[:5],
                        metadata={
                            "package": pkg_name,
                            "version": pkg_version,
                            "ecosystem": pkg_ecosystem,
                            "aliases": aliases,
                        },
                    ))

        return findings

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


class GrypeScanner(BaseScanner):
    """Alternative SCA scanner using Grype."""
    name = "grype"

    def is_available(self) -> bool:
        return shutil.which("grype") is not None

    def scan(
        self,
        settings: Settings,
        target_dir: Path | None = None,
        **kwargs,
    ) -> ScanResult:
        self._require_available()

        scan_id = uuid.uuid4().hex[:12]
        target = target_dir or settings.project_root

        cmd = ["grype", f"dir:{target}", "-o", "json", "--quiet"]
        start = time.monotonic()
        errors: list[str] = []

        try:
            proc = self._run_cmd(cmd, timeout=120, accept_codes=(0, 1))
            raw_output = proc.stdout
        except Exception as e:
            errors.append(str(e))
            raw_output = ""

        findings: list[Finding] = []
        if raw_output.strip():
            try:
                data = json.loads(raw_output)
                findings = self._parse_results(data, settings.project_root)
            except json.JSONDecodeError as e:
                errors.append(f"Failed to parse grype output: {e}")

        if len(findings) > settings.scanner_max_findings:
            findings = findings[:settings.scanner_max_findings]

        elapsed = round(time.monotonic() - start, 2)

        return ScanResult(
            scan_id=scan_id,
            scanner=self.name,
            category=FindingCategory.SCA,
            total_findings=len(findings),
            findings=findings,
            run_time_seconds=elapsed,
            errors=errors,
        )

    def _parse_results(self, data: dict, project_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vuln.get("id", "unknown")
            severity_str = vuln.get("severity", "medium").lower()
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "negligible": Severity.INFO,
            }.get(severity_str, Severity.MEDIUM)

            pkg_name = artifact.get("name", "unknown")
            pkg_version = artifact.get("version", "")

            finding_id = hashlib.sha256(
                f"grype:{vuln_id}:{pkg_name}:{pkg_version}".encode()
            ).hexdigest()[:16]

            locations = artifact.get("locations", [])
            file_path = ""
            if locations:
                file_path = locations[0].get("path", "")

            description = vuln.get("description", "")
            fix_versions = vuln.get("fix", {}).get("versions", [])
            if fix_versions:
                description += f"\n\nFix available: {', '.join(fix_versions)}"

            findings.append(Finding(
                finding_id=finding_id,
                scanner="grype",
                category=FindingCategory.SCA,
                severity=severity,
                title=f"{vuln_id}: {pkg_name}@{pkg_version}",
                description=description,
                location=CodeLocation(file_path=file_path, line_start=0, line_end=0),
                rule_id=vuln_id,
                references=[url for url in vuln.get("urls", [])[:5]],
                metadata={
                    "package": pkg_name,
                    "version": pkg_version,
                    "fix_versions": fix_versions,
                },
            ))

        return findings
