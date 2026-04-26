"""CodeQL SAST scanner — database creation + query execution."""

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
    DataflowStep,
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
)
from .base import BaseScanner, ScannerError

LANGUAGE_DB_MAP = {
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "java": "java",
    "go": "go",
    "cpp": "cpp",
    "c": "cpp",
    "csharp": "csharp",
    "ruby": "ruby",
    "swift": "swift",
}

_SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "recommendation": Severity.LOW,
    "note": Severity.INFO,
}

BUILTIN_SUITES = {
    "javascript": "javascript-security-and-quality",
    "python": "python-security-and-quality",
    "java": "java-security-and-quality",
    "go": "go-security-and-quality",
    "cpp": "cpp-security-and-quality",
    "csharp": "csharp-security-and-quality",
    "ruby": "ruby-security-and-quality",
}


class CodeQLScanner(BaseScanner):
    name = "codeql"

    def is_available(self) -> bool:
        return shutil.which("codeql") is not None

    def scan(
        self,
        settings: Settings,
        target_dir: Path | None = None,
        language: str | None = None,
        query_suite: str | None = None,
        query_file: str | None = None,
    ) -> ScanResult:
        self._require_available()

        scan_id = uuid.uuid4().hex[:12]
        target = target_dir or settings.project_root
        db_lang = LANGUAGE_DB_MAP.get(language or "", language or "")

        if not db_lang:
            raise ScannerError("language is required for CodeQL scanning")

        db_path = settings.cache_dir / "codeql" / f"db-{scan_id}"
        sarif_path = settings.cache_dir / "codeql" / f"{scan_id}.sarif.json"
        (settings.cache_dir / "codeql").mkdir(parents=True, exist_ok=True)

        errors: list[str] = []
        start = time.monotonic()

        try:
            self._create_database(target, db_path, db_lang, settings.codeql_timeout)
        except ScannerError as e:
            return ScanResult(
                scan_id=scan_id,
                scanner=self.name,
                category=FindingCategory.SAST,
                total_findings=0,
                findings=[],
                run_time_seconds=round(time.monotonic() - start, 2),
                errors=[str(e)],
            )

        suite = query_suite or BUILTIN_SUITES.get(db_lang, f"{db_lang}-security-and-quality")

        try:
            self._run_analysis(db_path, sarif_path, suite, query_file, settings.codeql_timeout)
        except ScannerError as e:
            errors.append(str(e))

        findings: list[Finding] = []
        if sarif_path.exists():
            findings = self._parse_sarif(sarif_path, settings.project_root)

        if len(findings) > settings.scanner_max_findings:
            findings = findings[:settings.scanner_max_findings]

        elapsed = round(time.monotonic() - start, 2)

        if db_path.exists():
            shutil.rmtree(db_path, ignore_errors=True)

        return ScanResult(
            scan_id=scan_id,
            scanner=self.name,
            category=FindingCategory.SAST,
            total_findings=len(findings),
            findings=findings,
            run_time_seconds=elapsed,
            commit_hash=self._get_commit(settings.project_root),
            errors=errors,
        )

    def _create_database(self, source: Path, db_path: Path, language: str, timeout: int) -> None:
        cmd = [
            "codeql", "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={source}",
            "--overwrite",
        ]
        self._run_cmd(cmd, timeout=timeout, check=True, accept_codes=(0,))

    def _run_analysis(
        self,
        db_path: Path,
        sarif_path: Path,
        suite: str,
        query_file: str | None,
        timeout: int,
    ) -> None:
        query_target = query_file or f"codeql/{suite}"
        cmd = [
            "codeql", "database", "analyze",
            str(db_path),
            query_target,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--sarif-add-snippets",
        ]
        self._run_cmd(cmd, timeout=timeout, check=True, accept_codes=(0,))

    def _parse_sarif(self, sarif_path: Path, project_root: Path) -> list[Finding]:
        with sarif_path.open("r", encoding="utf-8") as f:
            sarif = json.load(f)

        findings: list[Finding] = []
        runs = sarif.get("runs", [])
        if not runs:
            return findings

        rules_map: dict[str, dict] = {}
        tool = runs[0].get("tool", {}).get("driver", {})
        for rule in tool.get("rules", []):
            rules_map[rule.get("id", "")] = rule

        for result in runs[0].get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_def = rules_map.get(rule_id, {})
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")
            severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)

            locations = result.get("locations", [])
            if not locations:
                continue

            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            raw_uri = artifact.get("uri", "")
            region = phys.get("region", {})

            file_path = raw_uri.replace("file://", "")
            try:
                file_path = str(Path(file_path).resolve().relative_to(project_root))
            except ValueError:
                pass

            line_start = region.get("startLine", 0)
            line_end = region.get("endLine", line_start)
            snippet = region.get("snippet", {}).get("text", "")

            finding_id = hashlib.sha256(
                f"codeql:{rule_id}:{file_path}:{line_start}".encode()
            ).hexdigest()[:16]

            cwe = []
            tags = rule_def.get("properties", {}).get("tags", [])
            for tag in tags:
                if tag.startswith("external/cwe/cwe-"):
                    cwe.append(tag.replace("external/cwe/", "").upper())

            trace = self._extract_trace(result, project_root)

            findings.append(Finding(
                finding_id=finding_id,
                scanner="codeql",
                category=FindingCategory.SAST,
                severity=severity,
                title=f"[{rule_id}] {message[:100]}",
                description=message,
                location=CodeLocation(file_path=file_path, line_start=line_start, line_end=line_end),
                code_snippet=snippet.strip(),
                dataflow_trace=trace,
                rule_id=rule_id,
                cwe=cwe,
            ))

        return findings

    def _extract_trace(self, result: dict, project_root: Path) -> list[DataflowStep]:
        code_flows = result.get("codeFlows", [])
        if not code_flows:
            return []
        thread_flows = code_flows[0].get("threadFlows", [])
        if not thread_flows:
            return []

        locations = thread_flows[0].get("locations", [])
        steps: list[DataflowStep] = []
        total = len(locations)

        for i, loc in enumerate(locations):
            phys = loc.get("location", {}).get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            raw_uri = artifact.get("uri", "")
            file_path = raw_uri.replace("file://", "")
            try:
                file_path = str(Path(file_path).resolve().relative_to(project_root))
            except ValueError:
                pass

            line = region.get("startLine", 0)
            content = region.get("snippet", {}).get("text", "").strip()

            if i == 0:
                label = "source"
            elif i == total - 1:
                label = "sink"
            else:
                label = "propagator"

            steps.append(DataflowStep(
                location=CodeLocation(file_path=file_path, line_start=line, line_end=line),
                content=content,
                label=label,
            ))

        return steps

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
