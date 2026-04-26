"""Semgrep SAST scanner with taint analysis support."""

from __future__ import annotations

import hashlib
import importlib.resources
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

LANGUAGE_RULE_MAP = {
    "java": "java_spring_taint.yaml",
    "php": "php_taint.yaml",
    "javascript": "js_taint.yaml",
    "typescript": "js_taint.yaml",
    "python": "python_taint.yaml",
    "go": "go_taint.yaml",
}

EXTRA_RULE_FILES = [
    "dangerous_crypto.yaml",
    "dangerous_deser.yaml",
    "dangerous_injection.yaml",
]

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
}


def _get_builtin_rule(filename: str) -> Path:
    rules_pkg = importlib.resources.files("oss_finding.rules.semgrep")
    return Path(str(rules_pkg.joinpath(filename)))


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(
        self,
        settings: Settings,
        target_dir: Path | None = None,
        language: str | None = None,
        rule_file: str | None = None,
        include_extras: bool = True,
        diff_aware: bool = False,
        baseline_ref: str | None = None,
    ) -> ScanResult:
        self._require_available()
        target = self._resolve_target(settings, target_dir)
        rule_paths = self._resolve_rules(settings, language, rule_file, include_extras)

        scan_id = uuid.uuid4().hex[:12]
        sarif_dir = settings.cache_dir / "semgrep"
        sarif_dir.mkdir(parents=True, exist_ok=True)

        all_findings: list[Finding] = []
        total_time = 0.0
        errors: list[str] = []

        for rp in rule_paths:
            if not rp.exists():
                continue
            sarif_path = sarif_dir / f"{scan_id}_{rp.stem}.sarif.json"
            cmd = [
                "semgrep", "scan",
                "--config", str(rp),
                "--sarif", "--sarif-output", str(sarif_path),
                "--dataflow-traces",
                "--no-git-ignore",
                "--metrics=off",
                "--quiet",
            ]
            if diff_aware and baseline_ref:
                cmd.extend(["--baseline-commit", baseline_ref])
            cmd.append(str(target))

            start = time.monotonic()
            try:
                proc = self._run_cmd(cmd, timeout=settings.semgrep_timeout, accept_codes=(0, 1))
                if proc.returncode not in (0, 1):
                    errors.append(f"semgrep rule {rp.name}: exit {proc.returncode}")
                    continue
            except Exception as e:
                errors.append(str(e))
                continue
            elapsed = time.monotonic() - start
            total_time += elapsed

            if sarif_path.exists():
                findings = self._parse_sarif(sarif_path, settings.project_root)
                all_findings.extend(findings)

        if len(all_findings) > settings.scanner_max_findings:
            all_findings = all_findings[:settings.scanner_max_findings]

        return ScanResult(
            scan_id=scan_id,
            scanner=self.name,
            category=FindingCategory.SAST,
            total_findings=len(all_findings),
            findings=all_findings,
            run_time_seconds=round(total_time, 2),
            commit_hash=self._get_commit(settings.project_root),
            errors=errors,
        )

    def _resolve_target(self, settings: Settings, target_dir: Path | None) -> Path:
        if not target_dir:
            return settings.project_root
        target = (settings.project_root / target_dir).resolve()
        try:
            target.relative_to(settings.project_root)
        except ValueError as e:
            raise ValueError(f"target_dir must be inside project root") from e
        return target

    def _resolve_rules(
        self,
        settings: Settings,
        language: str | None,
        rule_file: str | None,
        include_extras: bool,
    ) -> list[Path]:
        if rule_file:
            p = Path(rule_file)
            if not p.is_absolute():
                p = settings.project_root / p
            return [p]

        paths: list[Path] = []
        if language and language in LANGUAGE_RULE_MAP:
            paths.append(_get_builtin_rule(LANGUAGE_RULE_MAP[language]))
        else:
            for fname in set(LANGUAGE_RULE_MAP.values()):
                paths.append(_get_builtin_rule(fname))

        if include_extras:
            for fname in EXTRA_RULE_FILES:
                paths.append(_get_builtin_rule(fname))

        return paths

    def _parse_sarif(self, sarif_path: Path, project_root: Path) -> list[Finding]:
        with sarif_path.open("r", encoding="utf-8") as f:
            sarif = json.load(f)

        findings: list[Finding] = []
        runs = sarif.get("runs", [])
        if not runs:
            return findings

        for result in runs[0].get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "note")
            severity = _SEVERITY_MAP.get(level, Severity.LOW)

            locations = result.get("locations", [])
            if not locations:
                continue

            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            raw_uri = artifact.get("uri", "")
            region = phys.get("region", {})

            file_path = self._normalize_uri(raw_uri, project_root)
            line_start = region.get("startLine", 0)
            line_end = region.get("endLine", line_start)
            snippet = region.get("snippet", {}).get("text", "")

            finding_id = hashlib.sha256(
                f"semgrep:{rule_id}:{file_path}:{line_start}".encode()
            ).hexdigest()[:16]

            trace = self._extract_trace(result, project_root)

            cwe = []
            props = result.get("properties", {})
            if "cwe" in props:
                cwe = props["cwe"] if isinstance(props["cwe"], list) else [props["cwe"]]

            findings.append(Finding(
                finding_id=finding_id,
                scanner="semgrep",
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
            file_path = self._normalize_uri(raw_uri, project_root)
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
    def _normalize_uri(uri: str, project_root: Path) -> str:
        cleaned = uri.replace("file://", "")
        try:
            return str(Path(cleaned).resolve().relative_to(project_root))
        except ValueError:
            return cleaned

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
