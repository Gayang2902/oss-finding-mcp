"""MCP server entry point — registers all tools and runs over stdio."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import Settings, load_settings
from .correlator import correlate_findings
from .diff_analyzer import analyze_diff
from .models import FindingCategory, ScanSummary, Severity
from .pattern_detector import detect_patterns
from .scanners.codeql import CodeQLScanner
from .scanners.gitleaks import GitleaksScanner
from .scanners.osv import GrypeScanner, OsvScanner
from .scanners.semgrep import SemgrepScanner
from .store import STORE
from .surface_analyzer import analyze_attack_surface

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("oss-finding")

_semgrep = SemgrepScanner()
_codeql = CodeQLScanner()
_gitleaks = GitleaksScanner()
_osv = OsvScanner()
_grype = GrypeScanner()


def _scan_summary(result) -> dict:
    severity_counts: dict[str, int] = {}
    for f in result.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    return ScanSummary(
        scan_id=result.scan_id,
        scanner=result.scanner,
        category=result.category.value,
        total_findings=result.total_findings,
        severity_counts=severity_counts,
        run_time_seconds=result.run_time_seconds,
        commit_hash=result.commit_hash,
    ).model_dump()


def _build_server(settings: Settings) -> FastMCP:
    mcp = FastMCP("oss-finding")

    # ================================================================
    # Scanner status
    # ================================================================

    @mcp.tool()
    def get_scanner_status() -> dict:
        """Check which security scanners are installed and available.

        Call this first to know which scan tools you can use.
        Returns availability of: semgrep, codeql, gitleaks, osv-scanner, grype.
        """
        return {
            "project_root": str(settings.project_root),
            "available_scanners": settings.available_scanners(),
            "cache_dir": str(settings.cache_dir),
        }

    # ================================================================
    # SAST scanners
    # ================================================================

    @mcp.tool()
    def scan_semgrep(
        language: str | None = None,
        rule_file: str | None = None,
        target_dir: str | None = None,
        include_extras: bool = True,
        diff_aware: bool = False,
        baseline_ref: str | None = None,
        registry_ruleset: str | None = None,
    ) -> dict:
        """Run Semgrep SAST scan with taint analysis.

        Supports: Java, PHP, JavaScript/TypeScript, Python, Go.
        Built-in rules cover taint flows (source→sink), dangerous crypto,
        deserialization, and injection patterns.

        Args:
            language: Filter to specific language rules.
            rule_file: Custom rule file path (relative to project root).
            target_dir: Subdirectory to scan (relative to project root).
            include_extras: Include dangerous pattern rules beyond taint (default True).
            diff_aware: Only report findings in changed code since baseline_ref.
            baseline_ref: Git ref for diff-aware scanning (e.g. "main", "HEAD~5").
            registry_ruleset: Semgrep registry ruleset (e.g. "p/security-audit",
                "p/owasp-top-ten", "p/secrets"). Overrides language/rule_file.
        """
        result = _semgrep.scan(
            settings,
            target_dir=Path(target_dir) if target_dir else None,
            language=language,
            rule_file=rule_file,
            include_extras=include_extras,
            diff_aware=diff_aware,
            baseline_ref=baseline_ref,
            registry_ruleset=registry_ruleset,
        )
        STORE.add_scan(result)
        return _scan_summary(result)

    @mcp.tool()
    def scan_codeql(
        language: str,
        target_dir: str | None = None,
        query_suite: str | None = None,
        query_file: str | None = None,
    ) -> dict:
        """Run CodeQL deep semantic analysis.

        Creates a CodeQL database and runs security queries. Most powerful for
        finding complex inter-procedural vulnerabilities.

        Supports: javascript, python, java, go, cpp, csharp, ruby, swift.

        Args:
            language: Target language (required).
            target_dir: Subdirectory to scan.
            query_suite: CodeQL query suite (default: {lang}-security-and-quality).
            query_file: Custom .ql query file path.
        """
        result = _codeql.scan(
            settings,
            target_dir=Path(target_dir) if target_dir else None,
            language=language,
            query_suite=query_suite,
            query_file=query_file,
        )
        STORE.add_scan(result)
        return _scan_summary(result)

    # ================================================================
    # Secret detection
    # ================================================================

    @mcp.tool()
    def scan_secrets(
        target_dir: str | None = None,
        scan_git_history: bool = False,
        config_file: str | None = None,
    ) -> dict:
        """Detect hardcoded secrets, API keys, tokens, and credentials using Gitleaks.

        Args:
            target_dir: Subdirectory to scan.
            scan_git_history: Also scan git commit history (slower but thorough).
            config_file: Custom gitleaks config file path.
        """
        result = _gitleaks.scan(
            settings,
            target_dir=Path(target_dir) if target_dir else None,
            scan_git_history=scan_git_history,
            config_file=config_file,
        )
        STORE.add_scan(result)
        return _scan_summary(result)

    # ================================================================
    # SCA (dependency vulnerabilities)
    # ================================================================

    @mcp.tool()
    def scan_dependencies(
        target_dir: str | None = None,
        lockfile: str | None = None,
        use_grype: bool = False,
    ) -> dict:
        """Scan dependencies for known vulnerabilities (CVEs).

        Uses OSV-Scanner by default, or Grype as alternative.
        Checks package.json, requirements.txt, go.sum, pom.xml, Cargo.lock, etc.

        Args:
            target_dir: Subdirectory containing dependency files.
            lockfile: Specific lockfile to scan (e.g. "package-lock.json").
            use_grype: Use Grype instead of OSV-Scanner.
        """
        scanner = _grype if use_grype else _osv
        result = scanner.scan(
            settings,
            target_dir=Path(target_dir) if target_dir else None,
            **({"lockfile": lockfile} if lockfile and not use_grype else {}),
        )
        STORE.add_scan(result)
        return _scan_summary(result)

    # ================================================================
    # Orchestration
    # ================================================================

    @mcp.tool()
    def run_all_scans(
        target_dir: str | None = None,
        language: str | None = None,
        include_codeql: bool = False,
    ) -> dict:
        """Run all available scanners in sequence and return combined summary.

        Runs: Semgrep (SAST) → Gitleaks (secrets) → OSV-Scanner (SCA).
        CodeQL is opt-in (slower, requires language param).

        Args:
            target_dir: Subdirectory to scan.
            language: Language hint for Semgrep/CodeQL.
            include_codeql: Include CodeQL scan (slower, needs language).
        """
        results: list[dict] = []
        target = Path(target_dir) if target_dir else None

        if _semgrep.is_available():
            r = _semgrep.scan(settings, target_dir=target, language=language)
            STORE.add_scan(r)
            results.append(_scan_summary(r))

        if _gitleaks.is_available():
            r = _gitleaks.scan(settings, target_dir=target)
            STORE.add_scan(r)
            results.append(_scan_summary(r))

        if _osv.is_available():
            r = _osv.scan(settings, target_dir=target)
            STORE.add_scan(r)
            results.append(_scan_summary(r))
        elif _grype.is_available():
            r = _grype.scan(settings, target_dir=target)
            STORE.add_scan(r)
            results.append(_scan_summary(r))

        if include_codeql and language and _codeql.is_available():
            r = _codeql.scan(settings, target_dir=target, language=language)
            STORE.add_scan(r)
            results.append(_scan_summary(r))

        total_findings = sum(r["total_findings"] for r in results)
        return {
            "scans_completed": len(results),
            "total_findings": total_findings,
            "results": results,
        }

    # ================================================================
    # Diff analysis
    # ================================================================

    @mcp.tool()
    def analyze_git_diff(
        base_ref: str = "HEAD~1",
        head_ref: str = "HEAD",
        scan_new_code: bool = True,
    ) -> dict:
        """Analyze git diff for security-relevant changes.

        Identifies security-sensitive file changes and scans newly added code
        for dangerous patterns. Essential for reviewing PRs and version bumps.

        Args:
            base_ref: Base git reference (e.g. "main", "v1.0.0", "HEAD~10").
            head_ref: Head git reference (default: HEAD).
            scan_new_code: Scan newly added lines for dangerous patterns.
        """
        result = analyze_diff(settings, base_ref, head_ref, scan_new_code)
        return result.model_dump()

    # ================================================================
    # Dangerous pattern detection
    # ================================================================

    @mcp.tool()
    def find_dangerous_patterns(
        target_dir: str | None = None,
        pattern_ids: list[str] | None = None,
        file_glob: str | None = None,
    ) -> dict:
        """Find dangerous code patterns using regex-based detection.

        Covers: command-injection, sql-injection, xss, path-traversal,
        deserialization, weak-crypto, ssrf, open-redirect, hardcoded-secret,
        xxe, race-condition.

        Faster than Semgrep but less precise. Use for quick triage, then
        validate with scan_semgrep or scan_codeql.

        Args:
            target_dir: Subdirectory to scan.
            pattern_ids: Filter to specific patterns (e.g. ["sql-injection", "xss"]).
            file_glob: File glob filter (e.g. "*.py", "src/**/*.java").
        """
        findings = detect_patterns(settings, target_dir, pattern_ids, file_glob)

        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings": [f.model_dump() for f in findings[:50]],
            "truncated": len(findings) > 50,
        }

    # ================================================================
    # Attack surface
    # ================================================================

    @mcp.tool()
    def find_attack_surface(
        target_dir: str | None = None,
        entry_types: list[str] | None = None,
    ) -> dict:
        """Map the attack surface: entry points, parsers, deserializers, sinks.

        Identifies: http_endpoint, file_parse, deserialize, cli_arg, socket,
        file_upload, template_render, database.

        Use this to understand where untrusted data enters the application
        and where it gets processed.

        Args:
            target_dir: Subdirectory to analyze.
            entry_types: Filter to specific entry types.
        """
        result = analyze_attack_surface(settings, target_dir, entry_types)
        return result.model_dump()

    # ================================================================
    # Correlation
    # ================================================================

    @mcp.tool()
    def correlate_scan_findings(
        scan_ids: list[str] | None = None,
        group_by: str = "location",
        dedup_radius: int = 5,
    ) -> dict:
        """Cross-reference findings from multiple scanners.

        Groups related findings, removes duplicates, and identifies issues
        confirmed by multiple tools (higher confidence).

        Args:
            scan_ids: Specific scan IDs to correlate (default: all scans).
            group_by: Grouping strategy — "location" | "file" | "cwe".
            dedup_radius: Line proximity for deduplication (default 5).
        """
        result = correlate_findings(scan_ids, group_by, dedup_radius)
        return result.model_dump()

    # ================================================================
    # Finding management
    # ================================================================

    @mcp.tool()
    def list_scans() -> dict:
        """List all completed scan results with their IDs and finding counts."""
        scans = STORE.list_scans()
        return {
            "scans": [_scan_summary(s) for s in scans],
            "total_scans": len(scans),
        }

    @mcp.tool()
    def get_scan_findings(
        scan_id: str,
        severity: str | None = None,
        limit: int = 30,
        offset: int = 0,
    ) -> dict:
        """Get findings from a specific scan (paginated).

        Args:
            scan_id: The scan ID returned by a scan tool.
            severity: Filter by severity (critical, high, medium, low, info).
            limit: Max findings per page (default 30).
            offset: Pagination offset.
        """
        scan = STORE.get_scan(scan_id)
        if scan is None:
            return {"error": f"Scan not found: {scan_id}"}

        findings = scan.findings
        if severity:
            findings = [f for f in findings if f.severity.value == severity]

        page = findings[offset:offset + limit]
        return {
            "scan_id": scan_id,
            "total": len(findings),
            "offset": offset,
            "limit": limit,
            "truncated": (offset + limit) < len(findings),
            "findings": [f.model_dump() for f in page],
        }

    @mcp.tool()
    def get_finding_detail(scan_id: str, finding_id: str) -> dict:
        """Get full detail for a single finding including dataflow trace.

        Args:
            scan_id: The scan ID.
            finding_id: The finding ID.
        """
        scan = STORE.get_scan(scan_id)
        if scan is None:
            return {"error": f"Scan not found: {scan_id}"}

        for f in scan.findings:
            if f.finding_id == finding_id:
                return f.model_dump()

        return {"error": f"Finding not found: {finding_id}"}

    @mcp.tool()
    def get_findings_summary() -> dict:
        """Get aggregated summary of all findings across all scans.

        Shows totals by severity, scanner, category, and top affected files.
        """
        findings = STORE.all_findings()

        by_severity: dict[str, int] = {}
        by_scanner: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_file: dict[str, int] = {}

        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
            by_category[f.category.value] = by_category.get(f.category.value, 0) + 1
            by_file[f.location.file_path] = by_file.get(f.location.file_path, 0) + 1

        top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_scanner": by_scanner,
            "by_category": by_category,
            "top_affected_files": dict(top_files),
        }

    return mcp


def main() -> None:
    try:
        settings = load_settings()
    except RuntimeError as e:
        print(f"[oss-finding] {e}", file=sys.stderr)
        sys.exit(1)

    log.info("Starting OSS Finding MCP")
    log.info("  project_root: %s", settings.project_root)
    log.info("  cache_dir:    %s", settings.cache_dir)
    log.info("  scanners:     %s", settings.available_scanners())

    mcp = _build_server(settings)
    mcp.run()


if __name__ == "__main__":
    main()
