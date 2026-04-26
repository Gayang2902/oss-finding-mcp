"""Cross-scanner finding correlation and deduplication."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from .models import (
    CorrelationGroup,
    CorrelationResult,
    Finding,
    Severity,
)
from .store import STORE

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def correlate_findings(
    scan_ids: list[str] | None = None,
    group_by: str = "location",
    dedup_radius: int = 5,
) -> CorrelationResult:
    if scan_ids:
        findings: list[Finding] = []
        for sid in scan_ids:
            scan = STORE.get_scan(sid)
            if scan:
                findings.extend(scan.findings)
    else:
        findings = STORE.all_findings()

    if not findings:
        return CorrelationResult(
            total_groups=0,
            groups=[],
            unique_findings=0,
            duplicate_findings_removed=0,
        )

    if group_by == "cwe":
        groups = _group_by_cwe(findings)
    elif group_by == "file":
        groups = _group_by_file(findings, dedup_radius)
    else:
        groups = _group_by_location(findings, dedup_radius)

    total_in_groups = sum(len(g.findings) for g in groups)
    duplicates_removed = len(findings) - total_in_groups

    return CorrelationResult(
        total_groups=len(groups),
        groups=groups,
        unique_findings=total_in_groups,
        duplicate_findings_removed=max(0, duplicates_removed),
    )


def _group_by_location(findings: list[Finding], radius: int) -> list[CorrelationGroup]:
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.location.file_path].append(f)

    groups: list[CorrelationGroup] = []

    for file_path, file_findings in by_file.items():
        sorted_findings = sorted(file_findings, key=lambda f: f.location.line_start)

        current_group: list[Finding] = []
        group_end = -1

        for f in sorted_findings:
            if not current_group or f.location.line_start <= group_end + radius:
                current_group.append(f)
                group_end = max(group_end, f.location.line_end or f.location.line_start)
            else:
                if current_group:
                    groups.append(_make_group(current_group))
                current_group = [f]
                group_end = f.location.line_end or f.location.line_start

        if current_group:
            groups.append(_make_group(current_group))

    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.consensus_severity, 0), reverse=True)
    return groups


def _group_by_file(findings: list[Finding], radius: int) -> list[CorrelationGroup]:
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.location.file_path].append(f)

    groups: list[CorrelationGroup] = []
    for file_path, file_findings in by_file.items():
        groups.append(_make_group(file_findings))

    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.consensus_severity, 0), reverse=True)
    return groups


def _group_by_cwe(findings: list[Finding]) -> list[CorrelationGroup]:
    by_cwe: dict[str, list[Finding]] = defaultdict(list)
    no_cwe: list[Finding] = []

    for f in findings:
        if f.cwe:
            for cwe in f.cwe:
                by_cwe[cwe].append(f)
        else:
            no_cwe.append(f)

    groups: list[CorrelationGroup] = []
    for cwe, cwe_findings in by_cwe.items():
        g = _make_group(cwe_findings)
        g.description = f"CWE: {cwe} — {len(cwe_findings)} findings from {len(g.scanners_involved)} scanner(s)"
        groups.append(g)

    if no_cwe:
        g = _make_group(no_cwe)
        g.description = f"No CWE — {len(no_cwe)} findings"
        groups.append(g)

    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.consensus_severity, 0), reverse=True)
    return groups


def _make_group(findings: list[Finding]) -> CorrelationGroup:
    scanners = list({f.scanner for f in findings})
    max_sev = max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    files = {f.location.file_path for f in findings}
    rules = {f.rule_id for f in findings if f.rule_id}

    group_id = hashlib.sha256(
        ":".join(sorted(f.finding_id for f in findings)).encode()
    ).hexdigest()[:12]

    desc_parts = []
    if len(scanners) > 1:
        desc_parts.append(f"Cross-scanner match ({', '.join(scanners)})")
    desc_parts.append(f"{len(findings)} finding(s) in {len(files)} file(s)")
    if rules:
        desc_parts.append(f"Rules: {', '.join(list(rules)[:5])}")

    return CorrelationGroup(
        group_id=group_id,
        findings=findings,
        scanners_involved=scanners,
        consensus_severity=max_sev,
        description=". ".join(desc_parts),
    )
