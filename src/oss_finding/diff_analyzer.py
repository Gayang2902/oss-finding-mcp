"""Git diff analysis for security-focused change review."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .config import Settings
from .models import (
    CodeLocation,
    DiffAnalysisResult,
    DiffEntry,
    Finding,
    FindingCategory,
    Severity,
)

SECURITY_FILE_PATTERNS = [
    r"auth", r"login", r"session", r"token", r"crypt",
    r"password", r"secret", r"key", r"cert", r"permission",
    r"access", r"role", r"admin", r"sanitiz", r"escap",
    r"valid", r"filter", r"middleware", r"guard",
    r"\.env", r"config", r"setting",
]

SECURITY_CODE_PATTERNS = [
    (r"eval\s*\(", "eval() usage", Severity.HIGH),
    (r"exec\s*\(", "exec() usage", Severity.HIGH),
    (r"innerHTML\s*=", "innerHTML assignment (potential XSS)", Severity.MEDIUM),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML", Severity.MEDIUM),
    (r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True", "Shell injection risk", Severity.HIGH),
    (r"os\.system\s*\(", "os.system() usage", Severity.HIGH),
    (r"Runtime\.getRuntime\(\)\.exec", "Java command execution", Severity.HIGH),
    (r"ProcessBuilder", "Java ProcessBuilder", Severity.MEDIUM),
    (r"unserialize\s*\(", "PHP unserialize", Severity.HIGH),
    (r"pickle\.loads?\s*\(", "Python pickle deserialization", Severity.HIGH),
    (r"yaml\.load\s*\(", "Unsafe YAML load", Severity.MEDIUM),
    (r"JSON\.parse\s*\(", "JSON parse (check input source)", Severity.LOW),
    (r"crypto\.createCipher\b", "Deprecated crypto.createCipher", Severity.MEDIUM),
    (r"md5|MD5|sha1|SHA1", "Weak hash algorithm", Severity.MEDIUM),
    (r"TODO.*(?:hack|fixme|security|vuln|temp)", "Security-related TODO", Severity.LOW),
    (r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded credential", Severity.HIGH),
    (r"disable.*(?:csrf|xss|auth|ssl|tls|verify)", "Security feature disabled", Severity.HIGH),
    (r"verify\s*=\s*False", "SSL verification disabled", Severity.HIGH),
    (r"allowAll|permitAll|@PermitAll", "Open access endpoint", Severity.MEDIUM),
]


def analyze_diff(
    settings: Settings,
    base_ref: str = "HEAD~1",
    head_ref: str = "HEAD",
    scan_new_code: bool = True,
) -> DiffAnalysisResult:
    diff_entries = _parse_git_diff(settings.project_root, base_ref, head_ref)

    security_files: list[str] = []
    for entry in diff_entries:
        for pattern in SECURITY_FILE_PATTERNS:
            if re.search(pattern, entry.file_path, re.IGNORECASE):
                security_files.append(entry.file_path)
                break

    new_findings: list[Finding] = []
    if scan_new_code:
        new_findings = _scan_added_lines(settings, diff_entries, head_ref)

    return DiffAnalysisResult(
        base_ref=base_ref,
        head_ref=head_ref,
        total_files_changed=len(diff_entries),
        entries=diff_entries,
        security_relevant_files=security_files,
        new_findings=new_findings,
    )


def _parse_git_diff(project_root: Path, base_ref: str, head_ref: str) -> list[DiffEntry]:
    try:
        proc = subprocess.run(
            ["git", "diff", "--numstat", f"{base_ref}...{head_ref}"],
            capture_output=True, text=True, cwd=project_root, check=False,
        )
    except FileNotFoundError:
        return []

    if proc.returncode != 0:
        try:
            proc = subprocess.run(
                ["git", "diff", "--numstat", base_ref, head_ref],
                capture_output=True, text=True, cwd=project_root, check=False,
            )
        except FileNotFoundError:
            return []

    entries: list[DiffEntry] = []

    name_status = subprocess.run(
        ["git", "diff", "--name-status", f"{base_ref}...{head_ref}"],
        capture_output=True, text=True, cwd=project_root, check=False,
    )
    if name_status.returncode != 0:
        name_status = subprocess.run(
            ["git", "diff", "--name-status", base_ref, head_ref],
            capture_output=True, text=True, cwd=project_root, check=False,
        )

    status_map: dict[str, str] = {}
    for line in name_status.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            s = parts[0][0].upper()
            fname = parts[-1]
            status_map[fname] = {
                "A": "added", "M": "modified", "D": "deleted", "R": "renamed",
            }.get(s, "modified")

    diff_lines_proc = subprocess.run(
        ["git", "diff", "-U0", f"{base_ref}...{head_ref}"],
        capture_output=True, text=True, cwd=project_root, check=False,
    )
    if diff_lines_proc.returncode != 0:
        diff_lines_proc = subprocess.run(
            ["git", "diff", "-U0", base_ref, head_ref],
            capture_output=True, text=True, cwd=project_root, check=False,
        )

    file_added_lines: dict[str, list[int]] = {}
    file_deleted_lines: dict[str, list[int]] = {}
    current_file = ""
    for line in diff_lines_proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            file_added_lines.setdefault(current_file, [])
            file_deleted_lines.setdefault(current_file, [])
        elif line.startswith("@@ "):
            hunk_match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if hunk_match:
                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2) or "1")
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4) or "1")
                if old_count > 0:
                    file_deleted_lines.setdefault(current_file, []).extend(
                        range(old_start, old_start + old_count)
                    )
                if new_count > 0:
                    file_added_lines.setdefault(current_file, []).extend(
                        range(new_start, new_start + new_count)
                    )

    all_files = set(status_map.keys()) | set(file_added_lines.keys())
    for fname in sorted(all_files):
        entries.append(DiffEntry(
            file_path=fname,
            status=status_map.get(fname, "modified"),
            added_lines=file_added_lines.get(fname, []),
            deleted_lines=file_deleted_lines.get(fname, []),
        ))

    return entries


def _scan_added_lines(
    settings: Settings,
    entries: list[DiffEntry],
    head_ref: str,
) -> list[Finding]:
    findings: list[Finding] = []

    for entry in entries:
        if entry.status == "deleted" or not entry.added_lines:
            continue

        file_path = settings.project_root / entry.file_path
        if not file_path.exists():
            continue

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        added_set = set(entry.added_lines)
        for line_num in sorted(added_set):
            if line_num < 1 or line_num > len(lines):
                continue
            line_text = lines[line_num - 1]

            for pattern, desc, severity in SECURITY_CODE_PATTERNS:
                if re.search(pattern, line_text):
                    fid = f"diff-{entry.file_path}-{line_num}-{desc[:20]}"
                    import hashlib
                    finding_id = hashlib.sha256(fid.encode()).hexdigest()[:16]

                    findings.append(Finding(
                        finding_id=finding_id,
                        scanner="diff-analyzer",
                        category=FindingCategory.DANGEROUS_PATTERN,
                        severity=severity,
                        title=f"New code: {desc}",
                        description=f"Potentially dangerous pattern in newly added code at {entry.file_path}:{line_num}",
                        location=CodeLocation(
                            file_path=entry.file_path,
                            line_start=line_num,
                            line_end=line_num,
                        ),
                        code_snippet=line_text.strip(),
                        rule_id=f"diff-{pattern[:30]}",
                    ))

    return findings
