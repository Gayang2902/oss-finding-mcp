"""Dangerous pattern detection using regex + optional Semgrep."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .config import Settings
from .models import (
    CodeLocation,
    Finding,
    FindingCategory,
    Severity,
)

DANGEROUS_PATTERNS: list[dict] = [
    {
        "id": "command-injection",
        "title": "Potential command injection",
        "patterns": [
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True",
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"ProcessBuilder\s*\(",
            r"exec\s*\(\s*[\"']",
            r"child_process\.(exec|spawn)\s*\(",
            r"shell_exec\s*\(",
            r"passthru\s*\(",
            r"system\s*\(",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-78"],
        "description": "External command execution that may be vulnerable to injection",
    },
    {
        "id": "sql-injection",
        "title": "Potential SQL injection",
        "patterns": [
            r"execute\s*\(\s*f[\"']",
            r"execute\s*\(\s*[\"'].*%s",
            r"\.query\s*\(\s*[\"'].*\+",
            r"\.query\s*\(\s*`",
            r"Statement\.execute\s*\(",
            r"createQuery\s*\(\s*[\"'].*\+",
            r"DB::raw\s*\(",
            r"\$wpdb->query\s*\(",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-89"],
        "description": "SQL query construction that may be vulnerable to injection",
    },
    {
        "id": "xss",
        "title": "Potential XSS",
        "patterns": [
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"document\.write\s*\(",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"\{\{.*\|.*safe\s*\}\}",
            r"@Html\.Raw\s*\(",
            r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
        ],
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-79"],
        "description": "HTML injection that may lead to cross-site scripting",
    },
    {
        "id": "path-traversal",
        "title": "Potential path traversal",
        "patterns": [
            r"open\s*\(.*\+",
            r"readFile(Sync)?\s*\(.*\+",
            r"Path\.Combine\s*\(",
            r"file_get_contents\s*\(\s*\$",
            r"include\s*\(\s*\$",
            r"require\s*\(\s*\$",
            r"\.resolve\s*\(.*req\.",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-22"],
        "description": "File path construction with external input",
    },
    {
        "id": "deserialization",
        "title": "Unsafe deserialization",
        "patterns": [
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\([^)]*$",
            r"yaml\.load\s*\([^)]*\)\s*$",
            r"unserialize\s*\(",
            r"ObjectInputStream\s*\(",
            r"readObject\s*\(",
            r"JSON\.parse\s*\(.*req\.",
            r"marshal\.load\s*\(",
            r"shelve\.open\s*\(",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-502"],
        "description": "Deserialization of untrusted data",
    },
    {
        "id": "weak-crypto",
        "title": "Weak cryptography",
        "patterns": [
            r"hashlib\.(md5|sha1)\s*\(",
            r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']",
            r"crypto\.createHash\s*\(\s*[\"'](md5|sha1)[\"']",
            r"DES\b|RC4\b|Blowfish\b",
            r"crypto\.createCipher\b",
            r"Math\.random\s*\(",
            r"rand\s*\(\s*\)",
            r"ECB\b",
        ],
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-327", "CWE-328"],
        "description": "Use of weak or broken cryptographic algorithm",
    },
    {
        "id": "ssrf",
        "title": "Potential SSRF",
        "patterns": [
            r"requests\.(get|post|put|delete|patch|head)\s*\(.*\+",
            r"fetch\s*\(.*\+",
            r"urllib\.request\.urlopen\s*\(",
            r"http\.get\s*\(.*\+",
            r"HttpClient\.(get|post|put)",
            r"curl_exec\s*\(",
            r"file_get_contents\s*\(\s*[\"']https?://",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-918"],
        "description": "HTTP request with potentially user-controlled URL",
    },
    {
        "id": "open-redirect",
        "title": "Potential open redirect",
        "patterns": [
            r"redirect\s*\(\s*req\.",
            r"res\.redirect\s*\(",
            r"header\s*\(\s*[\"']Location:\s*.*\$",
            r"HttpResponseRedirect\s*\(",
            r"sendRedirect\s*\(",
            r"window\.location\s*=",
            r"location\.href\s*=",
        ],
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-601"],
        "description": "Redirect with potentially user-controlled destination",
    },
    {
        "id": "hardcoded-secret",
        "title": "Hardcoded secret",
        "patterns": [
            r"(?:password|passwd|secret|api_?key|token|auth)\s*=\s*[\"'][A-Za-z0-9+/=]{8,}[\"']",
            r"(?:AWS_SECRET|PRIVATE_KEY)\s*=\s*[\"']",
            r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-798"],
        "description": "Hardcoded credential or secret value",
    },
    {
        "id": "xxe",
        "title": "Potential XXE",
        "patterns": [
            r"XMLParser\s*\(",
            r"etree\.parse\s*\(",
            r"etree\.fromstring\s*\(",
            r"DocumentBuilderFactory",
            r"SAXParserFactory",
            r"XMLReader",
            r"simplexml_load_string\s*\(",
            r"DOMDocument\s*\(",
        ],
        "severity": Severity.HIGH,
        "cwe": ["CWE-611"],
        "description": "XML parsing that may be vulnerable to XXE injection",
    },
    {
        "id": "race-condition",
        "title": "Potential race condition",
        "patterns": [
            r"check.*then.*use",
            r"if.*exists.*\n.*open",
            r"TOCTOU",
            r"flock\s*\(",
            r"fcntl\.flock\s*\(",
        ],
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-362"],
        "description": "Time-of-check to time-of-use pattern",
    },
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".gz", ".tar", ".pdf",
    ".pyc", ".class", ".o", ".so", ".dll", ".exe", ".bin",
}


def detect_patterns(
    settings: Settings,
    target_dir: str | None = None,
    pattern_ids: list[str] | None = None,
    file_glob: str | None = None,
) -> list[Finding]:
    root = settings.project_root
    if target_dir:
        root = (settings.project_root / target_dir).resolve()

    patterns_to_scan = DANGEROUS_PATTERNS
    if pattern_ids:
        patterns_to_scan = [p for p in DANGEROUS_PATTERNS if p["id"] in pattern_ids]

    findings: list[Finding] = []

    for pat_def in patterns_to_scan:
        for regex in pat_def["patterns"]:
            hits = _ripgrep_search(root, regex, file_glob)
            for file_path, line_num, line_text in hits:
                try:
                    rel_path = str(Path(file_path).relative_to(settings.project_root))
                except ValueError:
                    rel_path = file_path

                fid = f"pattern:{pat_def['id']}:{rel_path}:{line_num}"
                finding_id = hashlib.sha256(fid.encode()).hexdigest()[:16]

                findings.append(Finding(
                    finding_id=finding_id,
                    scanner="pattern-detector",
                    category=FindingCategory.DANGEROUS_PATTERN,
                    severity=pat_def["severity"],
                    title=pat_def["title"],
                    description=pat_def["description"],
                    location=CodeLocation(
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num,
                    ),
                    code_snippet=line_text.strip(),
                    rule_id=pat_def["id"],
                    cwe=pat_def.get("cwe", []),
                ))

    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = f"{f.location.file_path}:{f.location.line_start}:{f.rule_id}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped[:settings.scanner_max_findings]


def _ripgrep_search(
    root: Path, pattern: str, file_glob: str | None,
) -> list[tuple[str, int, str]]:
    cmd = ["rg", "--no-heading", "--line-number", "--no-filename", "-e", pattern]
    if file_glob:
        cmd.extend(["--glob", file_glob])
    cmd.append(str(root))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    results: list[tuple[str, int, str]] = []

    cmd_with_file = ["rg", "--no-heading", "--line-number", "--with-filename", "-e", pattern]
    if file_glob:
        cmd_with_file.extend(["--glob", file_glob])
    cmd_with_file.append(str(root))

    try:
        proc = subprocess.run(
            cmd_with_file, capture_output=True, text=True, check=False, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    for line in proc.stdout.splitlines()[:500]:
        match = re.match(r"^(.+?):(\d+):(.*)$", line)
        if match:
            fpath = match.group(1)
            ext = Path(fpath).suffix.lower()
            if ext in BINARY_EXTENSIONS:
                continue
            results.append((fpath, int(match.group(2)), match.group(3)))

    return results
