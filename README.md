# oss-finding-mcp

MCP server for finding vulnerabilities in codebases using open-source security tools.

Multi-scanner orchestration with unified output — Semgrep, CodeQL, Gitleaks, OSV-Scanner, Grype — plus intelligent analysis layers for diff review, dangerous pattern detection, attack surface mapping, and cross-scanner correlation.

## Tools (13)

| Tool | Description |
|------|-------------|
| `get_scanner_status` | Check which scanners are installed |
| `scan_semgrep` | SAST with taint analysis (Java, PHP, JS/TS, Python, Go) |
| `scan_codeql` | Deep semantic analysis (JS, Python, Java, Go, C/C++, C#, Ruby, Swift) |
| `scan_secrets` | Secret detection via Gitleaks |
| `scan_dependencies` | SCA via OSV-Scanner or Grype |
| `analyze_git_diff` | Security-focused diff analysis |
| `find_dangerous_patterns` | Fast regex-based pattern detection (11 vulnerability classes) |
| `find_attack_surface` | Map entry points, parsers, deserializers, sinks |
| `correlate_scan_findings` | Cross-reference and deduplicate findings |
| `list_scans` | List completed scans |
| `get_scan_findings` | Get findings from a scan (paginated) |
| `get_finding_detail` | Full detail for one finding |
| `get_findings_summary` | Aggregated stats across all scans |

## Prerequisites

Required:
- Python 3.11+
- [ripgrep](https://github.com/BurntSushi/ripgrep)

Optional (install what you need):
```bash
pip install semgrep
brew install gitleaks osv-scanner
# CodeQL: https://github.com/github/codeql-cli-binaries
# Grype: brew install grype
```

## Install

```bash
pip install -e .
```

## Usage

### As MCP server

```bash
OSS_FINDING_PROJECT_ROOT=/path/to/target oss-finding-mcp
```

### Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "oss-finding": {
      "command": "oss-finding-mcp",
      "env": {
        "OSS_FINDING_PROJECT_ROOT": "/path/to/target"
      }
    }
  }
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OSS_FINDING_PROJECT_ROOT` | Yes | Absolute path to target repository |
| `OSS_FINDING_CACHE_DIR` | No | Cache directory (default: `~/.cache/oss-finding-mcp`) |
| `OSS_FINDING_SEMGREP_TIMEOUT` | No | Semgrep timeout in seconds (default: 300) |
| `OSS_FINDING_CODEQL_TIMEOUT` | No | CodeQL timeout in seconds (default: 600) |

## Semgrep Rules

Built-in taint rules for 5 languages + 3 cross-cutting rule sets:

- `python_taint.yaml` — Command injection, SQLi, SSRF, path traversal, SSTI, unsafe deserialization
- `go_taint.yaml` — Command injection, SQLi, SSRF, path traversal
- `js_taint.yaml` — Command injection, SQLi, XSS, SSRF, path traversal, prototype pollution
- `php_taint.yaml` — Command injection, SQLi, XSS, file inclusion, SSRF
- `java_spring_taint.yaml` — Command injection, SQLi, XSS, SSRF, path traversal, LDAP/EL injection
- `dangerous_crypto.yaml` — Weak hashes, ECB mode, hardcoded IV, insecure PRNG, TLS bypass
- `dangerous_deser.yaml` — Pickle, YAML, marshal, Java ObjectInputStream, PHP unserialize
- `dangerous_injection.yaml` — Code injection, XXE, open redirect, log injection, header injection

## License

MIT
