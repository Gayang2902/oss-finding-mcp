# oss-finding-mcp

오픈소스 보안 도구를 통합하여 코드베이스 취약점을 탐지하는 MCP 서버.

Semgrep, CodeQL, Gitleaks, OSV-Scanner, Grype 5개 스캐너를 하나의 인터페이스로 통합하고, diff 분석 · 위험 패턴 감지 · 공격 표면 매핑 · 교차검증 등 지능형 분석 레이어를 제공합니다.

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Server (FastMCP)                     │
│                         14 Tools 등록                            │
├────────────┬────────────┬───────────────┬───────────────────────┤
│  스캐너 계층  │  분석 계층    │   저장/검증 계층  │     오케스트레이션      │
├────────────┼────────────┼───────────────┼───────────────────────┤
│ Semgrep    │ Diff       │ FindingStore  │ run_all_scans         │
│ CodeQL     │ Analyzer   │ (In-Memory)   │ (전체 스캔 오케스트레이션) │
│ Gitleaks   │            │               │                       │
│ OSV-Scanner│ Pattern    │ Correlator    │                       │
│ Grype      │ Detector   │ (교차검증)     │                       │
│            │            │               │                       │
│            │ Surface    │               │                       │
│            │ Analyzer   │               │                       │
└────────────┴────────────┴───────────────┴───────────────────────┘
       │            │              │
       ▼            ▼              ▼
┌────────────┐┌───────────┐┌──────────────┐
│ 통합 Finding ││ 통합 Finding ││ CorrelationGroup │
│   모델      ││   모델      ││ (그룹화된 결과)  │
└────────────┘└───────────┘└──────────────┘
```

### 계층 설명

**스캐너 계층** — 외부 OSS 보안 도구를 subprocess로 실행하고 결과(SARIF/JSON)를 통합 Finding 모델로 정규화합니다. 각 스캐너는 미설치 시 graceful degradation 합니다.

| 스캐너 | 역할 | 출력 포맷 |
|--------|------|-----------|
| Semgrep | SAST + Taint 분석 | SARIF (dataflow trace 포함) |
| CodeQL | 심층 시맨틱 SAST | SARIF (dataflow trace 포함) |
| Gitleaks | 시크릿/자격증명 탐지 | JSON |
| OSV-Scanner | 의존성 CVE 스캔 (SCA) | JSON |
| Grype | 의존성 CVE 스캔 (대체) | JSON |

**분석 계층** — 스캐너 없이도 동작하는 자체 분석 엔진입니다.

| 모듈 | 역할 | 기반 기술 |
|------|------|-----------|
| Diff Analyzer | git diff에서 보안 관련 변경 탐지 + 신규 코드 위험 패턴 스캔 | git + regex |
| Pattern Detector | 11종 위험 코드 패턴 빠른 탐지 (SQLi, XSS, RCE 등) | ripgrep + regex |
| Surface Analyzer | 공격 표면 매핑 (HTTP endpoint, parser, deserializer 등 8종) | ripgrep + regex |

**저장/검증 계층** — 스캔 결과를 세션 내 축적하여 교차 분석합니다.

- **FindingStore**: 모든 스캔 결과를 in-memory로 보관. 파일별/심각도별 집계 제공.
- **Correlator**: 복수 스캐너 결과를 위치/파일/CWE 기준으로 그룹화하고, 중복 제거 및 교차 확인된 이슈를 우선순위화합니다.

### 데이터 흐름

```
타겟 코드베이스
     │
     ▼
┌─ 스캔 단계 ──────────────────────────────────────┐
│ scan_semgrep ──→ SARIF 파싱 ──→ Finding[]        │
│ scan_codeql  ──→ SARIF 파싱 ──→ Finding[]        │
│ scan_secrets ──→ JSON 파싱  ──→ Finding[]         │
│ scan_dependencies ──→ JSON 파싱 ──→ Finding[]     │
└──────────────────────────────────────────────────┘
     │ 모든 Finding은 통합 스키마로 정규화
     ▼
┌─ 축적 ─────────────┐
│ FindingStore        │
│ (scan_id별 저장)     │
└─────────────────────┘
     │
     ▼
┌─ 분석 단계 ──────────────────────────────────────┐
│ correlate_scan_findings                          │
│   → 위치 근접도 기반 그룹화                         │
│   → 멀티스캐너 교차 확인                            │
│   → CWE 기반 분류                                 │
│   → 심각도 우선순위 정렬                            │
└──────────────────────────────────────────────────┘
     │
     ▼
  최종 결과: CorrelationGroup[]
  (교차 확인된 고신뢰 이슈 우선)
```

### 통합 Finding 모델

모든 스캐너 결과는 단일 스키마로 정규화됩니다:

```python
Finding(
    finding_id="abc123",        # 스캐너 + 룰 + 위치 기반 해시
    scanner="semgrep",          # semgrep | codeql | gitleaks | osv-scanner | grype
    category="sast",            # sast | sca | secret | dangerous_pattern
    severity="high",            # critical | high | medium | low | info
    title="[rule-id] 설명",
    description="상세 설명",
    location=CodeLocation(file_path="src/app.py", line_start=42, line_end=42),
    code_snippet="os.system(user_input)",
    dataflow_trace=[...],       # source → propagator → sink 추적
    rule_id="python-command-injection",
    cwe=["CWE-78"],
)
```

## 도구 목록 (14개)

| 카테고리 | 도구 | 설명 |
|---------|------|------|
| 상태 | `get_scanner_status` | 설치된 스캐너 확인 |
| SAST | `scan_semgrep` | Semgrep taint 분석 (Java, PHP, JS/TS, Python, Go) + 레지스트리 룰셋 |
| SAST | `scan_codeql` | CodeQL 심층 시맨틱 분석 (JS, Python, Java, Go, C/C++, C#, Ruby, Swift) |
| Secret | `scan_secrets` | Gitleaks 기반 시크릿/자격증명 탐지 |
| SCA | `scan_dependencies` | OSV-Scanner 또는 Grype로 의존성 CVE 스캔 |
| 오케스트레이션 | `run_all_scans` | 사용 가능한 전체 스캐너 일괄 실행 |
| Diff | `analyze_git_diff` | 보안 관점 git diff 분석 |
| 패턴 | `find_dangerous_patterns` | 11종 위험 패턴 regex 탐지 |
| 공격 표면 | `find_attack_surface` | 엔트리포인트/파서/역직렬화기 8종 매핑 |
| 교차검증 | `correlate_scan_findings` | 멀티스캐너 교차 확인 + 중복 제거 |
| 결과 관리 | `list_scans` | 완료된 스캔 목록 |
| 결과 관리 | `get_scan_findings` | 스캔 결과 조회 (페이지네이션) |
| 결과 관리 | `get_finding_detail` | 개별 finding 상세 (dataflow trace 포함) |
| 결과 관리 | `get_findings_summary` | 전체 스캔 통합 통계 |

## 사전 요구사항

필수:
- Python 3.11+
- [ripgrep](https://github.com/BurntSushi/ripgrep)

선택 (필요한 것만 설치):
```bash
pip install semgrep
brew install gitleaks osv-scanner
brew install --cask codeql   # + git clone https://github.com/github/codeql ~/.codeql/codeql-repo
brew install grype            # OSV-Scanner 대체
```

## 설치

```bash
pip install -e .
```

## 사용법

### MCP 서버 실행

```bash
OSS_FINDING_PROJECT_ROOT=/path/to/target oss-finding-mcp
```

### Claude Desktop / Claude Code 설정

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

### 사용 예시

```
1. get_scanner_status로 사용 가능한 스캐너 확인
2. run_all_scans로 전체 스캔 실행  (또는 개별 스캐너 호출)
3. get_findings_summary로 전체 현황 파악
4. get_scan_findings로 상세 결과 조회
5. correlate_scan_findings로 멀티스캐너 교차 확인
6. get_finding_detail로 개별 취약점 dataflow trace 분석
```

## 환경 변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `OSS_FINDING_PROJECT_ROOT` | O | 분석 대상 레포 절대 경로 |
| `OSS_FINDING_CACHE_DIR` | X | 캐시 디렉터리 (기본: `~/.cache/oss-finding-mcp`) |
| `OSS_FINDING_SEMGREP_TIMEOUT` | X | Semgrep 타임아웃 초 (기본: 300) |
| `OSS_FINDING_CODEQL_TIMEOUT` | X | CodeQL 타임아웃 초 (기본: 600) |

## 내장 Semgrep 룰

5개 언어 taint 룰 + 3개 공통 룰셋:

| 룰 파일 | 대상 | 탐지 항목 |
|---------|------|-----------|
| `python_taint.yaml` | Python | Command injection, SQLi, SSRF, path traversal, SSTI, unsafe deserialization |
| `go_taint.yaml` | Go | Command injection, SQLi, SSRF, path traversal |
| `js_taint.yaml` | JS/TS | Command injection, SQLi, XSS, SSRF, path traversal, prototype pollution |
| `php_taint.yaml` | PHP | Command injection, SQLi, XSS, file inclusion, SSRF |
| `java_spring_taint.yaml` | Java | Command injection, SQLi, XSS, SSRF, path traversal, LDAP/EL injection |
| `dangerous_crypto.yaml` | 공통 | Weak hash, ECB mode, hardcoded IV, insecure PRNG, TLS 검증 비활성화 |
| `dangerous_deser.yaml` | 공통 | Pickle, YAML, marshal, Java ObjectInputStream, PHP unserialize |
| `dangerous_injection.yaml` | 공통 | Code injection, XXE, open redirect, log injection, header injection |

추가로 `registry_ruleset` 파라미터로 Semgrep 레지스트리 룰셋(`p/security-audit`, `p/owasp-top-ten` 등)을 직접 사용할 수 있습니다.

## 경로 제외

다음 디렉터리/파일은 패턴 감지 및 공격 표면 분석에서 자동 제외됩니다:

- **디렉터리**: `node_modules`, `vendor`, `third_party`, `third-party`, `.git`, `__pycache__`, `dist`, `build`, `venv` 등
- **파일 패턴**: `*.min.js`, `*.bundle.js`, `*.map`, `*.generated.*`, `*lock*` 파일 등

## Django 실전 테스트 결과

| 스캐너 | 결과 | 소요 시간 |
|--------|------|-----------|
| Semgrep | 53 findings (weak crypto, unsafe deser, taint) | 15초 |
| CodeQL | 76 findings (path injection, cookie injection, XSS, template injection) | 204초 |
| Gitleaks | 8 findings (generic API keys) | 7초 |
| Pattern Detector | 110 findings (vendor 제외 후) | 1초 |
| Attack Surface | 1,447 entries (742 HTTP, 519 DB, 96 template, 90 deserialize) | 2초 |

Semgrep과 CodeQL이 서로 다른 취약점을 탐지 — 멀티스캐너 교차 확인의 가치를 실증.

## 라이선스

MIT
