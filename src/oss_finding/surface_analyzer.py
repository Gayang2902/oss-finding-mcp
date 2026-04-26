"""Attack surface analysis — identify entry points and high-risk code areas."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .config import Settings
from .models import AttackSurfaceEntry, AttackSurfaceResult, CodeLocation

ENTRY_POINT_PATTERNS: list[dict] = [
    {
        "type": "http_endpoint",
        "patterns": [
            (r"@(Get|Post|Put|Delete|Patch|Request)Mapping", "Spring endpoint"),
            (r"@(GET|POST|PUT|DELETE|PATCH|HEAD)\b", "JAX-RS endpoint"),
            (r"app\.(get|post|put|delete|patch|all|use)\s*\(", "Express endpoint"),
            (r"router\.(get|post|put|delete|patch|all|use)\s*\(", "Express router"),
            (r"fastify\.(get|post|put|delete|patch)\s*\(", "Fastify endpoint"),
            (r"@app\.(route|get|post|put|delete|patch)\s*\(", "Flask endpoint"),
            (r"path\s*\(\s*[\"']", "Django URL pattern"),
            (r"Route::(get|post|put|delete|patch|any)\s*\(", "Laravel route"),
            (r"func\s+\w+Handler\b", "Go HTTP handler"),
            (r"http\.HandleFunc\s*\(", "Go HTTP handler"),
            (r"gin\.(GET|POST|PUT|DELETE|PATCH)\s*\(", "Gin endpoint"),
        ],
        "risk_indicators": ["user_input", "network_boundary"],
    },
    {
        "type": "file_parse",
        "patterns": [
            (r"(xml\.parse|etree\.parse|etree\.fromstring|SAXParser)", "XML parsing"),
            (r"(json\.loads?|JSON\.parse)\s*\(", "JSON parsing"),
            (r"(yaml\.safe_load|yaml\.load|yaml\.unsafe_load)\s*\(", "YAML parsing"),
            (r"(csv\.reader|csv\.DictReader)\s*\(", "CSV parsing"),
            (r"(toml\.load|tomli\.load)\s*\(", "TOML parsing"),
            (r"protobuf|proto\.Unmarshal", "Protobuf parsing"),
            (r"msgpack\.(unpack|loads)", "MessagePack parsing"),
        ],
        "risk_indicators": ["untrusted_input", "parser_vulnerability"],
    },
    {
        "type": "deserialize",
        "patterns": [
            (r"pickle\.(loads?|Unpickler)\s*\(", "Python pickle"),
            (r"(unserialize|php://input)", "PHP unserialize"),
            (r"ObjectInputStream|readObject", "Java deserialization"),
            (r"(Marshal\.load|YAML\.load)\s*\(", "Ruby deserialization"),
            (r"jsonpickle\.decode", "jsonpickle decode"),
            (r"shelve\.open\s*\(", "Python shelve"),
        ],
        "risk_indicators": ["rce_risk", "untrusted_input"],
    },
    {
        "type": "cli_arg",
        "patterns": [
            (r"(argparse\.ArgumentParser|click\.command|typer\.Typer)", "Python CLI"),
            (r"(process\.argv|yargs|commander)", "Node.js CLI"),
            (r"(flag\.Parse|pflag\.Parse|cobra\.Command)", "Go CLI"),
            (r"sys\.argv", "Python sys.argv"),
        ],
        "risk_indicators": ["user_input"],
    },
    {
        "type": "socket",
        "patterns": [
            (r"socket\.(socket|create_server|listen)", "Socket server"),
            (r"net\.(createServer|Socket)\s*\(", "Node.js socket"),
            (r"ServerSocket|DatagramSocket", "Java socket"),
            (r"net\.Listen\s*\(", "Go listener"),
            (r"WebSocket|ws\.Server", "WebSocket"),
        ],
        "risk_indicators": ["network_boundary", "untrusted_input"],
    },
    {
        "type": "file_upload",
        "patterns": [
            (r"multer|formidable|busboy", "Node.js file upload"),
            (r"request\.files|FileField|upload_to", "Python/Django file upload"),
            (r"MultipartFile|@RequestParam.*file", "Java file upload"),
            (r"\$_FILES|move_uploaded_file", "PHP file upload"),
        ],
        "risk_indicators": ["untrusted_input", "file_write"],
    },
    {
        "type": "template_render",
        "patterns": [
            (r"render_template_string\s*\(", "Flask template string (SSTI risk)"),
            (r"Jinja2|Environment\(.*loader", "Jinja2 template"),
            (r"nunjucks\.renderString", "Nunjucks render string"),
            (r"Velocity|Freemarker|Thymeleaf", "Java template engine"),
            (r"Twig|Blade::render", "PHP template"),
        ],
        "risk_indicators": ["ssti_risk", "untrusted_input"],
    },
    {
        "type": "database",
        "patterns": [
            (r"execute\s*\(|cursor\.(execute|callproc)", "Direct SQL execution"),
            (r"createQuery|nativeQuery|@Query", "JPA/Hibernate query"),
            (r"MongoClient|mongoose\.(connect|model)", "MongoDB"),
            (r"redis\.(Redis|StrictRedis|createClient)", "Redis client"),
        ],
        "risk_indicators": ["data_store", "injection_sink"],
    },
]


def analyze_attack_surface(
    settings: Settings,
    target_dir: str | None = None,
    entry_types: list[str] | None = None,
) -> AttackSurfaceResult:
    root = settings.project_root
    if target_dir:
        root = (settings.project_root / target_dir).resolve()

    patterns_to_scan = ENTRY_POINT_PATTERNS
    if entry_types:
        patterns_to_scan = [p for p in ENTRY_POINT_PATTERNS if p["type"] in entry_types]

    all_entries: list[AttackSurfaceEntry] = []
    summary: dict[str, int] = {}

    for pattern_group in patterns_to_scan:
        entry_type = pattern_group["type"]
        risk_indicators = pattern_group.get("risk_indicators", [])

        for regex, detail in pattern_group["patterns"]:
            hits = _ripgrep_search(root, regex)
            for file_path, line_num, line_text in hits:
                try:
                    rel_path = str(Path(file_path).relative_to(settings.project_root))
                except ValueError:
                    rel_path = file_path

                all_entries.append(AttackSurfaceEntry(
                    entry_type=entry_type,
                    location=CodeLocation(
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num,
                    ),
                    detail=f"{detail}: {line_text.strip()[:120]}",
                    risk_indicators=risk_indicators,
                ))

        summary[entry_type] = len([e for e in all_entries if e.entry_type == entry_type])

    seen: set[str] = set()
    deduped: list[AttackSurfaceEntry] = []
    for e in all_entries:
        key = f"{e.entry_type}:{e.location.file_path}:{e.location.line_start}"
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    return AttackSurfaceResult(
        total_entries=len(deduped),
        entries=deduped,
        summary=summary,
    )


def _ripgrep_search(root: Path, pattern: str) -> list[tuple[str, int, str]]:
    cmd = ["rg", "--no-heading", "--line-number", "--with-filename", "-e", pattern, str(root)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    results: list[tuple[str, int, str]] = []
    for line in proc.stdout.splitlines()[:1000]:
        match = re.match(r"^(.+?):(\d+):(.*)$", line)
        if match:
            results.append((match.group(1), int(match.group(2)), match.group(3)))

    return results
