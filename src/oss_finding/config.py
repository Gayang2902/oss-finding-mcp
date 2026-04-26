from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_EXCLUDE_DIRS = frozenset({
    "node_modules", "vendor", "third_party", "third-party",
    ".git", ".svn", ".hg", "__pycache__", ".tox", ".venv", "venv",
    "dist", "build", ".eggs", "egg-info",
    "bower_components", "jspm_packages",
    "fixtures", "testdata",
})

DEFAULT_EXCLUDE_GLOBS = frozenset({
    "*.min.js", "*.min.css", "*.bundle.js", "*.map",
    "*.generated.*", "*.pb.go", "*_generated.go",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "Cargo.lock",
    "go.sum", "poetry.lock",
})


@dataclass(frozen=True)
class Settings:
    project_root: Path
    cache_dir: Path
    max_response_bytes: int = 200_000
    semgrep_timeout: int = 300
    codeql_timeout: int = 600
    scanner_max_findings: int = 1000
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS
    exclude_globs: frozenset[str] = DEFAULT_EXCLUDE_GLOBS

    @property
    def semgrep_available(self) -> bool:
        return shutil.which("semgrep") is not None

    @property
    def codeql_available(self) -> bool:
        return shutil.which("codeql") is not None

    @property
    def gitleaks_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    @property
    def osv_scanner_available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    @property
    def grype_available(self) -> bool:
        return shutil.which("grype") is not None

    def should_exclude(self, path: str) -> bool:
        from pathlib import PurePosixPath
        import fnmatch
        parts = PurePosixPath(path).parts
        for part in parts:
            if part in self.exclude_dirs:
                return True
        name = PurePosixPath(path).name
        for glob in self.exclude_globs:
            if fnmatch.fnmatch(name, glob):
                return True
        return False

    def available_scanners(self) -> dict[str, bool]:
        return {
            "semgrep": self.semgrep_available,
            "codeql": self.codeql_available,
            "gitleaks": self.gitleaks_available,
            "osv-scanner": self.osv_scanner_available,
            "grype": self.grype_available,
        }


def load_settings() -> Settings:
    root_str = os.environ.get("OSS_FINDING_PROJECT_ROOT")
    if not root_str:
        raise RuntimeError(
            "OSS_FINDING_PROJECT_ROOT environment variable is required. "
            "Set it to the absolute path of the target repository."
        )
    project_root = Path(root_str).expanduser().resolve()
    if not project_root.is_dir():
        raise RuntimeError(f"Project root is not a directory: {project_root}")

    cache_str = os.environ.get("OSS_FINDING_CACHE_DIR")
    if cache_str:
        cache_dir = Path(cache_str).expanduser().resolve()
    else:
        cache_dir = Path.home() / ".cache" / "oss-finding-mcp"
    cache_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        project_root=project_root,
        cache_dir=cache_dir,
        semgrep_timeout=int(os.environ.get("OSS_FINDING_SEMGREP_TIMEOUT", "300")),
        codeql_timeout=int(os.environ.get("OSS_FINDING_CODEQL_TIMEOUT", "600")),
    )
