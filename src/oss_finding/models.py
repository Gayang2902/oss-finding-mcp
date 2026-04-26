from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    DANGEROUS_PATTERN = "dangerous_pattern"
    ATTACK_SURFACE = "attack_surface"


class CodeLocation(BaseModel):
    file_path: str = Field(description="Path relative to project root")
    line_start: int = Field(default=0)
    line_end: int = Field(default=0)
    column: int | None = None


class DataflowStep(BaseModel):
    location: CodeLocation
    content: str = ""
    label: str = Field(description="source | propagator | sink")


class Finding(BaseModel):
    """Unified finding format across all scanners."""
    finding_id: str
    scanner: str = Field(description="semgrep | codeql | gitleaks | osv-scanner | grype | internal")
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    location: CodeLocation
    code_snippet: str = ""
    dataflow_trace: list[DataflowStep] = Field(default_factory=list)
    rule_id: str = ""
    cwe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    scanner: str
    category: FindingCategory
    total_findings: int
    findings: list[Finding]
    run_time_seconds: float
    commit_hash: str | None = None
    errors: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    scan_id: str
    scanner: str
    category: str
    total_findings: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    run_time_seconds: float
    commit_hash: str | None = None


class DiffEntry(BaseModel):
    file_path: str
    status: str = Field(description="added | modified | deleted | renamed")
    added_lines: list[int] = Field(default_factory=list)
    deleted_lines: list[int] = Field(default_factory=list)


class DiffAnalysisResult(BaseModel):
    base_ref: str
    head_ref: str
    total_files_changed: int
    entries: list[DiffEntry]
    security_relevant_files: list[str] = Field(default_factory=list)
    new_findings: list[Finding] = Field(default_factory=list)


class AttackSurfaceEntry(BaseModel):
    entry_type: str = Field(description="http_endpoint | cli_arg | file_parse | deserialize | env_var | socket | ipc")
    location: CodeLocation
    detail: str
    risk_indicators: list[str] = Field(default_factory=list)


class AttackSurfaceResult(BaseModel):
    total_entries: int
    entries: list[AttackSurfaceEntry]
    summary: dict[str, int] = Field(default_factory=dict)


class CorrelationGroup(BaseModel):
    group_id: str
    findings: list[Finding]
    scanners_involved: list[str]
    consensus_severity: Severity
    description: str


class CorrelationResult(BaseModel):
    total_groups: int
    groups: list[CorrelationGroup]
    unique_findings: int
    duplicate_findings_removed: int
