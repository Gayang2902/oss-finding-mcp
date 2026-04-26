"""In-memory finding store for cross-scanner correlation."""

from __future__ import annotations

import threading
from collections import defaultdict

from .models import Finding, ScanResult


class FindingStore:
    def __init__(self) -> None:
        self._scans: dict[str, ScanResult] = {}
        self._lock = threading.Lock()

    def add_scan(self, result: ScanResult) -> None:
        with self._lock:
            self._scans[result.scan_id] = result

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            return self._scans.get(scan_id)

    def list_scans(self) -> list[ScanResult]:
        with self._lock:
            return list(self._scans.values())

    def all_findings(self) -> list[Finding]:
        with self._lock:
            findings: list[Finding] = []
            for scan in self._scans.values():
                findings.extend(scan.findings)
            return findings

    def findings_by_file(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in self.all_findings():
            grouped[f.location.file_path].append(f)
        return dict(grouped)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in self.all_findings():
            grouped[f.severity.value].append(f)
        return dict(grouped)

    def clear(self) -> None:
        with self._lock:
            self._scans.clear()


STORE = FindingStore()
