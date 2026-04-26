"""Base scanner interface."""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from ..config import Settings
from ..models import ScanResult


class ScannerNotAvailable(RuntimeError):
    pass


class ScannerError(RuntimeError):
    pass


class BaseScanner(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def scan(self, settings: Settings, target_dir: Path | None = None, **kwargs) -> ScanResult: ...

    def _require_available(self) -> None:
        if not self.is_available():
            raise ScannerNotAvailable(
                f"{self.name} is not installed. Install it to use this scanner."
            )

    @staticmethod
    def _run_cmd(
        cmd: list[str],
        timeout: int = 300,
        check: bool = False,
        accept_codes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=timeout,
            )
        except FileNotFoundError as e:
            raise ScannerNotAvailable(f"Command not found: {cmd[0]}") from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}") from e

        if check and proc.returncode not in accept_codes:
            raise ScannerError(
                f"{cmd[0]} failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
            )
        return proc
