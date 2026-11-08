"""Execute a fixed Nmap argv list and capture XML output and process status."""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class ScanExecution:
    """Result of one Nmap process execution."""

    nmap_started: bool
    xml_output: str | None
    error_message: str | None
    scan_ms: float


@lru_cache(maxsize=1)
def _resolve_nmap_executable() -> str | None:
    """Resolve the trusted Nmap executable path once and cache the result."""
    return shutil.which("nmap")


async def run_nmap(arguments: Sequence[str], timeout_seconds: int) -> ScanExecution:
    """Run Nmap without a shell, enforce a timeout, and capture its output."""
    if not arguments or not arguments[0]:
        raise ValueError("Nmap arguments must include an executable name.")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero.")

    started_at = time.perf_counter()
    executable_path = _resolve_nmap_executable()
    if executable_path is None:
        return ScanExecution(
            nmap_started=False,
            xml_output=None,
            error_message="Nmap executable was not found on PATH.",
            scan_ms=_elapsed_ms(started_at),
        )

    try:
        process = await asyncio.create_subprocess_exec(
            executable_path,
            *arguments[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return ScanExecution(
            nmap_started=False,
            xml_output=None,
            error_message=f"Could not start Nmap: {exc}",
            scan_ms=_elapsed_ms(started_at),
        )

    try:
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
        except TimeoutError:
            await _stop_process(process)
            return ScanExecution(
                nmap_started=True,
                xml_output=None,
                error_message=f"Nmap scan timed out after {timeout_seconds} seconds.",
                scan_ms=_elapsed_ms(started_at),
            )
        except asyncio.CancelledError:
            await _stop_process(process)
            raise
    except OSError as exc:
        await _stop_process(process)
        return ScanExecution(
            nmap_started=True,
            xml_output=None,
            error_message=f"Error while collecting Nmap output: {exc}",
            scan_ms=_elapsed_ms(started_at),
        )

    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if process.returncode != 0:
        detail = stderr_text or f"Nmap exited with status {process.returncode}."
        return ScanExecution(
            nmap_started=True,
            xml_output=None,
            error_message=detail,
            scan_ms=_elapsed_ms(started_at),
        )

    return ScanExecution(
        nmap_started=True,
        xml_output=stdout.decode("utf-8", errors="replace"),
        error_message=None,
        scan_ms=_elapsed_ms(started_at),
    )


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    """Terminate a timed-out or cancelled process, escalating to kill if needed."""
    if process.returncode is not None:
        return

    try:
        process.terminate()
    except ProcessLookupError:
        pass

    try:
        await asyncio.wait_for(process.communicate(), timeout=2)
    except TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.communicate()


def _elapsed_ms(started_at: float) -> float:
    return (time.perf_counter() - started_at) * 1000
