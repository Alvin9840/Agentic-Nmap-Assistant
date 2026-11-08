"""Append-only JSONL audit logging for policy decisions, scan outcomes, and
agent-side planning.

The server's pre-scan "decision" event must fail closed: if it cannot be
written, the caller rejects the request instead of starting Nmap. Every other
event (the server's post-scan "outcome" event and the agent's "planner"
event) is best-effort: a logging failure is reported to stderr and never
changes a result already produced for the caller. Never log API keys,
credentials, or raw command strings here.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_AUDIT_PATH = Path("results/audit.jsonl")
AUDIT_PATH_ENV_VAR = "SAFE_NMAP_AUDIT_LOG"

_write_lock = threading.Lock()


class AuditWriteError(RuntimeError):
    """Raised when an audit event cannot be written."""


def utc_timestamp() -> str:
    """Return the current time as an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


def _resolve_audit_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    env_path = os.environ.get(AUDIT_PATH_ENV_VAR)
    if env_path:
        return Path(env_path)
    return DEFAULT_AUDIT_PATH


def write_event(event: dict[str, Any], path: str | Path | None = None) -> None:
    """Append one JSON object as a single line to the audit log.

    Raises ``AuditWriteError`` on any failure. Callers on the fail-closed path
    (the server's pre-scan decision event) must let this propagate and reject
    the request rather than starting Nmap. ``_write_lock`` only synchronizes
    writers within this process; the agent and server run as separate
    processes, so concurrent cross-process writes rely on POSIX append-mode
    writes of a single line remaining atomic below ``PIPE_BUF``.
    """
    audit_path = _resolve_audit_path(path)
    line = json.dumps(event, sort_keys=True) + "\n"

    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with _write_lock, audit_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as exc:
        raise AuditWriteError(f"Could not write audit event to {audit_path}: {exc}") from exc


def log_outcome_event(event: dict[str, Any], path: str | Path | None = None) -> None:
    """Best-effort audit write that never raises or changes the caller's result."""
    try:
        write_event(event, path)
    except AuditWriteError as exc:
        print(f"Warning: failed to write audit event: {exc}", file=sys.stderr)
