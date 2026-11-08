"""Unit tests for JSONL audit event writing."""

import json

import pytest

from safe_nmap.server import audit


def test_write_event_appends_one_json_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit.write_event({"event": "decision", "request_id": "r1"}, path=log_path)
    audit.write_event({"event": "outcome", "request_id": "r1"}, path=log_path)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"event": "decision", "request_id": "r1"}
    assert json.loads(lines[1]) == {"event": "outcome", "request_id": "r1"}


def test_write_event_creates_parent_directories(tmp_path):
    log_path = tmp_path / "nested" / "dir" / "audit.jsonl"
    audit.write_event({"event": "decision"}, path=log_path)
    assert log_path.exists()


def test_write_event_raises_on_unwritable_path(tmp_path):
    # Using a directory as the log "file" forces a write failure.
    blocked_path = tmp_path / "blocked"
    blocked_path.mkdir()
    with pytest.raises(audit.AuditWriteError):
        audit.write_event({"event": "decision"}, path=blocked_path)


def test_log_outcome_event_never_raises_on_failure(tmp_path, capsys):
    blocked_path = tmp_path / "blocked"
    blocked_path.mkdir()

    audit.log_outcome_event({"event": "outcome"}, path=blocked_path)

    captured = capsys.readouterr()
    assert "Warning" in captured.err


def test_resolve_audit_path_uses_env_var(monkeypatch, tmp_path):
    custom_path = tmp_path / "custom.jsonl"
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(custom_path))

    audit.write_event({"event": "decision"})

    assert custom_path.exists()


def test_utc_timestamp_is_iso8601_with_timezone():
    timestamp = audit.utc_timestamp()
    assert "T" in timestamp
    assert timestamp.endswith("+00:00")
