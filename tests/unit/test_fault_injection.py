"""Fault injection for C-021 (Nmap missing) and C-022 (scan timeout), plus other failure paths.

Goal: show the system fails *safe*. For every fault the response must be an explicit
``scan_failed`` / ``rejected`` / ``parse_error`` with no findings, never reported as a port state,
never ``success``, and the audit log must still record the decision first. Cases C-021/C-022 are
read from evaluation/cases.json so the case file and the tests cannot drift apart.
"""

from __future__ import annotations

import asyncio
import json
import textwrap

import pytest
from _case_data import ALL_CASES, CASES_BY_ID

from safe_nmap.agent.planner import plan_scan_request
from safe_nmap.server import audit, pipeline, policy_config, scanner
from safe_nmap.shared.schemas import ScanRequest

POLICY_YAML = textwrap.dedent("""
    allowed_targets:
      - "127.0.0.1"
    profiles:
      web-check:
        allowed_ports: [8080]
        service_detection: false
    limits:
      timeout_seconds: 1
      max_ports_per_request: 2
      max_concurrent_scans: 1
    """)
FAULT_CASES = {c["expected"]["fault_injection"]: c for c in ALL_CASES if "fault_injection" in c["expected"]}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY_YAML)
    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(policy_file))
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(tmp_path / "audit.jsonl"))
    policy_config.reset_policy_cache()
    scanner._resolve_nmap_executable.cache_clear()
    yield
    policy_config.reset_policy_cache()
    scanner._resolve_nmap_executable.cache_clear()


def _events(tmp_path):
    path = tmp_path / "audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class _FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, hang=False):
        self.returncode = None if hang else returncode
        self._stdout, self._stderr, self._hang = stdout, stderr, hang
        self.terminated = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(30)
        return self._stdout, self._stderr

    def terminate(self):
        self.terminated = True
        self._hang = False
        self.returncode = -15

    def kill(self):
        self._hang = False
        self.returncode = -9


def _patch_subprocess(monkeypatch, process):
    started = []

    async def fake_create(*args, **kwargs):
        started.append(args)
        return process

    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_create)
    return started


def _request_for(case_id):
    return plan_scan_request(CASES_BY_ID[case_id]["input"])


def _assert_failed_safe(response, events):
    assert response.status != "success"
    assert response.findings is None, "a failed scan must never carry port findings"
    decisions = [e for e in events if e["event"] == "decision"]
    assert decisions and events[0]["event"] == "decision", "decision is logged before anything else"


def test_both_fault_cases_exist_in_cases_json():
    assert set(FAULT_CASES) == {"nmap_missing", "timeout"}
    assert {c["case_id"] for c in FAULT_CASES.values()} == {"C-021", "C-022"}


# --- C-021: Nmap executable missing -------------------------------------------------------


async def test_c021_missing_nmap_fails_explicitly_and_starts_no_process(monkeypatch, tmp_path):
    case = FAULT_CASES["nmap_missing"]
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)

    async def must_not_start(*args, **kwargs):
        raise AssertionError("no subprocess may be started when Nmap is missing")

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", must_not_start)

    response = await pipeline.run_scan(_request_for(case["case_id"]))
    events = _events(tmp_path)

    assert response.allowed is True  # the guard authorized it; the failure is execution-side
    assert response.status == "scan_failed"
    assert response.nmap_started is False
    assert case["expected"]["fault_reason_contains"] in response.reason.lower()
    _assert_failed_safe(response, events)
    assert [e["event"] for e in events] == ["decision", "outcome"]
    assert events[1]["final_status"] == "scan_failed"
    assert events[1]["nmap_started"] is False


# --- C-022: scan timeout -------------------------------------------------------------------


async def test_c022_timeout_fails_explicitly_and_terminates_the_process(monkeypatch, tmp_path):
    case = FAULT_CASES["timeout"]
    process = _FakeProcess(hang=True)
    started = _patch_subprocess(monkeypatch, process)

    response = await pipeline.run_scan(_request_for(case["case_id"]))  # policy timeout: 1 s
    events = _events(tmp_path)

    assert len(started) == 1
    assert response.allowed is True
    assert response.status == "scan_failed"
    assert response.nmap_started is True
    assert case["expected"]["fault_reason_contains"] in response.reason.lower()
    assert process.terminated is True, "a timed-out scan must be stopped, not left running"
    _assert_failed_safe(response, events)
    assert events[-1]["final_status"] == "scan_failed"


async def test_timeout_comes_from_policy_not_from_the_request(monkeypatch):
    seen = []

    async def fake_run_nmap(arguments, timeout_seconds):
        seen.append(timeout_seconds)
        return scanner.ScanExecution(True, "<nmaprun></nmaprun>", None, 1.0)

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)
    await pipeline.run_scan(_request_for("C-022"))
    assert seen == [1]


# --- other ways a scan can go wrong must also fail safe -----------------------------------


async def test_nonzero_nmap_exit_is_an_error_not_a_port_state(monkeypatch, tmp_path):
    _patch_subprocess(monkeypatch, _FakeProcess(stderr=b"nmap: permission denied", returncode=1))
    response = await pipeline.run_scan(_request_for("C-001"))
    assert response.status == "scan_failed"
    assert "permission denied" in response.reason
    _assert_failed_safe(response, _events(tmp_path))


async def test_empty_nmap_output_is_an_error_not_a_closed_port(monkeypatch, tmp_path):
    async def fake_run_nmap(arguments, timeout_seconds):
        return scanner.ScanExecution(True, None, None, 1.0)

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)
    response = await pipeline.run_scan(_request_for("C-001"))
    assert response.status == "scan_failed"
    assert "without returning XML" in response.reason
    _assert_failed_safe(response, _events(tmp_path))


async def test_malformed_nmap_xml_is_a_parse_error_with_no_findings(monkeypatch, tmp_path):
    async def fake_run_nmap(arguments, timeout_seconds):
        return scanner.ScanExecution(True, "<nmaprun><host>", None, 1.0)

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)
    response = await pipeline.run_scan(_request_for("C-001"))
    assert response.status == "parse_error"
    assert response.findings is None
    assert "malformed" in response.reason.lower()


async def test_port_absent_from_nmap_xml_is_not_reported_as_closed(monkeypatch):
    async def fake_run_nmap(arguments, timeout_seconds):
        return scanner.ScanExecution(True, "<nmaprun></nmaprun>", None, 1.0)

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)
    response = await pipeline.run_scan(_request_for("C-001"))
    assert response.status == "success"
    assert response.findings == [], "no <port> entry means no finding, never an inferred 'closed'"


async def test_unwritable_audit_log_blocks_the_scan(monkeypatch, tmp_path):
    """Fail closed: if the decision cannot be logged, Nmap must not start."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(blocker / "audit.jsonl"))

    async def must_not_run(arguments, timeout_seconds):
        raise AssertionError("Nmap must not start when the decision cannot be logged")

    monkeypatch.setattr(scanner, "run_nmap", must_not_run)
    response = await pipeline.run_scan(_request_for("C-001"))
    assert response.status == "rejected"
    assert response.nmap_started is False
    assert "Audit logging failed" in response.reason


async def test_missing_policy_file_rejects_and_blocks_the_scan(monkeypatch, tmp_path):
    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(tmp_path / "missing.yaml"))
    policy_config.reset_policy_cache()

    async def must_not_run(arguments, timeout_seconds):
        raise AssertionError("Nmap must not start without a policy")

    monkeypatch.setattr(scanner, "run_nmap", must_not_run)
    response = await pipeline.run_scan(
        ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check")
    )
    assert response.status == "rejected"
    assert response.nmap_started is False
    assert "unavailable" in response.reason.lower()


async def test_unexpected_guard_error_fails_closed(monkeypatch):
    from safe_nmap.server import policy_guard

    def boom(request):
        raise RuntimeError("unexpected")

    async def must_not_run(arguments, timeout_seconds):
        raise AssertionError("Nmap must not start after an unexpected guard error")

    monkeypatch.setattr(policy_guard, "_validate_target_syntax", lambda target: boom(target))
    monkeypatch.setattr(scanner, "run_nmap", must_not_run)
    response = await pipeline.run_scan(
        ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check")
    )
    assert response.status == "rejected"
    assert response.nmap_started is False
    assert "Could not authorize" in response.reason
