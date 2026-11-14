"""One unauthorized request, start to finish, through the real MCP stack.

Shows, for the request "profile web-check port 9999 target 127.0.0.1":
  1. the input text,  2. the parsed plan,  3. the guard's decision (and reason),
  4. the audit trail,  5. evidence that no Nmap process was started.

Evidence for (5) works across the process boundary: the spawned MCP server finds a *fake* ``nmap``
first on its PATH; the fake records every invocation in a sentinel file. If the sentinel does not
exist after the request, Nmap was never executed. A control request (authorized, port 8080)
shows the sentinel does fire when Nmap is run, so its absence is meaningful.

Needs neither real Nmap nor the Docker lab. Run with ``pytest -s`` to print the walkthrough.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from safe_nmap.agent.cli import run_cli_request
from safe_nmap.agent.planner import plan_scan_request
from safe_nmap.server import audit

UNAUTHORIZED_TEXT = "profile web-check port 9999 target 127.0.0.1"
AUTHORIZED_TEXT = "profile web-check port 8080 target 127.0.0.1"
FAKE_NMAP = """#!/bin/sh
echo "$@" >> "$FAKE_NMAP_SENTINEL"
echo '<nmaprun></nmaprun>'
"""


@pytest.fixture
def stack(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "nmap"
    fake.write_text(FAKE_NMAP)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    sentinel = tmp_path / "nmap_was_executed.txt"
    audit_log = tmp_path / "audit.jsonl"
    # The agent-side "planner" audit event is written by this process; point it at the same file.
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(audit_log))
    env = {
        "SAFE_NMAP_POLICY": "config/policy.example.yaml",
        "SAFE_NMAP_AUDIT_LOG": str(audit_log),
        "FAKE_NMAP_SENTINEL": str(sentinel),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    }
    return {"env": env, "sentinel": sentinel, "audit": audit_log}


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


async def test_unauthorized_request_walkthrough_ends_with_no_nmap_process(stack):
    # 1. input text -> 2. parsed plan
    plan = plan_scan_request(UNAUTHORIZED_TEXT)
    assert (plan.target, plan.ports, plan.profile) == ("127.0.0.1", [9999], "web-check")

    # 3. guard decision, through the real CLI -> MCP client -> MCP server -> policy guard
    response, context = await run_cli_request(UNAUTHORIZED_TEXT, "deterministic", stack["env"])
    assert response.status == "rejected"
    assert response.allowed is False
    assert response.nmap_started is False
    assert "ports are not all authorized" in response.reason
    assert response.findings is None
    assert context.request.ports == [9999], "the planner did not change the requested port"

    # 4. audit trail: planner proposal, then one rejected decision, and no outcome event
    events = _events(stack["audit"])
    by_kind = {e["event"]: e for e in events}
    assert sorted(by_kind) == ["decision", "planner"]
    assert by_kind["planner"]["proposed_plan"] == {
        "target": "127.0.0.1", "ports": [9999], "profile": "web-check"
    }
    decision = by_kind["decision"]
    assert decision["policy_decision"] == "rejected"
    assert decision["original_request"] == by_kind["planner"]["proposed_plan"]
    assert decision["validated_destination"] is None
    assert decision["client_request_id"] == by_kind["planner"]["client_request_id"]
    assert "ports are not all authorized" in decision["reason"]

    # 5. no Nmap process: the fake nmap was never executed
    assert not stack["sentinel"].exists(), "Nmap was executed for a rejected request"

    print(
        "\n--- unauthorized request walkthrough ---\n"
        f"input    : {UNAUTHORIZED_TEXT}\n"
        f"plan     : target={plan.target} ports={plan.ports} profile={plan.profile}\n"
        f"decision : {response.status} (allowed={response.allowed}) - {response.reason}\n"
        f"audit    : {[e['event'] for e in events]}, decision={decision['policy_decision']}\n"
        f"nmap     : started={response.nmap_started}; executed sentinel present="
        f"{stack['sentinel'].exists()}"
    )


async def test_control_authorized_request_does_execute_nmap_so_the_evidence_is_meaningful(stack):
    response, _ = await run_cli_request(AUTHORIZED_TEXT, "deterministic", stack["env"])

    assert response.status == "success"
    assert response.nmap_started is True
    assert stack["sentinel"].exists()
    invocation = stack["sentinel"].read_text().strip()
    assert invocation.endswith("-p 8080 127.0.0.1")
    events = _events(stack["audit"])
    assert [e["event"] for e in events if e["event"] != "planner"] == ["decision", "outcome"]
