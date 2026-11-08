"""End-to-end test: natural language -> deterministic planner -> real MCP
stdio server -> policy guard -> real Nmap against the local Docker lab.

Requires nmap on PATH and 'docker compose -f lab/docker-compose.yml up -d';
skipped automatically otherwise.
"""

from __future__ import annotations

import shutil
import socket

import pytest

from safe_nmap.agent.cli import run_cli_request


def _port_is_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _lab_is_available() -> bool:
    return shutil.which("nmap") is not None and _port_is_open("127.0.0.1", 8080)


pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        not _lab_is_available(),
        reason="requires nmap on PATH and 'docker compose -f lab/docker-compose.yml up -d'",
    ),
]


@pytest.fixture
def server_env(tmp_path):
    """Point the spawned MCP server subprocess at an isolated policy/audit path.

    ``config/policy.example.yaml`` resolves relative to the server's cwd
    (the project root, see ``create_server_parameters``), so no tmp copy is
    needed. ``StdioServerParameters.env`` only merges in a safe-listed subset
    of the parent environment (not the full ``os.environ``), so these
    variables must be passed explicitly rather than set with
    ``monkeypatch.setenv``.
    """
    return {
        "SAFE_NMAP_POLICY": "config/policy.example.yaml",
        "SAFE_NMAP_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }


async def test_approved_request_completes_through_the_real_stack(server_env):
    response, context = await run_cli_request(
        "profile web-check port 8080 target 127.0.0.1", "deterministic", server_env
    )

    assert context.mode == "deterministic"
    assert response.status == "success"
    assert response.allowed is True
    assert response.nmap_started is True
    assert response.findings is not None
    assert any(finding.port == 8080 for finding in response.findings)


async def test_decoy_port_is_rejected_and_nmap_never_starts(server_env):
    response, _ = await run_cli_request(
        "profile web-check port 8081 target 127.0.0.1", "deterministic", server_env
    )

    assert response.status == "rejected"
    assert response.allowed is False
    assert response.nmap_started is False
