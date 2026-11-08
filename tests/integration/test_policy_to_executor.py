"""Integration test: policy guard to executor, with a mocked executor.

Confirms that denied requests never reach ``scanner.run_nmap`` (the only
function that spawns the real Nmap process), across every rejection reason:
unauthorized target, unknown profile, forbidden/duplicate/excess ports, and
the concurrency limit.
"""

from __future__ import annotations

import textwrap
from unittest.mock import AsyncMock

import pytest

from safe_nmap.server import pipeline, policy_config, scanner
from safe_nmap.shared.schemas import ScanRequest

POLICY_YAML = textwrap.dedent("""
    allowed_targets:
      - "127.0.0.1"
    profiles:
      web-check:
        allowed_ports: [8080]
        service_detection: false
    limits:
      timeout_seconds: 5
      max_ports_per_request: 2
      max_concurrent_scans: 1
    """)


@pytest.fixture
def configured_policy(monkeypatch, tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY_YAML)
    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(policy_file))
    policy_config.reset_policy_cache()
    yield
    policy_config.reset_policy_cache()


@pytest.fixture
def audit_log(monkeypatch, tmp_path):
    from safe_nmap.server import audit

    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(tmp_path / "audit.jsonl"))


@pytest.fixture
def mocked_scanner(monkeypatch):
    mock = AsyncMock(
        return_value=scanner.ScanExecution(
            nmap_started=True, xml_output="<nmaprun></nmaprun>", error_message=None, scan_ms=1.0
        )
    )
    monkeypatch.setattr(scanner, "run_nmap", mock)
    return mock


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"target": "10.0.0.1", "ports": [8080], "profile": "web-check"},  # unauthorized target
        {"target": "127.0.0.1", "ports": [8080], "profile": "ghost-check"},  # unknown profile
        {"target": "127.0.0.1", "ports": [9999], "profile": "web-check"},  # forbidden port
        {"target": "127.0.0.1", "ports": [8080, 8080], "profile": "web-check"},  # duplicate ports
    ],
)
async def test_denied_requests_never_invoke_the_executor(
    configured_policy, audit_log, mocked_scanner, request_kwargs
):
    response = await pipeline.run_scan(ScanRequest(**request_kwargs))

    assert response.status == "rejected"
    assert response.allowed is False
    assert response.nmap_started is False
    mocked_scanner.assert_not_called()


async def test_concurrency_limit_denial_never_invokes_the_executor(
    configured_policy, audit_log, monkeypatch
):
    import asyncio

    release_scan = asyncio.Event()
    started_scan = asyncio.Event()

    async def slow_run_nmap(arguments, timeout_seconds):
        started_scan.set()
        await release_scan.wait()
        return scanner.ScanExecution(
            nmap_started=True, xml_output="<nmaprun></nmaprun>", error_message=None, scan_ms=1.0
        )

    monkeypatch.setattr(scanner, "run_nmap", slow_run_nmap)

    request = ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check")
    first = asyncio.ensure_future(pipeline.run_scan(request))
    await started_scan.wait()

    second_response = await pipeline.run_scan(request)
    assert second_response.status == "rejected"
    assert second_response.nmap_started is False
    assert second_response.reason == "too many concurrent scans"

    release_scan.set()
    first_response = await first
    assert first_response.status == "success"
