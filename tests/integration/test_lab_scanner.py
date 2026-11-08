"""Integration tests against the real nmap binary and the Docker lab.

These tests require ``docker compose -f lab/docker-compose.yml up -d`` and a
real ``nmap`` on PATH; they are skipped automatically otherwise.
"""

from __future__ import annotations

import shutil
import socket

import pytest

from safe_nmap.server import parser, policy_config, scanner


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


async def test_scan_approved_port_reports_open_http():
    execution = await scanner.run_nmap(
        ["nmap", "-n", "-sT", "-T3", "-oX", "-", "-sV", "-p", "8080", "127.0.0.1"],
        timeout_seconds=30,
    )
    assert execution.nmap_started is True
    assert execution.error_message is None

    findings = parser.parse_nmap_xml(execution.xml_output)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.port == 8080
    assert finding.state == "open"
    assert finding.service == "http"
    assert finding.product == "nginx"


async def test_scan_port_with_nothing_listening_reports_closed():
    execution = await scanner.run_nmap(
        ["nmap", "-n", "-sT", "-T3", "-oX", "-", "-p", "9999", "127.0.0.1"],
        timeout_seconds=30,
    )
    assert execution.nmap_started is True
    findings = parser.parse_nmap_xml(execution.xml_output)
    assert len(findings) == 1
    assert findings[0].state == "closed"


def test_example_policy_only_authorizes_the_approved_port():
    # config/policy.example.yaml only lists 127.0.0.1:8080; the decoy's 8081
    # is reachable but never an authorized port under either profile.
    policy = policy_config.load_policy("config/policy.example.yaml")
    assert policy.allowed_targets == ["127.0.0.1"]
    for profile in policy.profiles.values():
        assert 8081 not in profile.allowed_ports
