"""Integration test for the target-scope lab (lab/docker-compose.targets.yml).

Unlike tests/integration/test_lab_scanner.py (port-scope, loopback), this
proves *target-IP* scope enforcement: the approved and decoy services have
distinct container IPs on a Docker bridge network that is not routable from
the host, so this test must run *inside* the ``scanner`` container:

    docker compose -f lab/docker-compose.targets.yml up -d --build
    docker compose -f lab/docker-compose.targets.yml exec \
        -e SAFE_NMAP_POLICY=/app/config/policy.lab-network.example.yaml \
        scanner python3 -m pytest tests/integration/test_target_scope_lab.py -v

Skipped automatically everywhere else (including the host), since the
container-only IPs below are unreachable from the host by design.
"""

from __future__ import annotations

import socket

import pytest

from safe_nmap.server import command_builder, policy_guard, scanner

APPROVED_IP = "172.28.0.10"
DECOY_IP = "172.28.0.11"


def _host_is_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _host_is_reachable(APPROVED_IP, 80),
    reason=(
        "requires running inside the lab/docker-compose.targets.yml 'scanner' "
        "container, with SAFE_NMAP_POLICY pointed at policy.lab-network.example.yaml"
    ),
)


async def test_approved_container_ip_is_authorized_and_scanned():
    from safe_nmap.shared.schemas import ScanRequest

    request = ScanRequest(target=APPROVED_IP, ports=[80], profile="web-check")
    plan = policy_guard.authorize(request)
    arguments = command_builder.build_nmap_command(plan)
    execution = await scanner.run_nmap(arguments, plan.timeout_seconds)

    assert execution.nmap_started is True
    assert execution.xml_output is not None


def test_decoy_container_ip_is_rejected_despite_being_reachable():
    from safe_nmap.shared.schemas import ScanRequest

    assert _host_is_reachable(DECOY_IP, 80), "decoy must be reachable to prove this is a real rejection"

    request = ScanRequest(target=DECOY_IP, ports=[80], profile="web-check")
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(request)
