"""Unit tests for the server-side policy guard.

These tests inject a ``Policy`` directly so they do not depend on a file on
disk, except where the test specifically exercises missing/invalid policy
file handling.
"""

import pytest
from pydantic import ValidationError

from safe_nmap.server import policy_guard
from safe_nmap.server.policy_config import Policy
from safe_nmap.shared.schemas import ScanRequest


@pytest.fixture
def policy() -> Policy:
    return Policy.model_validate(
        {
            "allowed_targets": ["127.0.0.1"],
            "profiles": {
                "web-check": {"allowed_ports": [8080], "service_detection": False},
                "service-check": {
                    "allowed_ports": [8080, 8081],
                    "service_detection": True,
                },
            },
            "limits": {
                "timeout_seconds": 60,
                "max_ports_per_request": 2,
                "max_concurrent_scans": 1,
            },
        }
    )


def _request(**overrides) -> ScanRequest:
    defaults = {"target": "127.0.0.1", "ports": [8080], "profile": "web-check"}
    defaults.update(overrides)
    return ScanRequest(**defaults)


def test_authorize_allows_a_benign_request(policy):
    plan = policy_guard.authorize(_request(), policy=policy)
    assert plan.resolved_ip == "127.0.0.1"
    assert plan.ports == [8080]
    assert plan.service_detection is False
    assert plan.timeout_seconds == 60


def test_authorize_uses_profile_settings_not_request_values(policy):
    # service_detection/timeout always come from policy, never the request.
    plan = policy_guard.authorize(_request(profile="service-check"), policy=policy)
    assert plan.service_detection is True
    assert plan.timeout_seconds == 60


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.1",  # not in allowed_targets
        "127.1",  # alternative short numeric form
        "2130706433",  # decimal integer encoding
        "0x7f.0.0.1",  # hex-octet encoding
        "127.0.0.01",  # leading zero
        "::1",  # IPv6
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6
        "127.0.0.1/32",  # CIDR
        "localhost",  # hostname (unsupported in V1)
    ],
)
def test_authorize_rejects_unsupported_or_forbidden_targets(policy, target):
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(_request(target=target), policy=policy)


def test_authorize_rejects_unknown_profile(policy):
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(_request(profile="ghost-check"), policy=policy)


def test_authorize_rejects_port_outside_profile(policy):
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(_request(ports=[9999]), policy=policy)


def test_authorize_rejects_too_many_ports(policy):
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(
            _request(profile="service-check", ports=[8080, 8081, 22]), policy=policy
        )


def test_authorize_rejects_duplicate_ports(policy):
    with pytest.raises(policy_guard.PolicyRejectedError):
        policy_guard.authorize(_request(ports=[8080, 8080]), policy=policy)


def test_authorize_fails_closed_when_policy_file_missing(monkeypatch, tmp_path):
    from safe_nmap.server import policy_config

    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(tmp_path / "missing.yaml"))
    policy_config.reset_policy_cache()
    try:
        with pytest.raises(policy_guard.PolicyRejectedError):
            policy_guard.authorize(_request())
    finally:
        policy_config.reset_policy_cache()


def test_authorize_fails_closed_when_policy_file_invalid(monkeypatch, tmp_path):
    from safe_nmap.server import policy_config

    bad_policy = tmp_path / "policy.yaml"
    bad_policy.write_text("allowed_targets: not-a-list\n")
    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(bad_policy))
    policy_config.reset_policy_cache()
    try:
        with pytest.raises(policy_guard.PolicyRejectedError):
            policy_guard.authorize(_request())
    finally:
        policy_config.reset_policy_cache()


def test_scan_request_cannot_carry_unexpected_fields():
    # Extra/raw-command fields are rejected before ever reaching the guard.
    with pytest.raises(ValidationError):
        ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check", raw_flags=["-A"])
