"""Unit tests for the deterministic fallback planner."""

import pytest
from pydantic import ValidationError

from safe_nmap.agent.planner import PlanningError, plan_scan_request


def test_plan_scan_request_extracts_target_ports_profile():
    request = plan_scan_request("profile web-check port 8080 target 127.0.0.1")
    assert request.target == "127.0.0.1"
    assert request.ports == [8080]
    assert request.profile == "web-check"


def test_plan_scan_request_preserves_explicit_target_verbatim():
    # The planner must not rewrite or "correct" an explicit target.
    request = plan_scan_request("profile web-check port 8080 target 127.0.0.2")
    assert request.target == "127.0.0.2"


def test_plan_scan_request_preserves_multiple_explicit_ports_in_order():
    request = plan_scan_request("profile service-check port 8080,8081 target 127.0.0.1")
    assert request.ports == [8080, 8081]


def test_plan_scan_request_rejects_multiple_targets():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port 8080 target 127.0.0.1 10.0.0.1")


def test_plan_scan_request_rejects_missing_target():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port 8080")


def test_plan_scan_request_rejects_missing_ports():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check target 127.0.0.1")


def test_plan_scan_request_rejects_port_ranges():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check ports 8000-8010 target 127.0.0.1")


def test_plan_scan_request_rejects_negative_ports():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port -5 target 127.0.0.1")


def test_plan_scan_request_rejects_multiple_port_clauses():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port 8080 port 9090 target 127.0.0.1")


def test_plan_scan_request_rejects_ports_without_separator():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port 8080 9090 target 127.0.0.1")


def test_plan_scan_request_preserves_unknown_profile_for_the_server_to_reject():
    # The planner does not authorize profiles; the server's policy guard does.
    request = plan_scan_request("profile ghost-check port 8080 target 127.0.0.1")
    assert request.profile == "ghost-check"


def test_plan_scan_request_infers_service_check_from_phrase():
    request = plan_scan_request("port 8080 target 127.0.0.1 with service detection")
    assert request.profile == "service-check"


def test_plan_scan_request_infers_web_check_from_phrase():
    request = plan_scan_request("port 8080 target 127.0.0.1 web check")
    assert request.profile == "web-check"


def test_plan_scan_request_rejects_ambiguous_profile_mentions():
    with pytest.raises(PlanningError):
        plan_scan_request("port 8080 target 127.0.0.1 web-check service-check")


def test_plan_scan_request_rejects_multiple_explicit_profiles():
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check profile service-check port 8080 target 127.0.0.1")


def test_plan_scan_request_rejects_missing_profile():
    with pytest.raises(PlanningError):
        plan_scan_request("port 8080 target 127.0.0.1")


def test_plan_scan_request_does_not_truncate_ipv4_mapped_ipv6_target():
    # Must preserve "::ffff:127.0.0.1" verbatim rather than silently reducing
    # it to its embedded "127.0.0.1"; the policy guard, not the planner,
    # rejects unsupported target syntax (see test_policy_guard.py).
    request = plan_scan_request("profile web-check port 8080 target ::ffff:127.0.0.1")
    assert request.target == "::ffff:127.0.0.1"


def test_plan_scan_request_does_not_truncate_cidr_target():
    # Must preserve "127.0.0.1/32" verbatim rather than silently dropping the
    # CIDR suffix; the policy guard rejects CIDR targets explicitly.
    request = plan_scan_request("profile web-check port 8080 target 127.0.0.1/32")
    assert request.target == "127.0.0.1/32"


def test_plan_scan_request_rejects_empty_text():
    with pytest.raises(PlanningError):
        plan_scan_request("   ")


def test_plan_scan_request_rejects_non_string_input():
    with pytest.raises(PlanningError):
        plan_scan_request(None)  # type: ignore[arg-type]


def test_plan_scan_request_wraps_schema_validation_errors_as_planning_errors():
    # Port 0 is syntactically extracted but fails ScanRequest's range check.
    with pytest.raises(PlanningError):
        plan_scan_request("profile web-check port 0 target 127.0.0.1")


def test_plan_scan_request_returns_a_validated_scan_request_instance():
    request = plan_scan_request("profile web-check port 8080 target 127.0.0.1")
    with pytest.raises(ValidationError):
        type(request)(target="127.0.0.1", ports=[8080], profile="web-check", extra="nope")
