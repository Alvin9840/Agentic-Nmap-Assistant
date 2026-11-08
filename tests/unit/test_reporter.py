"""Unit tests for the deterministic report template."""

from safe_nmap.server.reporter import render_report
from safe_nmap.shared.schemas import Finding, ScanResponse


def test_render_report_includes_core_fields_and_profile():
    response = ScanResponse(
        request_id="r1",
        status="success",
        allowed=True,
        nmap_started=True,
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        findings=[Finding(port=8080, protocol="tcp", state="open", service="http")],
        policy_ms=1.0,
        scan_ms=2.0,
        server_total_ms=3.0,
    )
    report = render_report(response, profile="web-check")

    assert "Request ID: r1" in report
    assert "Requested target: 127.0.0.1" in report
    assert "Scanned target: 127.0.0.1" in report
    assert "Scan profile: web-check" in report
    assert "Status: success" in report
    assert "8080/tcp: open; http" in report
    assert "Timing: policy=1.0ms, scan=2.0ms, total=3.0ms" in report


def test_render_report_includes_limitations_disclaimer():
    response = ScanResponse(
        request_id="r2",
        status="success",
        allowed=True,
        nmap_started=True,
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        findings=[],
    )
    report = render_report(response)

    assert "not proof the target is secure" in report
    assert "unverified guess" in report
    assert "not a vulnerability" in report


def test_render_report_rejected_request_shows_reason_and_no_findings_claim():
    response = ScanResponse(
        request_id="r3",
        status="rejected",
        allowed=False,
        nmap_started=False,
        reason="Target '10.0.0.1' is not an authorized target.",
        target="10.0.0.1",
    )
    report = render_report(response, profile="web-check")

    assert "Allowed: no" in report
    assert "Nmap started: no" in report
    assert "Reason: Target '10.0.0.1' is not an authorized target." in report
    assert "Findings: unavailable" in report


def test_render_report_empty_findings_list_is_distinct_from_none():
    empty = ScanResponse(
        request_id="r4",
        status="success",
        allowed=True,
        nmap_started=True,
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        findings=[],
    )
    missing = ScanResponse(
        request_id="r5",
        status="scan_failed",
        allowed=True,
        nmap_started=False,
        reason="Nmap executable was not found on PATH.",
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        findings=None,
    )
    assert "Findings: none observed." in render_report(empty)
    assert "Findings: unavailable" in render_report(missing)
