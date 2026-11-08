"""Unit tests for shared request/response schema validation."""

import pytest
from pydantic import ValidationError

from safe_nmap.shared.schemas import Finding, ScanRequest, ScanResponse


def test_scan_request_accepts_minimal_valid_fields():
    request = ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check")
    assert request.client_request_id is None
    assert request.experiment_condition is None


def test_scan_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ScanRequest(
            target="127.0.0.1", ports=[8080], profile="web-check", raw_command="nmap -A"
        )


def test_scan_request_rejects_empty_ports():
    with pytest.raises(ValidationError):
        ScanRequest(target="127.0.0.1", ports=[], profile="web-check")


@pytest.mark.parametrize("port", [0, -1, 65536, 100000])
def test_scan_request_rejects_out_of_range_ports(port):
    with pytest.raises(ValidationError):
        ScanRequest(target="127.0.0.1", ports=[port], profile="web-check")


def test_scan_request_rejects_non_integer_port_coercion():
    with pytest.raises(ValidationError):
        ScanRequest(target="127.0.0.1", ports=["8080"], profile="web-check")


def test_scan_request_accepts_valid_metadata_fields():
    request = ScanRequest(
        target="127.0.0.1",
        ports=[8080],
        profile="web-check",
        client_request_id="exp-001_run.1",
        experiment_condition="C3",
    )
    assert request.client_request_id == "exp-001_run.1"
    assert request.experiment_condition == "C3"


@pytest.mark.parametrize("value", ["has space", "semi;colon", "a" * 65, ""])
def test_scan_request_rejects_invalid_metadata_charset_or_length(value):
    with pytest.raises(ValidationError):
        ScanRequest(
            target="127.0.0.1", ports=[8080], profile="web-check", client_request_id=value
        )


def test_scan_response_rejects_unknown_status():
    with pytest.raises(ValidationError):
        ScanResponse(
            request_id="r1",
            status="unknown",
            allowed=False,
            nmap_started=False,
            target="127.0.0.1",
        )


def test_finding_allows_missing_service_details():
    finding = Finding(port=8080, protocol="tcp", state="open")
    assert finding.service is None
    assert finding.product is None
    assert finding.version is None
