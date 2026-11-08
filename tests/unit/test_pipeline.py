"""Unit tests for the server pipeline's audit hooks and response assembly."""

import json
import textwrap

import pytest

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
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(log_path))
    return log_path


def _read_events(log_path):
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


async def test_run_scan_writes_decision_and_outcome_events_on_success(
    monkeypatch, configured_policy, audit_log
):
    async def fake_run_nmap(arguments, timeout_seconds):
        return scanner.ScanExecution(
            nmap_started=True,
            xml_output="<nmaprun></nmaprun>",
            error_message=None,
            scan_ms=1.0,
        )

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)

    request = ScanRequest(target="127.0.0.1", ports=[8080], profile="web-check")
    response = await pipeline.run_scan(request)

    assert response.status == "success"
    events = _read_events(audit_log)
    assert [event["event"] for event in events] == ["decision", "outcome"]
    assert events[0]["policy_decision"] == "allowed"
    assert events[0]["validated_destination"] == "127.0.0.1"
    assert events[1]["final_status"] == "success"
    assert events[1]["request_id"] == events[0]["request_id"]


async def test_run_scan_writes_only_decision_event_on_rejection(configured_policy, audit_log):
    request = ScanRequest(target="10.0.0.1", ports=[8080], profile="web-check")
    response = await pipeline.run_scan(request)

    assert response.status == "rejected"
    events = _read_events(audit_log)
    assert [event["event"] for event in events] == ["decision"]
    assert events[0]["policy_decision"] == "rejected"
    assert events[0]["validated_destination"] is None


async def test_run_scan_echoes_client_request_id_into_decision_event(
    configured_policy, audit_log
):
    request = ScanRequest(
        target="10.0.0.1", ports=[8080], profile="web-check", client_request_id="abc-123"
    )
    await pipeline.run_scan(request)

    events = _read_events(audit_log)
    assert events[0]["client_request_id"] == "abc-123"
