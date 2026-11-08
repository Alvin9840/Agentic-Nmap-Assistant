"""Unit tests for policy file loading and validation."""

import pytest

from safe_nmap.server.policy_config import Policy, PolicyConfigError, load_policy

VALID_POLICY_YAML = """
allowed_targets:
  - "127.0.0.1"
profiles:
  web-check:
    allowed_ports: [8080]
    service_detection: false
limits:
  timeout_seconds: 60
  max_ports_per_request: 4
  max_concurrent_scans: 1
"""


def test_load_policy_parses_valid_file(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_POLICY_YAML)

    policy = load_policy(policy_file)
    assert isinstance(policy, Policy)
    assert policy.allowed_targets == ["127.0.0.1"]
    assert policy.limits.max_concurrent_scans == 1


def test_load_policy_missing_file_fails_closed(tmp_path):
    with pytest.raises(PolicyConfigError):
        load_policy(tmp_path / "does-not-exist.yaml")


def test_load_policy_invalid_yaml_fails_closed(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("allowed_targets: [unterminated")
    with pytest.raises(PolicyConfigError):
        load_policy(policy_file)


def test_load_policy_rejects_non_canonical_target(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_POLICY_YAML.replace("127.0.0.1", "127.1"))
    with pytest.raises(PolicyConfigError):
        load_policy(policy_file)


def test_load_policy_rejects_unknown_fields(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_POLICY_YAML + "\nextra_field: true\n")
    with pytest.raises(PolicyConfigError):
        load_policy(policy_file)


def test_load_policy_rejects_non_mapping_top_level(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("- just\n- a\n- list\n")
    with pytest.raises(PolicyConfigError):
        load_policy(policy_file)


def test_load_policy_rejects_zero_or_negative_limits(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_POLICY_YAML.replace("max_concurrent_scans: 1", "max_concurrent_scans: 0"))
    with pytest.raises(PolicyConfigError):
        load_policy(policy_file)
