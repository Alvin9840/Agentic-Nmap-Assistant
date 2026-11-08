"""Load and validate the server-controlled policy configuration.

The policy file is never trusted input: it is read from a server-side path,
never from agent or MCP arguments. A missing or invalid file must fail closed
(see ``policy_guard.authorize``, which treats ``PolicyConfigError`` as a
rejection).
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

import yaml
from pydantic import Field, StrictBool, StrictInt, StrictStr, field_validator

from safe_nmap.shared.schemas import Port, StrictModel

DEFAULT_POLICY_PATH = Path("config/policy.yaml")
POLICY_PATH_ENV_VAR = "SAFE_NMAP_POLICY"


class PolicyConfigError(ValueError):
    """Raised when the policy file is missing, unreadable, or invalid."""


class Limits(StrictModel):
    timeout_seconds: StrictInt = Field(gt=0)
    max_ports_per_request: StrictInt = Field(gt=0)
    max_concurrent_scans: StrictInt = Field(gt=0)


class Profile(StrictModel):
    allowed_ports: list[Port] = Field(min_length=1)
    service_detection: StrictBool


class Policy(StrictModel):
    allowed_targets: list[StrictStr]
    profiles: dict[StrictStr, Profile]
    limits: Limits

    @field_validator("allowed_targets")
    @classmethod
    def _validate_allowed_targets(cls, value: list[str]) -> list[str]:
        for target in value:
            if not _is_canonical_ipv4(target):
                raise ValueError(
                    f"allowed_targets entry {target!r} is not a canonical IPv4 address."
                )
        return value


def _is_canonical_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return str(address) == value


def _resolve_policy_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    env_path = os.environ.get(POLICY_PATH_ENV_VAR)
    if env_path:
        return Path(env_path)
    return DEFAULT_POLICY_PATH


def load_policy(path: str | Path | None = None) -> Policy:
    """Load and validate the policy file, raising ``PolicyConfigError`` on any problem."""
    policy_path = _resolve_policy_path(path)
    try:
        raw_text = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyConfigError(f"Could not read policy file {policy_path}: {exc}") from exc

    try:
        raw_data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"Policy file {policy_path} is not valid YAML: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise PolicyConfigError(
            f"Policy file {policy_path} must contain a mapping at the top level."
        )

    try:
        return Policy.model_validate(raw_data)
    except Exception as exc:  # any validation failure must fail closed
        raise PolicyConfigError(f"Policy file {policy_path} failed validation: {exc}") from exc


_cached_policy: Policy | None = None
_cached_policy_path: Path | None = None


def get_policy(path: str | Path | None = None) -> Policy:
    """Return the cached policy for ``path``, loading it on first use.

    The cache key is the resolved path, so tests that point ``SAFE_NMAP_POLICY``
    at a fixture file still get a correctly loaded policy without restarting
    the process.
    """
    global _cached_policy, _cached_policy_path
    resolved_path = _resolve_policy_path(path)
    if _cached_policy is None or _cached_policy_path != resolved_path:
        _cached_policy = load_policy(resolved_path)
        _cached_policy_path = resolved_path
    return _cached_policy


def reset_policy_cache() -> None:
    """Clear the cached policy; used by tests that inject a fresh policy file."""
    global _cached_policy, _cached_policy_path
    _cached_policy = None
    _cached_policy_path = None
