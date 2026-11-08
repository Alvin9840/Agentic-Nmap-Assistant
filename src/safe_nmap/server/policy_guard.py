"""Independent server-side authorization boundary.

Checks run in a fixed order and short-circuit on the first failure: target
syntax, target authorization, profile, port authorization, request size, and
duplicate ports. Any unexpected error is also treated as a rejection, so
"cannot determine" always means "deny", never "allow". Only a successfully
authorized request produces a ``ValidatedPlan``, and the plan's execution
options (timeout, service detection) come from policy, never from the request.
"""

from __future__ import annotations

import ipaddress

from safe_nmap.server.policy_config import Policy, PolicyConfigError, get_policy
from safe_nmap.shared.schemas import ScanRequest, ValidatedPlan


class PolicyRejectedError(ValueError):
    """Raised when a scan request is rejected by policy."""


def authorize(request: ScanRequest, policy: Policy | None = None) -> ValidatedPlan:
    """Return a server-created validated plan or raise ``PolicyRejectedError``.

    ``policy`` can be injected directly (for tests); otherwise the cached,
    file-backed policy is loaded.
    """
    try:
        return _authorize(request, policy)
    except PolicyRejectedError:
        raise
    except Exception as exc:  # fail closed on any unexpected error
        raise PolicyRejectedError(f"Could not authorize the request: {exc}") from exc


def _authorize(request: ScanRequest, policy: Policy | None) -> ValidatedPlan:
    try:
        active_policy = policy if policy is not None else get_policy()
    except PolicyConfigError as exc:
        raise PolicyRejectedError(f"Policy configuration is unavailable: {exc}") from exc

    resolved_ip = _validate_target_syntax(request.target)

    if resolved_ip not in active_policy.allowed_targets:
        raise PolicyRejectedError(f"Target {request.target!r} is not an authorized target.")

    profile = active_policy.profiles.get(request.profile)
    if profile is None:
        raise PolicyRejectedError(f"Profile {request.profile!r} is not a known profile.")

    allowed_ports = set(profile.allowed_ports)
    if not set(request.ports).issubset(allowed_ports):
        raise PolicyRejectedError(
            f"Requested ports are not all authorized for profile {request.profile!r}."
        )

    if len(request.ports) > active_policy.limits.max_ports_per_request:
        raise PolicyRejectedError(
            f"Too many ports requested; the limit is {active_policy.limits.max_ports_per_request}."
        )

    if len(set(request.ports)) != len(request.ports):
        raise PolicyRejectedError("Duplicate ports are not allowed in one request.")

    return ValidatedPlan(
        original_target=request.target,
        resolved_ip=resolved_ip,
        ports=request.ports,
        profile=request.profile,
        timeout_seconds=active_policy.limits.timeout_seconds,
        service_detection=profile.service_detection,
    )


def _validate_target_syntax(target: str) -> str:
    """Accept only a canonical dotted-quad IPv4 address; reject everything else.

    Hostnames, CIDR, IPv6, IPv4-mapped IPv6, and non-canonical numeric forms
    (decimal/hex integers, leading zeros, short forms) are out of scope for V1
    and are rejected explicitly rather than normalized.
    """
    try:
        address = ipaddress.IPv4Address(target)
    except ValueError as exc:
        raise PolicyRejectedError(
            f"Target {target!r} is not a supported IPv4 address; hostnames, CIDR, "
            "and IPv6 are unsupported in V1."
        ) from exc

    if str(address) != target:
        raise PolicyRejectedError(
            f"Target {target!r} must be written as a canonical IPv4 address, e.g. {address}."
        )

    return str(address)
