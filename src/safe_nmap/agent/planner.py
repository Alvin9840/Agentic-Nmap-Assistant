"""Deterministic fallback parser for the shared scan request."""

from __future__ import annotations

import re

from pydantic import ValidationError

from safe_nmap.shared.schemas import ScanRequest


class PlanningError(ValueError):
    """Raised when a user request cannot be turned into one unambiguous plan."""


_IPV4_TOKEN = re.compile(
    # Exclude a preceding ':' (IPv4-mapped IPv6, e.g. "::ffff:127.0.0.1") and a
    # following '/' (CIDR, e.g. "127.0.0.1/32") so these unsupported forms are
    # not silently truncated to their embedded bare IPv4 address; the whole
    # unsupported literal must reach the caller unparsed.
    r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d|/)"
)
_TARGET_LABELS = re.compile(
    r"(?ix)(?<![a-z0-9_])(?:target|host|destination)\s*"
    # Only treat a single ':'/'=' as a "target:" separator, not the leading
    # '::' of an IPv6 literal (e.g. "target ::1" must keep both colons).
    r"(?:(?:is|at|to)\s+|(?:[:=](?!:))\s*)?"
    r"(?!on\b|in\b|for\b|with\b|port\b|ports\b)"
    # Capture '/' and ':' as part of the value too (CIDR, IPv6, IPv4-mapped
    # IPv6) so an explicitly labeled target is preserved verbatim rather than
    # silently truncated to an embedded substring; the policy guard rejects
    # unsupported syntax, the planner must not "fix" it first.
    r"(?P<value>[a-z0-9:][a-z0-9.:/-]*[a-z0-9]|[a-z0-9])",
)

_PORT_VALUES = r"\d+(?:\s*(?:,|;|\band\b)\s*\d+)*"
_NEGATIVE_PORT = re.compile(
    r"(?i)\bports?\b\s*(?:are\s+|is\s+|[:=]\s*)?-\s*\d+"
)
_PORT_RANGE = re.compile(
    r"(?i)\bports?\b\s*(?:are\s+|is\s+|[:=]\s*)?\d+\s*-\s*\d+"
)
_PORT_CLAUSES = (
    re.compile(
        rf"(?i)(?<![a-z0-9_])ports?\b\s*(?:(?:are|is)\s+|[:=]\s*)?"
        rf"(?P<values>{_PORT_VALUES})"
    ),
    re.compile(
        rf"(?i)(?P<values>{_PORT_VALUES})\s*ports?\b"
    ),
)

_PROFILE_LABEL = re.compile(
    r"(?i)(?<![a-z0-9_])profile\s*(?:is\s+|[:=]\s*)?(?P<name>[a-z][a-z0-9-]*)"
)


def _extract_target(text: str) -> str:
    candidates = [match.group(0) for match in _IPV4_TOKEN.finditer(text)]
    for match in _TARGET_LABELS.finditer(text):
        candidates.append(match.group("value"))

    # Keep each explicit target exactly as written while ignoring duplicate matches
    # (an IP may match both the IPv4 pattern and a labeled target).
    unique_candidates = list(dict.fromkeys(candidates))
    if not unique_candidates:
        raise PlanningError("Provide one explicit target, for example 127.0.0.1.")
    if len(unique_candidates) > 1:
        raise PlanningError("Multiple targets were found; provide exactly one target per request.")
    return unique_candidates[0]


def _extract_ports(text: str) -> list[int]:
    if _PORT_RANGE.search(text):
        raise PlanningError("Port ranges are not supported; list each port individually.")
    if _NEGATIVE_PORT.search(text):
        raise PlanningError("Ports must be positive integers from 1 through 65535.")

    matches = [match for pattern in _PORT_CLAUSES for match in pattern.finditer(text)]
    if not matches:
        raise PlanningError("List at least one port, for example 'ports 8080'.")
    if len(matches) > 1:
        raise PlanningError("Provide one port list per request to avoid ambiguity.")

    match = matches[0]
    if re.match(r"\s+\d", text[match.end() :]):
        raise PlanningError("Separate ports with commas, semicolons, or the word 'and'.")

    return [int(value) for value in re.findall(r"\d+", match.group("values"))]


def _extract_profile(text: str) -> str:
    explicit_profiles: list[str] = []
    for match in _PROFILE_LABEL.finditer(text):
        value = match.group("name")
        # Preserve an explicitly named profile. The server, not the planner,
        # decides whether that profile is authorized and recognized.
        explicit_profiles.append(value)

    if explicit_profiles:
        if len({value.lower() for value in explicit_profiles}) > 1:
            raise PlanningError("Multiple different profiles were specified.")
        return explicit_profiles[0]

    lowered = text.lower()
    mentions_service = any(
        phrase in lowered
        for phrase in (
            "service-check",
            "service check",
            "service detection",
        )
    )
    mentions_web = any(
        phrase in lowered for phrase in ("web-check", "web check")
    )
    if mentions_service and mentions_web:
        raise PlanningError("Both web-check and service-check were mentioned; specify one profile.")
    if mentions_service:
        return "service-check"
    if mentions_web:
        return "web-check"
    raise PlanningError(
        "Specify a profile: web-check or service-check. You can also ask for a web check "
        "or service detection."
    )


def plan_scan_request(user_text: str) -> ScanRequest:
    """Parse one explicit scan request without authorizing or rewriting it.

    The planner deliberately does not decide whether a target or profile is
    allowed. The MCP server's policy guard must make that decision independently.
    """
    if not isinstance(user_text, str) or not user_text.strip():
        raise PlanningError("Provide a scan request.")

    target = _extract_target(user_text)
    ports = _extract_ports(user_text)
    profile = _extract_profile(user_text)

    try:
        return ScanRequest(target=target, ports=ports, profile=profile)
    except ValidationError as exc:
        raise PlanningError(f"The request contains invalid fields: {exc}") from exc
