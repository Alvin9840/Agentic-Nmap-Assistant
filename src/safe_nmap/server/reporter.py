"""Deterministic human-readable report generation.

Never asserts that an open port is a vulnerability or that a clean scan
proves a target is secure; findings are presented as observed, not judged.
"""

from __future__ import annotations

from safe_nmap.shared.schemas import ScanResponse

_LIMITATIONS = (
    "Limitations: this reflects one Nmap scan only. An open port is not a "
    "vulnerability, a clean scan is not proof the target is secure, and a "
    "detected service name/version is an unverified guess."
)


def render_report(response: ScanResponse, profile: str | None = None) -> str:
    """Render one deterministic report. ``profile`` is the requested scan profile,
    which is not part of ``ScanResponse`` and must be supplied by the caller."""
    lines = [
        f"Request ID: {response.request_id}",
        f"Requested target: {response.target}",
    ]
    if response.resolved_ip is not None:
        lines.append(f"Scanned target: {response.resolved_ip}")
    if profile is not None:
        lines.append(f"Scan profile: {profile}")

    lines.append(f"Status: {response.status}")
    lines.append(f"Allowed: {'yes' if response.allowed else 'no'}")
    lines.append(f"Nmap started: {'yes' if response.nmap_started else 'no'}")

    if response.reason:
        lines.append(f"Reason: {response.reason}")

    if response.findings is None:
        lines.append("Findings: unavailable; no valid scan result was returned.")
    elif not response.findings:
        lines.append("Findings: none observed.")
    else:
        lines.append("Findings:")
        for finding in response.findings:
            service = finding.service or "unknown service"
            details = " ".join(value for value in (finding.product, finding.version) if value)
            if details:
                service = f"{service} ({details})"
            lines.append(f"  {finding.port}/{finding.protocol}: {finding.state}; {service}")

    timing_parts = [
        f"{label}={value:.1f}ms"
        for label, value in (
            ("policy", response.policy_ms),
            ("scan", response.scan_ms),
            ("total", response.server_total_ms),
        )
        if value is not None
    ]
    if timing_parts:
        lines.append("Timing: " + ", ".join(timing_parts))

    lines.append("")
    lines.append(_LIMITATIONS)
    return "\n".join(lines)
