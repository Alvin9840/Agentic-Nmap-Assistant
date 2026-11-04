"""Independent server-side authorization boundary.

The project policy and authorization rules are owned by the policy workstream.
Until those rules are implemented, this module fails closed.
"""

from safe_nmap.shared.schemas import ScanRequest, ValidatedPlan


class PolicyRejectedError(ValueError):
    """Raised when a scan request is rejected by policy."""


def authorize(request: ScanRequest) -> ValidatedPlan:
    """Return a server-created validated plan or reject the request.

    Replace the placeholder with policy loading, target/port/profile checks,
    and construction of the canonical plan. Do not return a plan before those
    checks have completed.
    """
    raise NotImplementedError("Policy rules are not implemented; scan authorization is disabled.")
