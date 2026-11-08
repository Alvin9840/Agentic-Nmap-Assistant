"""Standalone stub MCP server used only by integration tests.

Exercises the real ``create_server`` wiring and real stdio transport without
needing a policy file, Nmap, or the Docker lab: the handler returns a canned
success response for one fixed non-routable test address and raises for
anything else, so tests can also exercise client-side error handling.
"""

from __future__ import annotations

from safe_nmap.server.mcp_server import create_server
from safe_nmap.shared.schemas import ScanRequest, ScanResponse

# TEST-NET-3 (RFC 5737): reserved for documentation/testing, never a real scan target.
STUB_SUCCESS_TARGET = "203.0.113.5"


async def _stub_scan_handler(request: ScanRequest) -> ScanResponse:
    if request.target == STUB_SUCCESS_TARGET:
        return ScanResponse(
            request_id="stub-request-id",
            status="success",
            allowed=True,
            nmap_started=True,
            target=request.target,
            resolved_ip=request.target,
            findings=[],
        )
    raise ValueError(f"stub handler rejects unknown target {request.target!r}")


def main() -> None:
    server = create_server(scan_handler=_stub_scan_handler)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
