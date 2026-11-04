"""MCP v2 stdio server exposing the policy-guarded ``scan_network`` tool."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from mcp.server import MCPServer
from pydantic import ValidationError

from safe_nmap.server.pipeline import run_scan
from safe_nmap.shared.schemas import ScanRequest, ScanResponse

TOOL_NAME = "scan_network"

ScanHandler = Callable[[ScanRequest], Awaitable[ScanResponse]]


class ScanServiceUnavailableError(RuntimeError):
    """Raised when the MCP interface is started before the scan core is wired in."""


def create_server(scan_handler: ScanHandler | None = None) -> MCPServer:
    """Create the MCP server, optionally injecting the server-side scan workflow.

    The handler is responsible for policy authorization and for ensuring that
    rejected requests never reach Nmap. Keeping it injectable lets the MCP
    interface be developed independently from the policy and scanner modules.
    """
    server = MCPServer(
        name="safe-nmap-assistant",
        instructions=(
            "Accept structured scan requests and return the server's policy decision. "
            "The server, not the caller, authorizes every scan."
        ),
    )

    @server.tool(name=TOOL_NAME)
    async def scan_network(target: str, ports: list[int], profile: str) -> ScanResponse:
        """Request an Nmap scan; the server independently checks its policy first."""
        try:
            request = ScanRequest.model_validate(
                {"target": target, "ports": ports, "profile": profile}
            )
        except ValidationError as exc:
            # The SDK normally validates the generated input schema too. Keep
            # this explicit validation at the trust boundary regardless.
            raise ValueError("Invalid scan request.") from exc

        if scan_handler is None:
            raise ScanServiceUnavailableError(
                "The MCP tool is available, but the policy and scan workflow is not wired in yet."
            )

        response = await scan_handler(request)
        return ScanResponse.model_validate(response)

    return server


async def _run() -> None:
    """Run the server over stdio for the local MCP client."""
    server = create_server(scan_handler=run_scan)
    await server.run(transport="stdio")


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
