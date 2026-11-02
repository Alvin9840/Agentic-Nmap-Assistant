"""Coordinate request planning and the MCP scan call."""

from collections.abc import Callable

from safe_nmap.agent.mcp_client import MCPClient
from safe_nmap.shared.schemas import ScanRequest, ScanResponse


Planner = Callable[[str], ScanRequest]


async def run_scan(
    user_text: str,
    planner: Planner,
    mcp_client: MCPClient,
) -> ScanResponse:
    """Plan one scan request and return the server's structured response."""
    request = planner(user_text)

    async with mcp_client as client:
        return await client.scan_network(request)