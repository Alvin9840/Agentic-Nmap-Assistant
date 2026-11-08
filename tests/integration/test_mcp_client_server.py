"""Integration test: MCPClient <-> a real MCP server process over stdio.

Uses a stub scan handler (``_stub_mcp_server.py``) so this exercises the real
protocol layer (tool discovery, structured round trip, error propagation)
without needing a policy file, Nmap, or the Docker lab.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from safe_nmap.agent.mcp_client import MCPClient, MCPClientError
from safe_nmap.shared.schemas import ScanRequest

_STUB_SERVER_SCRIPT = Path(__file__).parent / "_stub_mcp_server.py"


def _stub_server_parameters() -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=[str(_STUB_SERVER_SCRIPT)])


async def test_client_discovers_tool_and_round_trips_structured_response():
    request = ScanRequest(target="203.0.113.5", ports=[8080], profile="web-check")
    async with MCPClient(_stub_server_parameters()) as client:
        response = await client.scan_network(request)

    assert response.status == "success"
    assert response.allowed is True
    assert response.target == "203.0.113.5"


async def test_client_raises_mcp_client_error_on_handler_failure():
    request = ScanRequest(target="198.51.100.9", ports=[8080], profile="web-check")
    async with MCPClient(_stub_server_parameters()) as client:
        with pytest.raises(MCPClientError):
            await client.scan_network(request)
