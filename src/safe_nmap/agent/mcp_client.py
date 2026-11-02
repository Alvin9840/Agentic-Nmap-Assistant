"""MCP SDK v2 client for the policy-guarded scan_network tool."""

from __future__ import annotations

from contextlib import AsyncExitStack
from types import TracebackType

import mcp.types as mcp_types
from mcp import Client, StdioServerParameters
from pydantic import ValidationError

from safe_nmap.shared.schemas import ScanRequest, ScanResponse


TOOL_NAME = "scan_network"


class MCPClientError(RuntimeError):
    """Raised when the MCP server returns an error or invalid response."""


class MCPClient:
    """Manage one SDK v2 stdio connection and expose the typed scan operation."""

    def __init__(self, server_parameters: StdioServerParameters) -> None:
        self._server_parameters = server_parameters
        self._exit_stack: AsyncExitStack | None = None
        self._client: Client | None = None

    async def __aenter__(self) -> MCPClient:
        if self._client is not None:
            raise MCPClientError("This MCP client is already connected.")

        exit_stack = AsyncExitStack()
        await exit_stack.__aenter__()

        try:
            client = await exit_stack.enter_async_context(Client(self._server_parameters))
            tools = await client.list_tools()
            if not any(tool.name == TOOL_NAME for tool in tools.tools):
                raise MCPClientError(f"The MCP server does not expose {TOOL_NAME!r}.")
        except BaseException:
            await exit_stack.aclose()
            raise

        self._exit_stack = exit_stack
        self._client = client
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        exit_stack = self._exit_stack
        self._exit_stack = None
        self._client = None
        if exit_stack is None:
            return None
        return await exit_stack.__aexit__(exc_type, exc, traceback)

    async def scan_network(self, request: ScanRequest) -> ScanResponse:
        """Call the fixed scan tool and validate its structured response."""
        if self._client is None:
            raise MCPClientError("Connect the MCP client with 'async with' before scanning.")

        result = await self._client.call_tool(
            TOOL_NAME,
            arguments=request.model_dump(mode="json"),
        )

        if result.is_error:
            details = " ".join(
                block.text
                for block in result.content
                if isinstance(block, mcp_types.TextContent)
            )
            raise MCPClientError(details or "The MCP server reported a tool error.")

        if result.structured_content is None:
            raise MCPClientError("The MCP server returned no structured scan response.")

        try:
            return ScanResponse.model_validate(result.structured_content)
        except ValidationError as exc:
            raise MCPClientError("The MCP server returned an invalid ScanResponse.") from exc
