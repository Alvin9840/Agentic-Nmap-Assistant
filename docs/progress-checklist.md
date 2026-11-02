# V1 Project Progress Checklist

Last reviewed: 2026-11-02

## Status Legend

- `[x] Implemented`: code or project files exist. This does not mean the item has passed tests or end-to-end validation.
- `[ ] Not implemented or not verified`: work remains before the item can be considered complete.

## Shared Foundation

- [x] Create the V1 repository structure for the agent, server, lab, tests, evaluation, and documentation.
- [x] Define shared Pydantic models: `ScanRequest`, `ValidatedPlan`, `Finding`, and `ScanResponse`.
- [x] Add strict request fields, port range validation, and supported response status values.
- [x] Set up `uv`, the project virtual environment, and `uv.lock`.
- [x] Select MCP Python SDK v2 and lock the resolved SDK version in `uv.lock`.
- [x] Add `.env.example` and ignore local credentials, local policy, virtual environments, and generated results.
- [ ] Verify fresh setup from the documented instructions on a clean machine.

## A — Agent and MCP Client

- [x] Implement a deterministic fallback planner for the supported English request patterns.
- [x] Preserve explicitly extracted targets, ports, and profiles in the shared `ScanRequest` model.
- [x] Return planning errors for missing or ambiguous values instead of silently guessing.
- [x] Implement an OpenAI-backed planner using structured output and the shared request fields.
- [x] Add planner instructions that treat user text as untrusted input and prohibit command generation.
- [x] Distinguish LLM service/configuration unavailability from request-planning errors.
- [x] Implement the MCP SDK v2 client using stdio and a fixed `scan_network` tool name.
- [x] Validate structured MCP output as `ScanResponse`.
- [x] Implement the pipeline that passes text through a planner and then calls the MCP client.
- [x] Implement CLI planner modes: `auto`, `llm`, and `deterministic`.
- [x] In `auto` mode, fall back only when the LLM planner is unavailable; planning ambiguity remains an error.
- [ ] Confirm the MCP server launch command with B and verify it matches the CLI's stdio parameters.
- [ ] Run the agent and client through the completed MCP server.
- [ ] Add planner/client/pipeline acceptance cases for C to implement and run.

## B — Policy and Scan Server

- [x] Add an example policy configuration file.
- [ ] Implement and validate server-controlled policy configuration loading.
- [ ] Implement the independent server-side policy guard.
- [ ] Implement the fixed Nmap command builder from validated plans.
- [ ] Implement the Nmap executor, timeout handling, and process-start reporting.
- [ ] Implement Nmap XML parsing and structured findings.
- [ ] Implement deterministic report generation.
- [ ] Implement JSONL audit logging.
- [ ] Implement the MCP v2 server and its `scan_network` tool.
- [ ] Add the server module entry point expected by the CLI.
- [ ] Ensure denied requests never invoke the executor.

## C — Testing and Evaluation

- [x] Create unit, integration, end-to-end, and fixture directories.
- [x] Add a starter evaluation case file and evaluation script placeholders.
- [ ] Implement unit tests for schemas, planners, policy guard, command builder, executor, parser, and error classification.
- [ ] Implement integration tests for MCP, policy, scanner, parser, and the controlled lab.
- [ ] Implement end-to-end tests from natural-language request through the policy guard.
- [ ] Build and validate the approved and decoy Docker testbed.
- [ ] Finalize individual evaluation cases and expected decisions/execution behavior.
- [ ] Implement the C1–C4 comparison and latency workflows.
- [ ] Run tests and record results; no tests have been run for this checklist.
- [ ] Export reproducible raw results, summaries, and figures.

## Current Integration Blocker

The CLI launches `safe_nmap.server.mcp_server` over stdio, but the server module is still a placeholder. The CLI cannot complete a scan until B implements the MCP server entry point and the `scan_network` tool. The current planner, client, and CLI code has not yet been verified by tests or an end-to-end run.
