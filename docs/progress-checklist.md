# V1 Project Progress Checklist

Last reviewed: 2026-11-08

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

## A — Completed Implementation

These are the components implemented by A so far. C still needs to verify them through tests and integration runs.

- [x] Implement a deterministic fallback planner for the supported English request patterns.
- [x] Preserve explicitly extracted targets, ports, and profiles in the shared `ScanRequest` model.
- [x] Return planning errors for missing or ambiguous values instead of silently guessing.
- [x] Implement an OpenAI-backed planner using structured output and the shared request fields.
- [x] Add planner instructions that treat user text as untrusted input and prohibit command generation.
- [x] Distinguish LLM service/configuration unavailability from request-planning errors.
- [x] Implement the MCP SDK v2 client using stdio and a fixed `scan_network` tool name.
- [x] Validate structured MCP output as `ScanResponse`.
- [x] Implement the agent pipeline that passes text through a planner and then calls the MCP client.
- [x] Implement CLI planner modes: `auto`, `llm`, and `deterministic`.
- [x] In `auto` mode, fall back only when the LLM planner is unavailable; planning ambiguity remains an error.
- [x] Add the MCP v2 stdio server entry point and expose `scan_network` with shared request validation.
- [x] Implement the initial fixed Nmap command builder, scanner executor, and XML parser (not yet test-verified).
- [x] Implement the server pipeline and wire the MCP tool to it (not yet test-verified).

## B — Remaining Non-Test Implementation

- [x] Add an example policy configuration file.
- [x] Implement policy configuration loading and validation (`server/policy_config.py`; fails closed on a missing/invalid file; path overridable via `SAFE_NMAP_POLICY`). Not yet test-verified with pytest.
- [x] Implement the server-side policy guard and create `ValidatedPlan` only after authorization (`server/policy_guard.py`: canonical-IPv4 syntax check, target/profile/port/size/duplicate checks in order, fail-closed on any unexpected error). Not yet test-verified with pytest.
- [x] Ensure denied requests stop before the scanner is called (policy rejection and concurrency-limit rejection both return before `command_builder`/`scanner` run). Verified manually (not with pytest): see session notes.
- [x] Add the `-T3` flag to the command builder and resolve the Nmap executable path once via `shutil.which`, returning `nmap_started=false` when it is missing.
- [x] Add a non-blocking concurrency limiter in `server/pipeline.py` driven by `limits.max_concurrent_scans`; verified manually that a second concurrent request is rejected with reason "too many concurrent scans".
- [x] Add optional `client_request_id` / `experiment_condition` metadata fields to `ScanRequest` and the `scan_network` MCP tool (logging/experiment labels only; never used for authorization).
- [ ] Review and integrate the command builder, scanner, parser, and server pipeline with the completed policy end-to-end against the real lab (M1/M4).
- [x] Implement deterministic report generation (`server/reporter.py`: `render_report(response, profile=None)`; includes a limitations footer and never claims a vulnerability or that a target is secure).
- [x] Implement JSONL audit logging (`server/audit.py`: `write_event`/`log_outcome_event`, path from `SAFE_NMAP_AUDIT_LOG` or `results/audit.jsonl`). `server/pipeline.py` now writes a fail-closed "decision" event before Nmap starts and a best-effort "outcome" event after; `agent/cli.py` writes a best-effort "planner" event carrying the same `client_request_id` for correlation. Verified with unit tests and one manual end-to-end run (real pipeline, missing-nmap path).
- [x] Finalize the approved and decoy Docker Compose lab and its setup/ground-truth documentation (`lab/README.md`, verified 2026-11-08).
- [ ] Complete any remaining non-test setup or implementation documentation.

## C — Testing and Evaluation

- [x] Create unit, integration, end-to-end, and fixture directories.
- [x] Add a starter evaluation case file and evaluation script placeholders.
- [x] Implement unit tests for schemas, policy guard/config, command builder, executor (scanner), XML parser, reporter, audit, and the server pipeline's audit hooks (`tests/unit/`). **Run with `uv run pytest` or, if `uv` is unavailable, `source .venv/bin/activate && pytest -q`: 72 passed (75 with the lab running; 3 are `@pytest.mark.lab` integration tests).** Planner/LLM-planner unit tests are still missing.
- [ ] Implement integration tests for MCP, policy, scanner, parser, and the controlled lab.
- [ ] Implement end-to-end tests from natural-language request through the policy guard.
- [x] Verify that denied requests never invoke the executor (covered indirectly: `test_policy_guard.py` asserts rejection before a `ValidatedPlan`/scanner call can occur; no direct mock-based pipeline test yet).
- [x] Start and validate the approved and decoy Docker testbed. nmap 7.993 installed via Homebrew; `docker compose -f lab/docker-compose.yml up -d` brings up `approved-nginx` (127.0.0.1:8080) and `decoy-nginx` (127.0.0.1:8081), both confirmed with `curl` (HTTP 200) and with real `nmap -n -sT -T3 [-sV] -oX -` scans (both open, `http`/`nginx` 1.30.6 detected). Ground truth recorded in `lab/README.md`; XML captures saved under `tests/fixtures/`. Added `tests/integration/test_lab_scanner.py` (marked `@pytest.mark.lab`, auto-skipped when nmap/the lab are unavailable) exercising the real `scanner.run_nmap` + `parser.parse_nmap_xml` path and confirming `config/policy.example.yaml` never authorizes port 8081. 75 tests pass locally with the lab running.
- [ ] Verify fresh setup from the documented instructions on a clean machine.
- [ ] Finalize individual evaluation cases and expected decisions/execution behavior.
- [ ] Implement the C1–C4 comparison and latency workflows.
- [x] Run tests and record results: `pytest -q` → 72 passed, 0 failed (2026-11-08, local `.venv`, no `uv` installed on this machine). `ruff check .` is clean for all files touched in M2/M3/M5; 4 pre-existing lint findings remain in untouched `agent/` files.
- [ ] Export reproducible raw results, summaries, and figures.

## Current Integration Blocker

The CLI can launch `safe_nmap.server.mcp_server`, discover `scan_network`, and route calls into the server pipeline. The policy guard now implements real authorization rules (M2) instead of always raising `NotImplementedError`, the reporter and audit log are implemented (M3), and the local lab (M1) is running with nmap installed, both verified by a real scan against the approved service and by `tests/integration/test_lab_scanner.py`. 75 tests pass locally with the lab up. Remaining blockers before a true end-to-end run (M4): `config/policy.yaml` must be created locally from `config/policy.example.yaml` (git-ignored, required at runtime) before launching the MCP server, and the CLI's full stdio round trip (agent -> MCP client -> MCP server -> pipeline) has not yet been exercised against the live lab. Planner/LLM-planner and MCP client/server unit, integration, and end-to-end tests are still missing.

