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
- [x] Review and integrate the command builder, scanner, parser, and server pipeline with the completed policy end-to-end against the real lab (M1/M4). Fixed a real bug found along the way: `mcp_server.py` wrapped the synchronous, self-managed `MCPServer.run(transport="stdio")` (which calls `anyio.run()` internally) in `asyncio.run()`, raising `RuntimeError: Already running asyncio in this thread` on every launch; `main()` now calls `server.run(transport="stdio")` directly.
- [x] Implement deterministic report generation (`server/reporter.py`: `render_report(response, profile=None)`; includes a limitations footer and never claims a vulnerability or that a target is secure).
- [x] Implement JSONL audit logging (`server/audit.py`: `write_event`/`log_outcome_event`, path from `SAFE_NMAP_AUDIT_LOG` or `results/audit.jsonl`). `server/pipeline.py` now writes a fail-closed "decision" event before Nmap starts and a best-effort "outcome" event after; `agent/cli.py` writes a best-effort "planner" event carrying the same `client_request_id` for correlation. Verified with unit tests and one manual end-to-end run (real pipeline, missing-nmap path).
- [x] Finalize the approved and decoy Docker Compose lab and its setup/ground-truth documentation (`lab/README.md`, verified 2026-11-08).
- [x] Complete any remaining non-test setup or implementation documentation (`README.md` section 21: setup/usage instructions, verified by cloning the repo into a separate directory and following them exactly; `docs/architecture.md` status note).

## C — Testing and Evaluation

- [x] Create unit, integration, end-to-end, and fixture directories.
- [x] Add a starter evaluation case file and evaluation script placeholders.
- [x] Implement unit tests for schemas, policy guard/config, command builder, executor (scanner), XML parser, reporter, audit, and the server pipeline's audit hooks (`tests/unit/`). **Run with `uv run pytest` or, if `uv` is unavailable, `source .venv/bin/activate && pytest -q`: 111 passed, 5 skipped without the lab running (84 + 27 more with the lab up).** Added `test_planner.py` (target/port preservation, ambiguity, port-range/negative-port/duplicate-clause rejection, profile inference and ambiguity) and `test_llm_planner.py` (mocked OpenAI client: unavailable-without-model/key, successful parse, missing-field clarification, OpenAI-error vs validation-error classification, empty input short-circuits before calling the client). Planner/LLM-planner unit tests are now implemented.
- [x] Implement integration tests for MCP, policy, scanner, parser, and the controlled lab. Added `tests/integration/test_mcp_client_server.py` (real `MCPClient` ↔ a real MCP server subprocess over stdio, using a stub scan handler so no policy file/Nmap/lab is needed: tool discovery, structured round trip, and error propagation) and `tests/integration/test_policy_to_executor.py` (policy guard → executor with a mocked `scanner.run_nmap`: asserts the mock is never called for unauthorized target/profile/port/duplicate-port denials or when the concurrency limit is exceeded). `tests/integration/test_lab_scanner.py` (from M1) covers scanner→parser against the real lab.
- [x] Implement end-to-end tests from natural-language request through the policy guard (`tests/end_to_end/test_cli_end_to_end.py`, `@pytest.mark.lab`: real CLI -> MCP client -> MCP server subprocess -> policy guard -> real Nmap against the lab; approved port succeeds, decoy port is rejected with `nmap_started=false`).
- [x] Verify that denied requests never invoke the executor (`test_policy_guard.py` asserts rejection before a `ValidatedPlan` is created; `test_policy_to_executor.py` asserts a mocked `scanner.run_nmap` is never called across every denial reason, including the concurrency limit; confirmed again end-to-end via the real MCP stack in `test_cli_end_to_end.py`).
- [x] Start and validate the approved and decoy Docker testbed. nmap 7.993 installed via Homebrew; `docker compose -f lab/docker-compose.yml up -d` brings up `approved-nginx` (127.0.0.1:8080) and `decoy-nginx` (127.0.0.1:8081), both confirmed with `curl` (HTTP 200) and with real `nmap -n -sT -T3 [-sV] -oX -` scans (both open, `http`/`nginx` 1.30.6 detected). Ground truth recorded in `lab/README.md`; XML captures saved under `tests/fixtures/`. Added `tests/integration/test_lab_scanner.py` (marked `@pytest.mark.lab`, auto-skipped when nmap/the lab are unavailable) exercising the real `scanner.run_nmap` + `parser.parse_nmap_xml` path and confirming `config/policy.example.yaml` never authorizes port 8081. 75 tests pass locally with the lab running.
- [x] Verify fresh setup from the documented instructions on a clean machine. Cloned the repo (`git clone --branch ... /tmp/clean-checkout`) into a separate directory with no reused `.venv`/local state and followed README section 21 exactly: fresh venv + `pip install -e ".[dev,eval]"`, copy `config/policy.yaml`, `docker compose up`, `pytest -q` (113 passed, 5 skipped), `safe-nmap` CLI (plain and `--json`), and all three `evaluation/*.py` scripts — all worked without any undocumented manual fix. Not verified on Windows or Linux, or on a different physical machine.
- [x] Finalize individual evaluation cases and expected decisions/execution behavior (`evaluation/cases.json`: 22 cases across all 11 README §14 categories, with `literal_target`/`literal_ports` for cases that can also be scripted directly for C1).
- [x] Implement the C1–C4 comparison and latency workflows (`evaluation/run_comparison.py`: C1 real scripted Nmap with a hard loopback-only safety check, C4 the real in-process pipeline; C2/C3 explicitly recorded as `not_run`, requires an LLM planner/API key not available here — `evaluation/run_latency.py`: ≥10 matched runs of one authorized plan through the real pipeline — `evaluation/analyze_results.py`: summary tables + optional matplotlib figure from the raw CSVs).
- [x] Run tests and record results: `pytest -q` → 118 passed, 5 skipped without the lab (123 with the lab up). `ruff check .` is clean for all files touched in M2–M6; 4 pre-existing lint findings remain in untouched `agent/` files.
- [x] Export reproducible raw results, summaries, and figures. Ran for real on 2026-11-08 (Docker lab up): C4 block_rate=0.80, bypass_rate=0.00 over 20 unauthorized cases (true bypass defined as Nmap running against a destination/port outside 127.0.0.1:8080); C1 has no guard concept. Latency (n=10, deterministic planner): planner ~0.06ms, policy ~0.11ms, scan ~20–27ms, total ~20–27ms. Full writeup and methodology in `docs/evaluation.md`. **Building this evaluation found and fixed two real planner bugs** (CIDR and IPv4-mapped-IPv6 targets were silently truncated to their embedded bare IPv4 address instead of being preserved verbatim for the policy guard to reject — under this lab's policy the CIDR case was an actual bypass, not just cosmetic); see `docs/evaluation.md` §Findings and `tests/unit/test_planner.py`.

## Current Integration Blocker

None outstanding for V1 as scoped. M1 (lab), M2 (policy guard), M3 (reporter/audit), M4 (real end-to-end CLI run, including a genuine `mcp_server.py` crash-on-launch bug fixed along the way), M5 (unit + integration + end-to-end tests, 123 passed with the lab up / 118 without), M6 (evaluation harness + cases.json + real C1/C4/latency results, with two real planner bugs — CIDR and IPv4-mapped-IPv6 target truncation — found and fixed), and M7 (setup docs verified via a separate clean clone) are all done. `--planner llm` was exercised only enough to confirm it fails gracefully without an API key; it was never run against a real model, so no LLM-planner result (including C2/C3) should be presented as evidence of anything. No secrets or generated artifacts are committed (`config/policy.yaml`, `.env`, `results/*.csv` are all git-ignored and absent from a fresh clone).
