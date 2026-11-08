# Implementation Plan

Date: 2026-11-08 (revised: open questions resolved)
Basis: review of the repo against README §§6–19 and `docs/progress-checklist.md`.

Status words used below: **implemented** = code exists; **tested** = a test was run and passed; **planned** = not yet done. Nothing is tested today.

## 1. Current State (verified by reading code)

| Area | State |
|---|---|
| `shared/schemas.py` | Implemented. Strict models. `ScanResponse` uses flat `policy_ms/scan_ms/server_total_ms` (README example nests under `timing`; flat form is fine, keep it and treat it as the contract). |
| `agent/*` (planner, llm_planner, mcp_client, cli, pipeline) | Implemented, untested. |
| `server/mcp_server.py`, `pipeline.py` | Implemented, untested. Pipeline already handles reject / scan_failed / parse_error / success. |
| `server/command_builder.py`, `scanner.py`, `parser.py` | Implemented, untested. Builder emits `nmap -n -sT -oX - [-sV] -p … <ip>`. |
| `server/policy_guard.py` | **Stub**: always raises `NotImplementedError` (not `PolicyRejectedError`), so every request currently crashes the pipeline rather than being rejected. |
| `server/reporter.py`, `server/audit.py` | **Empty**. |
| `lab/docker-compose.yml` | Written, never started. |
| `tests/`, `evaluation/*.py`, `cases.json` | Empty / placeholders. |

## 2. Design Decisions (confirmed 2026-11-08)

All four open questions from the earlier draft are resolved as follows: (1) add optional `client_request_id` / `experiment_condition` to `ScanRequest`; (2) reject duplicate ports; (3) hostnames unsupported in V1, documented as a limitation; (4) add a two-container-IP Docker network for target-scope experiments, kept separate from the default loopback lab.

1. **Policy location**: `config/policy.yaml` (git-ignored), overridable via env var `SAFE_NMAP_POLICY` (server-side only; never a tool argument). Missing/invalid file → every request rejected (fail closed) with a clear reason.
2. **Target scope for V1**: canonical dotted-quad IPv4 only. Reject hostnames, CIDR, IPv6, IPv4-mapped IPv6, and non-canonical numeric forms (`2130706433`, `0x7f.1`, `127.1`, leading zeros). Parse with `ipaddress.IPv4Address` and additionally require `str(addr) == input` so alternates are rejected explicitly, not normalized. Hostnames are **out of scope for V1** and are rejected with an explicit reason; this is recorded as a limitation in the docs and report (the hostname test category expects rejection).
3. **Policy checks** (in order, short-circuit on first failure): target syntax → target in `allowed_targets` → profile known → ports ⊆ profile `allowed_ports` → `len(ports) ≤ max_ports_per_request` → duplicate ports rejected (or de-duplicated; **decided: reject**, to avoid silently altering the request; reason string "duplicate ports").
4. **Concurrency limit**: `asyncio.Semaphore(max_concurrent_scans)` in the server pipeline, acquired non-blocking; if unavailable → rejected with reason "too many concurrent scans" (fail closed).
5. **Policy exceptions**: guard raises only `PolicyRejectedError` for any failure, including unexpected exceptions (wrap in `try/except Exception` → reject). This keeps "cannot determine ⇒ deny".
6. **Command builder**: add `-T3` to match README §11 example; keep everything else. Resolve `nmap` once via `shutil.which` at startup (trusted path), fail with `scan_failed` if missing.
7. **Audit**: JSONL at `results/audit.jsonl` (path configurable by env var). The server does not know the planner mode or the original NL text. Rather than widening the MCP tool signature, the **agent writes its own planner-side event** (request text hash/ID, planner mode, proposed plan) and the **server writes the policy/execution event**; both carry the same `request_id` if the client supplies it. **Decided:** add two optional fields to `ScanRequest`: `client_request_id: StrictStr | None = None` (max 64 chars, `[A-Za-z0-9_.-]` only) and `experiment_condition: StrictStr | None = None` (one of `C2`/`C3`/`C4`/`prod`, or free label validated by the same character set). They are metadata only: the guard never uses them for authorization, and the MCP tool gains matching optional parameters. This is a schema change; update `schemas.py`, `mcp_server.py`, `mcp_client.py`, and tests together, and tell A/B/C.
8. **Audit failure semantics**: write the "decision" event *before* starting Nmap; if the write fails, reject (fail closed). Failure of the final "outcome" event is logged to stderr and does not change the response.
9. **Reporter**: pure function `render_report(response, profile) -> str`, deterministic template; used by the CLI for display. No LLM text. Includes limitations footer; never says "secure" or "vulnerable".
10. **No stdout noise** in the server process (stdio MCP): all diagnostics to stderr.
11. **Final decision on alt-target-encoding handling (confirmed 2026-11-08 by Haoyu Chang, after a conflicting design surfaced in a teammate's P2 slides):** the guard **rejects** hostnames, CIDR, IPv6, IPv4-mapped IPv6, and non-canonical numeric IPv4 forms outright; it never resolves a hostname, expands a CIDR block, or normalizes an IPv4-mapped IPv6 literal down to its embedded address. This supersedes the alternative "resolve the address, then check the resolved IP against the allowlist" design shown in the P2 slide deck (slide 9) — that alternative is **not** being implemented. Rationale: (a) this is what decision 2 above and all of M2/M5/M6's shipped code, tests, and real evaluation results already assume and exercise; (b) resolve-then-check meaningfully widens the trust surface for a V1 security project (hostname resolution adds DNS-rebinding risk that README §10 explicitly calls out as unevaluated; CIDR expansion risks iterating arbitrarily large ranges); (c) rewriting it would invalidate the existing `tests/unit/test_policy_guard.py` table and the `docs/evaluation.md` results. Any future "resolve-then-check" mode (if the team still wants one for comparison) must be a separate, explicitly-labeled profile/condition, not a change to the default V1 guard behavior.
12. **Adversarial test case numbering (confirmed 2026-11-08 by Haoyu Chang):** `evaluation/cases.json`'s `C-001`–`C-022` is the project's adversarial test case set, superseding the `T1`–`T10` set shown in the P2 slide deck (slide 8) — it covers the same intent (benign, injection, forbidden target/port/option, alt encodings, IPv6, CIDR, hostname) with more cases (22 vs. 10) and the README §14 case schema. Do not maintain both numbering schemes; any report or slide referencing `T1`–`T10` should be updated to reference the `C-00N` cases instead.

### M1 — Lab and scanner baseline
1. Install nmap; `docker compose -f lab/docker-compose.yml up -d`; confirm `curl 127.0.0.1:8080/8081`.
2. Run manual `nmap -sT -p 8080,8081 -oX - 127.0.0.1`; save the XML as `tests/fixtures/nmap_open_8080.xml` (plus hand-made fixtures: closed port, `-sV` result, empty host, malformed XML, wrong root).
3. Call `scanner.run_nmap` + `parser.parse_nmap_xml` from a Python snippet; confirm port 8080 `open`/`http`.
4. Write `lab/README.md` ground truth table (what is listening where, expected nmap output).
5. **Target-scope lab (M1b, after M2 works):** add `lab/docker-compose.targets.yml` with a user-defined bridge network (fixed subnet, e.g. `172.28.0.0/24`), `approved-nginx` at `172.28.0.10`, `decoy-nginx` at `172.28.0.11`, and a `scanner` container (nmap + the project, no published ports) at `172.28.0.2`. Provide a second policy file `config/policy.lab-network.example.yaml` allowing only `172.28.0.10`. The default loopback compose stays for port-scope experiments. Document which topology each experiment uses.

**Acceptance**: Python call returns the expected approved service.

### M2 — Policy enforcement (highest priority; unblocks everything)
1. `server/policy_config.py` (or inside `policy_guard.py`): Pydantic `Policy` model (`extra="forbid"`) with `allowed_targets`, `profiles{allowed_ports, service_detection}`, `limits{timeout_seconds, max_ports_per_request, max_concurrent_scans}`; `load_policy(path)`; validate that each `allowed_targets` entry is a canonical IPv4 and ports are 1–65535.
2. `policy_guard.authorize(request, policy=None) -> ValidatedPlan`: implements §2.3; builds `ValidatedPlan` with `resolved_ip = original_target`, `timeout_seconds` and `service_detection` taken from policy (never from the request). Accept an optional injected `Policy` so tests need no file; default path loads (and caches) the config.
3. Pipeline: catch `PolicyRejectedError` (already done); add concurrency semaphore; ensure no code path reaches `scanner.run_nmap` without a `ValidatedPlan`.
4. Add `-T3` to command builder; add executable lookup.
**Acceptance**: unit tests show unauthorized requests never call the executor (mock `scanner.run_nmap` and assert not called).

### M3 — Reporter and audit
1. `reporter.py` per §2.9.
2. `audit.py`: `write_event(dict)` using append-mode JSONL, one `json.dumps` per line, file lock or single-writer lock to avoid interleaving; fields per README §13 (request_id, timestamp UTC ISO-8601, proposed plan, validated destination, decision, reason, nmap_started, final status, timing, experiment condition, planner mode if known). Never log API keys.
3. Hook into `server/pipeline.py`: decision event before scan (fail closed on write error), outcome event after.
4. CLI: print `render_report(response)` by default, `--json` flag to print raw `ScanResponse`; agent-side planner event written with the same request ID.

**Acceptance**: each request produces exactly the expected JSONL lines; report text matches fixtures.

### M4 — MCP and agent integration (end-to-end)
1. Run the real path: `uv run safe-nmap --planner deterministic --request "..."` against the lab (approved → success; decoy port 8081 → rejected, `nmap_started=false`).
2. Fix integration issues found (stdout pollution, error mapping in `mcp_client`, tool-call retry limit).
3. Run once with `--planner llm` if an API key is available; label result with planner mode.

**Acceptance**: approved NL request completes; unauthorized NL request is rejected through the full path.

### M5 — Tests (can start in parallel with M2/M3 for already-written modules)
- **Unit** (`tests/unit/`): `test_schemas` (incl. optional metadata fields: length/charset limits, unknown fields still rejected), `test_planner` (target/port preserved, ambiguity → error), `test_llm_planner` (mock OpenAI client; unavailable vs planning error), `test_policy_guard` (table-driven: good, unknown target, alt encodings, IPv6, CIDR, hostname (explicitly rejected), forbidden port, unknown profile, too many ports, duplicates, missing/invalid policy file, extra fields), `test_command_builder` (exact argv, no extra flags, `-sV` only when set), `test_scanner` (fake process: success, nonzero exit, timeout, missing binary, cancellation), `test_parser` (fixtures from M1), `test_reporter`, `test_audit`.
- **Integration** (`tests/integration/`): MCP client↔server over stdio with a stub handler; policy→scanner with mocked executor (assert not called on denial); scanner→parser against the real lab (mark `@pytest.mark.lab`, skipped when nmap/Docker missing).
- **End-to-end** (`tests/end_to_end/`): NL → deterministic planner → MCP → guard → (mock or real) nmap; denied case asserts no process spawned.
- Run `uv run pytest` and `uv run ruff check`; record actual pass/fail output in `results/` or the checklist — never claim results not run.

### M6 — Evaluation
1. Write `evaluation/cases.json` using the README §14 case format (`case_id, category, input, expected_plan_or_parse_outcome, expected_policy_decision, expected_execution_behavior`), one case per input, covering all 11 categories (benign, malformed, prompt injection, forbidden targets, alt IP encodings, IPv6, CIDR, hostname, forbidden options, forbidden ports, timeout/exec errors).
2. `run_comparison.py` with C1–C4:
   - C1 manual nmap: scripted `nmap` with the case's literal target/ports (lab-only).
   - C2/C3/C4: same LLM planner/model/settings; differ only in guard (C2 none, in a **separate harness module**, never reachable from the production server; C3 restrictive prompt only; C4 production guard). Execution is still argv-based and confined to loopback/lab.
   - Record destination/ports actually scanned and whether the process started, to compute block rate and bypass rate per README §16.
3. `run_latency.py`: ≥10 matched runs of the same authorized plan; report n, mean, std for planner / policy / scan / total.
4. `analyze_results.py`: CSV → summary table + figures (use the `dataviz` guidance) into `results/`.
5. Run port-scope cases on the loopback lab and target-scope cases (forbidden target IP, alt encodings of the allowed/forbidden IP) on the two-container-IP lab from M1b; record the topology in each result row. Update `docs/evaluation.md` accordingly.

### M7 — Docs and clean-machine verification
Update `README.md` run instructions, `docs/architecture.md`, `docs/progress-checklist.md` (tick only items that were actually tested); follow the docs on a clean machine/container; confirm no secrets committed.

## 4. Recommended Order

`M2 (incl. schema change) → M5 (unit tests for policy/command/parser) → M3 → M1 (+M1b) → M4 → M5 (integration/e2e) → M6 → M7`

M2 first because the pipeline currently crashes on every request; unit tests on the guard then lock in the security property before anything else is built on it.

## 5. Risks and Known Limitations

1. **Hostnames unsupported** (decision 3): any hostname input is rejected; this limits realism and must be stated in the report. Hostname-resolution/DNS-rebinding behavior is not evaluated.
2. **IPv6 unsupported** in V1 for the same reason; rejected explicitly.
3. **Two-network lab** (M1b) adds Docker complexity; if it slips, target-scope experiments must be documented as not run rather than inferred from the loopback lab.
4. **Schema change** (decision 1) touches agent and server; do it first in M2 with its tests so later work builds on the final contract.
5. **LLM experiments** require an API key and a fixed model/version; record token usage. Deterministic-planner results must not be presented as evidence of prompt-injection resistance.
6. Nmap `-sT` on loopback should need no privileges, but verify on the target OS; `-sV` timing may approach the 60 s timeout, so validate.
7. Package ownership (README §18): M2, M3, M1b mostly B; M5, M6, M7 mostly C.
