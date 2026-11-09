# Safe Nmap Assistant

A small, reproducible application for CS/ECE 5584 (Network Security) that
lets a user request an authorized Nmap scan using natural language. The
core security requirement: **the agent proposes a scan; a server-side
policy guard independently authorizes it before Nmap starts.**

Full design specification, data contracts, and component details now live
in `docs/architecture.md`; design decisions and milestones in
`docs/implementation-plan.md`; experiment methodology and results in
`docs/evaluation.md`; the detailed implemented/tested checklist in
`docs/progress-checklist.md`. This file only covers status, work packages,
and setup.

## Project Status (read this first)

### Architecture

```text
CLI -> Agent/Planner (deterministic or LLM) -> MCP Client -> MCP Server
  -> Policy Guard -> Command Builder -> Nmap Executor -> XML Parser -> Report
```

The policy guard is the only trusted authorization point; user text,
planner output, and MCP arguments are all untrusted. See
`docs/architecture.md` for the full trust-boundary diagram and the
per-component specification.

### Done and tested

| Milestone | What | Evidence |
|---|---|---|
| M1 | Loopback lab (port-scope: `127.0.0.1:8080`/`8081`) **and** M1b target-scope lab (distinct container IPs `172.28.0.10`/`.11` on an isolated Docker network, `lab/docker-compose.targets.yml`) | `lab/README.md`; `tests/integration/test_lab_scanner.py`, `test_target_scope_lab.py` |
| M2 | Policy guard: canonical-IPv4-only; hostnames, CIDR, IPv6, IPv4-mapped IPv6, and non-canonical numeric forms are rejected outright, never resolved/expanded (design finalized — see `docs/implementation-plan.md` §2 decision 11) | `tests/unit/test_policy_guard.py` |
| M3 | Deterministic report (`server/reporter.py`) + JSONL audit log (`server/audit.py`: decision event before Nmap starts, outcome event after) | `tests/unit/test_reporter.py`, `test_audit.py` |
| M4 | Real end-to-end CLI run against the lab (approved request succeeds, decoy request rejected); found and fixed a real bug where the MCP stdio server crashed on every launch | manual run + `tests/end_to_end/` |
| M5 | 113 unit/integration tests passing without any lab running; 118 with the loopback lab up (`pytest -q`); the 2 target-scope tests additionally pass when run *inside* the `scanner` container (120 total, across two separate test invocations — see `lab/README.md`) | `pytest -q` |
| M6 | Evaluation harness: C1 (manual Nmap) and C4 (our system) run for real across 22 cases (`evaluation/cases.json`, supersedes an earlier `T1`–`T10` draft — see decision 12); 2 real planner bugs found and fixed (CIDR and IPv4-mapped-IPv6 targets were being silently truncated) | `docs/evaluation.md` |
| M7 | Setup instructions ("Setup and Usage" below) verified by cloning the repo into a separate directory and following them exactly | `docs/progress-checklist.md` |

### How to run it

See **"Setup and Usage"** below for the full, verified steps. Quick version:

```sh
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev,eval]"
cp config/policy.example.yaml config/policy.yaml
docker compose -f lab/docker-compose.yml up -d
safe-nmap --planner deterministic --request "profile web-check port 8080 target 127.0.0.1"
pytest -q
```

### Not done yet — handoff items

1. **C2 (agent with no policy guard) and C3 (prompt-only guardrail)** both
   require the same LLM planner/model and a configured
   `OPENAI_API_KEY`/`OPENAI_MODEL`, which this environment does not have.
   `evaluation/run_comparison.py` already has the structure
   (`run_c2_or_c3`), but it intentionally returns `not_run` placeholders
   rather than shipping an untested "skip the policy guard" code path.
   **Whoever has an API key should implement and run these.**
2. **Real prompt-injection testing against the LLM planner** — same
   blocker; only the deterministic planner has been exercised against
   injection-style inputs, which is explicitly not evidence of LLM
   behavior (see `docs/evaluation.md`).
3. **Policy-layer overhead and user-time metrics** depend on C2 and on a
   human timing study respectively; neither is computed yet.
4. **Windows/Linux setup verification** — only verified on macOS so far.
5. Final report sections, slides, and any figures beyond what is already
   in `docs/evaluation.md`.

See `docs/progress-checklist.md` for the full item-by-item implemented/
tested status and `docs/evaluation.md` for the real measured results and
their limitations.

## Work Packages

Based on git history: Package A is everything committed before 2026-11-08
(the original scaffold); Package B is everything committed on 2026-11-08
(this session); Package C is what is left.

### Package A: Initial Scaffold (committed 2026-10-28 – 2026-11-04)

- Project structure, shared Pydantic schemas (`ScanRequest`, `ValidatedPlan`,
  `Finding`, `ScanResponse`).
- CLI, deterministic planner, LLM planner, and prompts.
- Agent pipeline and MCP client.
- MCP server tool interface and server pipeline (not yet wired to a working
  policy guard).
- Initial command builder, Nmap executor, and XML parser.
- `policy_guard.py` was a stub that always raised `NotImplementedError`;
  `reporter.py` and `audit.py` were empty; the lab had never been started;
  `tests/`, `evaluation/cases.json`, and the `evaluation/*.py` scripts were
  empty placeholders.

### Package B: Policy Guard, Reporter/Audit, Lab, Tests, Evaluation (committed 2026-11-08)

- Policy configuration loading and the independent policy guard
  (canonical-IPv4-only; rejects hostnames/CIDR/IPv6/IPv4-mapped-IPv6/
  non-canonical numeric forms outright — design finalized, see
  `docs/implementation-plan.md` §2 decision 11); denied requests verified to
  never reach the Nmap executor.
- `-T3` and executable lookup in the command builder; a concurrency limiter
  in the server pipeline.
- Deterministic report generation and JSONL audit logging (decision event
  before Nmap starts, outcome event after).
- The loopback port-scope lab (M1) and the M1b target-scope lab with
  distinct container IPs, including fixing a Compose project-name collision
  between the two.
- A real end-to-end run against the lab, including fixing a genuine bug
  where the MCP stdio server crashed on every launch.
- The full unit/integration/end-to-end test suite (120 tests total).
- Evaluation cases (`evaluation/cases.json`, supersedes an earlier `T1`–`T10`
  draft — decision 12), the C1/C4 comparison and latency workflows, and
  real exported results, summaries, and limitations in `docs/evaluation.md`
  — including two real planner bugs found and fixed along the way (CIDR and
  IPv4-mapped-IPv6 targets being silently truncated).
- Setup verified from a clean environment (a separate `git clone`, macOS only).

### Package C: Remaining Work

- Implement and run C2 (agent with no policy guard) and C3 (prompt-only
  guardrail) — both require a configured `OPENAI_API_KEY`/`OPENAI_MODEL`,
  which this environment does not have.
- Real prompt-injection testing against the LLM planner (only the
  deterministic planner has been exercised so far, which is not evidence of
  LLM behavior).
- Policy-layer overhead and user-task-time metrics (the former depends on
  C2; the latter on a human timing study).
- Verify setup on Windows and/or Linux (only macOS has been verified).
- Final report sections, slides, and any figures beyond what is already in
  `docs/evaluation.md`.

All contributors must agree on schemas and audit fields before parallel work.

## Setup and Usage

Verified 2026-11-08 on macOS (Python 3.11, nmap 7.993, Docker Desktop) and by
cloning the repository into a separate directory and repeating these exact
steps with no other local state; not verified on Windows or Linux.

### Prerequisites

- Python 3.11 or later.
- `nmap` on `PATH` (e.g. `brew install nmap` on macOS, `apt-get install nmap`
  on Debian/Ubuntu).
- Docker (for the local lab).

### 1. Install the project

With `uv`:

```sh
uv sync --extra dev --extra eval
```

Without `uv` (plain `venv` + `pip`):

```sh
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,eval]"
```

### 2. Create the local policy file

```sh
cp config/policy.example.yaml config/policy.yaml
```

`config/policy.yaml` is git-ignored and required at runtime; every request is
rejected (fail closed) without it. Override its path with `SAFE_NMAP_POLICY`.

### 3. Start the local lab (required for a real scan)

```sh
docker compose -f lab/docker-compose.yml up -d
curl 127.0.0.1:8080   # approved service
curl 127.0.0.1:8081   # decoy service, forbidden by config/policy.example.yaml
docker compose -f lab/docker-compose.yml down   # when done
```

### 4. Run the CLI

```sh
safe-nmap --planner deterministic --request "profile web-check port 8080 target 127.0.0.1"
safe-nmap --planner deterministic --request "profile web-check port 8080 target 127.0.0.1" --json
```

To use `--planner llm` or `--planner auto`, copy `.env.example` to `.env` and
set `OPENAI_API_KEY`/`OPENAI_MODEL` first; without them the LLM planner
reports an explicit unavailability error rather than silently falling back
(except in `auto` mode, which falls back to the deterministic planner).

### 5. Run tests

```sh
pytest -q                 # unit tests + integration tests that need no lab
pytest -q -m lab          # also requires nmap on PATH and the lab running
ruff check .
```

### 6. Run the evaluation scripts

```sh
python3 evaluation/run_comparison.py --conditions C1,C4   # C2/C3 need an LLM planner; see docs/evaluation.md
python3 evaluation/run_latency.py --repeats 10
python3 evaluation/analyze_results.py
```

See `docs/evaluation.md` for methodology, limitations, and the latest results.

### Known V1 limitations

- Hostnames, IPv6, IPv4-mapped IPv6, and CIDR targets are explicitly
  unsupported and rejected rather than resolved or expanded.
- The C2/C3 comparison conditions and any LLM-planner evaluation require a
  configured `OPENAI_API_KEY`/`OPENAI_MODEL`; they are not run by default.

## Further Documentation

- `docs/architecture.md` — full design specification: scope, trust boundary,
  shared data contracts, and per-component responsibilities (agent/planner,
  MCP client/server, policy guard, command builder/executor, parser/reporter,
  audit logging).
- `docs/implementation-plan.md` — design decisions, milestones, recommended
  order, risks, and the original testing specification.
- `docs/evaluation.md` — comparison-experiment and metrics methodology, real
  results, limitations, and bugs found while evaluating.
- `docs/progress-checklist.md` — the authoritative, item-by-item
  implemented/tested status, including the original "Definition of Done".


## Development Update — November 9, 2026

### Completed Work

- Integrated Virginia Tech ARC's `gpt-oss-120b` model using the OpenAI-compatible Chat Completions API.
- Implemented C2 (LLM without application policy guard) and C3 (LLM with prompt-only restrictions) planning experiments.
- Added selectable LLM and deterministic planner modes for C4.
- Verified the C4 end-to-end pipeline: LLM → server-side policy guard → Nmap → results.
- Confirmed authorized scans succeed and unauthorized port requests are rejected before Nmap execution.
- Verified the command builder excludes unauthorized Nmap flags.
- Passed 123 automated tests; 2 Docker-specific integration tests remain skipped.

### Experiment Results

Environment: macOS (Apple Silicon), Python 3.11, Docker, Nmap 7.99.1, VT ARC `gpt-oss-120b`.

#### C2/C3 Planning Evaluation

22 test cases per condition.

| Metric | C2 | C3 |
|---|---:|---:|
| Plans generated | 18 | 7 |
| Planning failures | 4 | 15 |
| Plan generation rate | 81.8% | 31.8% |

These are planning-only results. They do not establish actual scan execution or prompt-injection success rates.

#### C4 LLM + Server-side Policy Guard

22 test cases:

- Successful scans: 6
- Rejected by policy guard: 12
- Planner errors before policy evaluation: 4
- Nmap started: 6
- Nmap not started: 16

All 12 policy-rejected cases had `nmap_started=False`.

#### Performance Evaluation

10 successful runs per configuration.

| Metric | Deterministic | LLM |
|---|---:|---:|
| Planner mean | 0.037 ms | 2558.491 ms |
| Policy mean | 0.074 ms | 0.376 ms |
| Scan mean | 13.850 ms | 34.527 ms |
| Server total mean | 14.087 ms | 35.866 ms |
| End-to-end mean | Not separately recorded | 2594.801 ms |

These measurements come from separate runs. The policy-stage timing is not a matched estimate of net policy overhead.

### Remaining Work

- Complete execution-level C2/C3 comparisons in an isolated lab.
- Finalize prompt-injection outcome classification and security metrics.
- Execute the missing-executable and timeout fault-injection scenarios.
- Complete matched policy-overhead measurements.
- Verify Windows and Linux setup, or document unverified platforms.
- Finalize experiment documentation, report, and presentation.

### Experimental Limitations

- The C2/C3 results are planning-only.
- LLM output may vary across runs.
- Some C4 cases fail before reaching the policy guard.
- Fault-injection scenarios C-021 and C-022 have not yet been executed under their intended failure conditions.
- Cross-platform verification remains pending.


### Final Verification Update

Additional verification was completed on November 9, 2026:

- Automated host test suite: 125 passed, 2 skipped.
- Both skipped target-scope integration tests passed separately
  inside the dedicated Docker Linux scanner container.
- C1 manual Nmap and C4 matched on both benign authorized
  cases (2/2 port-state agreement).
- Eight additional prompt-injection cases were evaluated under
  C2, C3, and C4 (24 planning-only records).
- Six unauthorized C4-generated plans were rejected by the
  server-side Policy Guard (6/6).
- Missing-Nmap and scan-timeout behavior were verified using
  mocked Scanner and Pipeline tests.
- LLM end-to-end latency averaged 2594.801 ms over 10
  successful authorized runs.

Remaining limitations include unmatched policy-on/policy-off
overhead measurements, incomplete C2/C3 execution-level
comparisons, and unverified native Windows/Linux installations.

See `docs/evaluation.md` for the detailed methodology and
experimental results.



### Additional Performance and Execution Verification

Two further evaluations were completed on November 9, 2026.

**Policy Overhead Microbenchmark**

- 1,000 matched policy-on/policy-off measurements.
- Policy-on mean: 0.002926 ms.
- Policy-off mean: 0.000295 ms.
- Paired authorization overhead: 0.002631 ms.
- Both conditions generated identical Nmap commands.
- This microbenchmark does not measure full C2/C4 end-to-end overhead.

**C2/C3 Contained Execution**

- C2: 6 successful scans, 12 outside laboratory scope,
  and 4 planning failures.
- C3: 7 successful scans and 15 planning failures.
- All executed scans returned `8080/open`.
- The independent experimental harness restricted execution
  to the authorized local target `127.0.0.1:8080`.
- The results do not establish unrestricted C2/C3 bypass rates.

Detailed methodology and limitations are documented in
`docs/evaluation.md`.
