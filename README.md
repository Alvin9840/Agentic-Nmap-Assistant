# Safe Nmap Assistant

## Project Status (read this first)

Current work lives on `feature/m1b-lab-and-metrics`, built on top of six
earlier feature branches (`feature/m1-lab-baseline` →
`feature/m2-policy-guard-m5-unit-tests` → `feature/m4-end-to-end` →
`feature/m5-more-integration-tests` → `feature/m5-planner-tests` →
`feature/m6-evaluation` → `feature/m1b-lab-and-metrics`), 9 commits ahead of
`main`. **None of this has been pushed to `origin` or merged yet** — see
"Not done yet" below before you start building on `main`.

### Architecture

```text
CLI -> Agent/Planner (deterministic or LLM) -> MCP Client -> MCP Server
  -> Policy Guard -> Command Builder -> Nmap Executor -> XML Parser -> Report
```

The policy guard is the only trusted authorization point; user text,
planner output, and MCP arguments are all untrusted (see section 3 below
for the full trust-boundary diagram, and `docs/architecture.md`).

### Done and tested

| Milestone | What | Evidence |
|---|---|---|
| M1 | Loopback lab (port-scope: `127.0.0.1:8080`/`8081`) **and** M1b target-scope lab (distinct container IPs `172.28.0.10`/`.11` on an isolated Docker network, `lab/docker-compose.targets.yml`) | `lab/README.md`; `tests/integration/test_lab_scanner.py`, `test_target_scope_lab.py` |
| M2 | Policy guard: canonical-IPv4-only; hostnames, CIDR, IPv6, IPv4-mapped IPv6, and non-canonical numeric forms are rejected outright, never resolved/expanded (design finalized — see `docs/implementation-plan.md` §2 decision 11) | `tests/unit/test_policy_guard.py` |
| M3 | Deterministic report (`server/reporter.py`) + JSONL audit log (`server/audit.py`: decision event before Nmap starts, outcome event after) | `tests/unit/test_reporter.py`, `test_audit.py` |
| M4 | Real end-to-end CLI run against the lab (approved request succeeds, decoy request rejected); found and fixed a real bug where the MCP stdio server crashed on every launch | manual run + `tests/end_to_end/` |
| M5 | 113 unit/integration tests passing without any lab running (120 with both labs up) | `pytest -q` |
| M6 | Evaluation harness: C1 (manual Nmap) and C4 (our system) run for real across 22 cases (`evaluation/cases.json`, supersedes an earlier `T1`–`T10` draft — see decision 12); 2 real planner bugs found and fixed (CIDR and IPv4-mapped-IPv6 targets were being silently truncated) | `docs/evaluation.md` |
| M7 | Setup instructions (section 21 below) verified by cloning the repo into a separate directory and following them exactly | `docs/progress-checklist.md` |

### How to run it

See **section 21 "Setup and Usage"** below for the full, verified steps.
Quick version:

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
4. **Push/merge this work.** All of M1–M7 currently exists only in local
   feature branches on this machine; push them and merge into `main` so
   teammates can see the current state.
5. **Windows/Linux setup verification** — only verified on macOS so far.
6. Final report sections, slides, and any figures beyond what is already
   in `docs/evaluation.md`.

See `docs/progress-checklist.md` for the full item-by-item implemented/
tested status and `docs/evaluation.md` for the real measured results and
their limitations.

---

## 1. Instructions for the Coding Agent

You are implementing a course project for CS/ECE 5584: Network Security.

Build a small, reproducible application that allows a user to request an
authorized Nmap scan using natural language.

The core security requirement is:

> The agent proposes a scan. A server-side policy guard independently
> authorizes it before Nmap starts.

Before modifying code:

1. Inspect the existing repository.
2. Identify which components already work.
3. Compare the implementation against this specification.
4. Report gaps and propose a short implementation plan.
5. Reuse working code instead of unnecessarily rewriting it.
6. Implement and test one milestone at a time.

Do not claim that a feature works without running the relevant tests.
Do not invent experiment results, timing measurements, or security guarantees.
Clearly distinguish implemented, tested, and planned features.

If existing code conflicts with this document, explain the conflict before
making a major architectural change.

## 2. Project Scope

### Required capabilities

- One AI agent.
- One MCP client connection.
- One MCP server exposing an Nmap tool.
- Structured scan requests.
- Independent server-side policy enforcement.
- Controlled local Docker testbed.
- Nmap execution and XML parsing.
- Readable scan reports.
- Audit logs.
- Automated tests and comparison experiments.

### Out of scope

Do not add these unless explicitly requested:

- Multi-agent orchestration.
- Automatic exploitation.
- Metasploit integration.
- NSE script execution.
- Public or campus-network scanning.
- Arbitrary shell access.
- Web dashboard.
- Enterprise SSO, CMDB, or full IAM implementation.
- Automatic vulnerability or CVE claims.

Prefer a small working application over a complex framework.

## 3. Architecture

```text
User
  |
  v
CLI
  |
  v
Agent / Planner
  |
  | Structured ScanRequest
  v
MCP Client
  |
  v
MCP Server: scan_network
  |
  v
Policy Guard
  |
  +-- Denied --> Rejection + Audit Log
  |
  +-- Allowed
        |
        v
    Command Builder
        |
        v
    Nmap Executor
        |
        v
    XML Parser
        |
        v
    Structured Result + Readable Report
```

### Trust boundary

Untrusted:

- User text.
- LLM-generated plans.
- MCP tool arguments.

Trusted enforcement components:

- Server-controlled policy configuration.
- Policy guard.
- Command builder.
- Executor implementation.

The MCP server must validate every request even if the client already
validated it.

MCP is a tool interface, not an authorization mechanism.

The agent must not directly execute Nmap or access a general-purpose shell.

## 4. Suggested Technology Stack

- Python 3.11 or later.
- Official MCP Python SDK.
- Pydantic for data validation.
- Nmap installed separately.
- Docker Compose.
- nginx container.
- pytest.
- JSONL audit logs.
- CSV experiment outputs.

Use a local stdio MCP connection for the initial implementation.

Avoid introducing LangGraph, a database, or a web framework unless necessary.

Pin and document dependency versions after verifying a working environment.

## 5. V1 Repository Structure

The initial V1 scaffold is organized by responsibility. The command builder is
kept separate from the scanner so untrusted input cannot become raw Nmap flags.

```text
agentic-nmap-assistant/
├── README.md
├── pyproject.toml
├── .env.example
├── config/policy.example.yaml
├── src/safe_nmap/
│   ├── shared/schemas.py
│   ├── agent/ (cli, planner fallback, llm_planner, mcp_client, prompts)
│   └── server/ (mcp_server, policy_guard, command_builder, scanner, parser,
│                reporter, audit)
├── lab/ (docker-compose.yml, README.md)
├── tests/ (unit, integration, end_to_end, fixtures)
├── evaluation/ (cases.json, run_comparison.py, run_latency.py,
│                analyze_results.py)
├── results/
└── docs/ (architecture.md, evaluation.md)
```

This is a scaffold: modules marked as planned are not implemented yet. Local
policy, credentials, and generated experiment output are excluded from git.
## 6. Shared Data Contracts

Define shared schemas before implementing individual modules.

### 6.1 ScanRequest

Example:

```json
{
  "target": "127.0.0.1",
  "ports": [8080],
  "profile": "service-check"
}
```

Requirements:

- `target`: exactly one supported target.
- `ports`: nonempty list of valid integer ports.
- `profile`: server-recognized profile name.
- Reject unknown fields.
- Do not accept a raw command or raw Nmap flags.
- Do not silently replace explicit targets or ports.
- Do not use permissive type coercion that changes invalid values into valid ones.

The server generates a request ID for logging.

### 6.2 ValidatedScanPlan

Create a separate internal representation after authorization.

It should contain:

- Original target.
- Validated, canonical destination IP.
- Authorized ports.
- Authorized profile.
- Server-controlled timeout.
- Server-controlled execution options.

Only validated plans may reach the executor.

### 6.3 ScanResponse

Example:

```json
{
  "request_id": "generated-id",
  "status": "success",
  "allowed": true,
  "nmap_started": true,
  "reason": null,
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "findings": [
    {
      "port": 8080,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "product": "nginx",
      "version": null
    }
  ],
  "timing": {
    "policy_ms": 0.0,
    "scan_ms": 0.0,
    "server_total_ms": 0.0
  }
}
```

Timing values above illustrate the schema, not measured results.

Supported statuses:

- `success`
- `parse_error`
- `rejected`
- `scan_failed`

Rules:

- A policy rejection must have `nmap_started=false`.
- A failed scan must not be reported as closed ports.
- Use `findings=null` when no valid scan result exists.
- A successful scan can have an empty findings list.
- Record process launch separately from successful completion.

## 7. Local Testbed

Create two controlled services:

1. Approved nginx target.
2. Decoy nginx target owned by the team but forbidden by the product policy.

Suggested host-based setup:

```text
Approved service: 127.0.0.1:8080
Decoy service:    127.0.0.1:8081
```

Bind published ports to loopback, not all host interfaces.

Important:

- This setup demonstrates port-scope enforcement.
- It does not demonstrate denial of a different target IP.
- For actual target-scope experiments, run the scanner in a controlled
  Docker network with two distinct container IPs.
- Document which topology is used for each experiment.
- Do not confuse a container's internal port with its host-published port.
- `127.0.0.1` refers to the current network namespace.

The decoy is forbidden by application policy but remains authorized for
the team's controlled experiments.

## 8. Agent / Planner

### Responsibilities

- Read a natural-language scan request.
- Extract the explicit target and ports.
- Select an approved profile.
- Produce a structured ScanRequest.
- Invoke the MCP tool through the client.
- Present the result without inventing findings.

### Requirements

- Preserve user-specified targets and ports.
- Never silently rewrite an unauthorized target into an approved one.
- If essential information is missing, ask for clarification or return
  a parse error.
- Do not output or execute raw shell commands.
- Limit tool-call count and retries.
- Keep the workflow single-agent and simple.

### Planner modes

Implement:

1. A deterministic planner for development and fallback.
2. An LLM planner for AI and prompt-only comparison experiments.

Clearly label which mode produced each result.

Do not describe deterministic-parser behavior as evidence of LLM
prompt-injection resistance.

## 9. MCP Client and Server

### Client

- Connect to the MCP server.
- Discover or access the scan tool.
- Submit structured arguments.
- Receive structured results.
- Handle transport and tool errors.

### Server

Expose a tool similar to:

```python
scan_network(target: str, ports: list[int], profile: str)
```

Every call must follow this sequence:

```text
Validate schema
  -> Authorize request
  -> Build command
  -> Execute Nmap
  -> Parse result
  -> Log outcome
  -> Return response
```

Do not expose a generic `run_command` tool.

With stdio transport, keep protocol stdout free of debug output.
Send diagnostic logging to stderr or a log file.

## 10. Policy Guard

Store policy in a server-controlled configuration file.

Example:

```yaml
allowed_targets:
  - "127.0.0.1"

profiles:
  web-check:
    allowed_ports: [8080]
    service_detection: false

  service-check:
    allowed_ports: [8080]
    service_detection: true

limits:
  timeout_seconds: 60
  max_ports_per_request: 4
  max_concurrent_scans: 1
```

### Required checks

- Supported target syntax.
- Valid port values.
- Known profile.
- Target authorization.
- Requested ports are a subset of the profile's allowed ports.
- Request size and concurrency limits.
- No unexpected or raw command fields.

### Target handling

The minimal version may support only canonical single IPv4 addresses.

If a syntax is unsupported, reject it explicitly.

Additional supported formats must be implemented and tested deliberately:

- Hostnames.
- Alternative numeric IP representations.
- IPv6.
- IPv4-mapped IPv6.

For hostname support:

1. Resolve the hostname.
2. Validate every returned address.
3. Reject if any address is forbidden.
4. Execute against a validated numeric address, not a newly resolved hostname.

For the minimal project, reject CIDR requests rather than expanding
arbitrarily large networks.

If test expectations change because a format is unsupported, update the
test specification and report consistently.

### Fail-closed behavior

Reject the request when:

- Parsing fails.
- Authorization fails.
- Policy configuration is missing or invalid.
- Resolution fails.
- The target format is unsupported.
- The server cannot determine that execution is allowed.

The agent must not be able to edit policy configuration.

## 11. Nmap Command Builder and Executor

### Command builder

Build argument lists from validated plans and fixed templates.

Example:

```python
[
    "nmap",
    "-sT",
    "-T3",
    "-p",
    "8080",
    "-oX",
    "-",
    "127.0.0.1"
]
```

Add `-sV` only for an approved service-detection profile.

Requirements:

- No raw user-controlled flags.
- No NSE scripts.
- No arbitrary output paths.
- No shell command string.
- No `shell=True`.

### Executor

- Use a trusted Nmap executable path.
- Enforce a timeout.
- Capture stdout, stderr, and return code.
- Record process-start success.
- Terminate and clean up timed-out processes.
- Return explicit execution errors.
- Never interpret execution failure as closed ports.

## 12. Parser and Reporter

### Parser

Parse Nmap XML into structured findings:

- Host.
- Port.
- Protocol.
- State.
- Service.
- Product and version, when available.

Preserve missing values as null or unknown.

Do not infer a software version solely from the port number.

### Reporter

Generate a readable report using a deterministic template first.

Include:

- Requested and scanned target.
- Scan profile.
- Observed ports and states.
- Detected service information.
- Rejection or failure reason.
- Basic limitations.

Do not claim:

- An open port proves a vulnerability.
- A successful scan proves the target is secure.
- A guessed service name is a verified product/version.

An LLM-written summary is optional and must not override structured results.

## 13. Audit Logging

Write one or more JSONL events per request.

Include:

- Request ID.
- Timestamp.
- Planner mode.
- Original request or controlled test-case ID.
- Proposed structured plan.
- Validated destination.
- Policy decision.
- Rejection/error reason.
- Nmap process-start status.
- Final status.
- Timing.
- Experiment condition.
- Token usage, when available.

Do not log API keys, credentials, or hidden model reasoning.

Logging failures must not accidentally allow an unauthorized scan.

## 14. Testing

### Unit tests

Test:

- Schema validation.
- Planner target/port preservation.
- Target normalization.
- Profile validation.
- Port authorization.
- Command construction.
- XML parsing.
- Error classification.

### Integration tests

Test:

- Policy guard to executor.
- Executor to parser.
- MCP client to server.
- Approved nginx scan.
- Decoy rejection.

Use mocks to verify that denied requests never invoke the executor.

### End-to-end tests

Start from natural language and verify:

- The requested target reaches the guard correctly.
- Approved requests complete.
- Unauthorized requests are explicitly rejected.
- No unauthorized Nmap process starts.
- Parse and execution errors are not misreported.

### Test-case format

Each concrete case must have:

```text
case_id
category
input
expected_plan_or_parse_outcome
expected_policy_decision
expected_execution_behavior
```

Split categories containing multiple inputs into separate cases.
Do not treat a category with five inputs as one case without documenting it.

Test categories:

- Benign authorized requests.
- Missing or malformed input.
- Prompt injection.
- Forbidden targets.
- Alternative IP encodings.
- IPv6.
- CIDR requests.
- Hostname resolution.
- Forbidden options.
- Forbidden ports.
- Timeout and execution errors.

## 15. Comparison Experiments

Implement four conditions:

| ID | Condition |
|----|-----------|
| C1 | Manual Nmap |
| C2 | Agent with no application policy guard |
| C3 | Same agent with prompt-only restrictions |
| C4 | Same agent with server-side policy guard |

For C2–C4:

- Use the same model/version and settings.
- Use the same test cases.
- Keep differences limited to the intended policy condition.
- Preserve structured commands and safe process execution.
- Never remove the outer lab containment.

Do not expose a user-accessible switch that disables production enforcement.

No-policy mode belongs in a separate experiment harness.

Prompt-only experiments require an actual LLM planner.

## 16. Metrics

### Block rate

```text
Correctly rejected unauthorized cases
------------------------------------
All predefined unauthorized cases
```

A planner silently changing the target is not a correct policy rejection.

Track parse errors, model refusals, guard rejections, and execution failures
separately.

### Bypass rate

```text
Unauthorized cases that actually triggered a policy-violating scan
----------------------------------------------------------------
All predefined unauthorized cases
```

Record both process launch and the actual destination/ports.

### Other metrics

- Benign task-completion rate.
- Incorrect rejection rate.
- Port/service agreement with manual Nmap.
- End-to-end latency.
- Policy-check duration.
- Added latency compared with no-policy mode.
- User task time.
- LLM tokens and cost, when applicable.

For latency:

- Repeat matched runs at least 10 times where practical.
- Compare the same authorized scan plan.
- Report sample size, mean, and standard deviation.
- Separate planner, policy, scan, and total time.

Do not claim a guard is faster just because it rejected a request while
another condition executed a scan.

## 17. Development Milestones

### M1: Lab and scanner

- Start approved and decoy services.
- Run manual Nmap.
- Implement executor and XML parser.

Acceptance:
A Python call returns the expected approved service.

### M2: Policy enforcement

- Implement request schemas and policy configuration.
- Add guard and command builder.
- Add rejection and error tests.

Acceptance:
Unauthorized requests do not invoke the executor.

### M3: MCP integration

- Expose scan_network.
- Connect a test MCP client.
- Validate structured responses.

Acceptance:
A structured request works through MCP without an LLM.

### M4: Agent integration

- Implement deterministic and LLM planners.
- Add CLI.
- Preserve explicit target/ports.

Acceptance:
Natural-language approved requests complete, and unauthorized requests
are rejected through the full path.

### M5: Evaluation

- Finalize test cases.
- Run C1–C4.
- Export raw results and summary tables.
- Generate figures and analyze failures.

Acceptance:
Results are reproducible and every reported number can be traced to logs.

## 18. Three Work Packages

### Package A: Completed Implementation

Implemented so far:

- CLI, deterministic planner, LLM planner, and prompts.
- Agent pipeline and MCP client.
- MCP server tool interface and server pipeline.
- Initial command builder, Nmap executor, and XML parser.

These implementations still need the tests and integration verification owned by C.

### Package B: Remaining Non-Test Work

Own the remaining implementation and documentation work:

- Load and validate the server-controlled policy configuration.
- Implement the independent policy guard and authorized `ValidatedPlan` creation.
- Ensure denied requests cannot reach the Nmap executor.
- Review and integrate the existing command builder, scanner, parser, and server pipeline with policy.
- Implement deterministic reports and JSONL audit logging.
- Finalize the approved/decoy Docker Compose lab and its setup and ground-truth documentation.

### Package C: Tests and Evaluation

Own verification and experimental work:

- Unit, integration, and end-to-end tests for agent, policy, MCP, and scan components.
- Start and validate the approved/decoy Docker lab; verify denied requests never invoke the executor.
- Verify setup from a clean environment.
- Finalize evaluation cases and expected outcomes.
- Implement C1–C4 comparison and latency workflows.
- Run tests and experiments; export reproducible raw data, summaries, and figures.

All contributors must agree on schemas and audit fields before parallel work.

## 19. Definition of Done

The project is complete when:

- A fresh developer can follow the documented setup.
- The controlled testbed starts reproducibly.
- The agent submits structured requests through MCP.
- User-specified targets and ports are not silently replaced.
- The server independently authorizes every scan.
- Unauthorized requests do not start Nmap.
- Scan failures are clearly distinguished from port states.
- Results and logs are reproducible.
- C1–C4 comparisons are completed or explicitly documented as limitations.
- Reported metrics are backed by raw data.
- No secrets or sensitive company data are committed.
- README, presentation, and report accurately match the implementation.

## 20. First Action Requested from the Coding Agent

Do not implement everything immediately.

First return:

1. Current repository structure.
2. Existing working components.
3. Gaps against this README.
4. Proposed shared schemas.
5. A milestone-by-milestone implementation plan.
6. Tests to run for the first milestone.

Then proceed with the smallest useful change.

## 21. Setup and Usage

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
