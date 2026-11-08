# Architecture and trust boundary

The application is a small single-agent system with one MCP client and one MCP
server. The agent proposes a structured `ScanRequest`; the server independently
validates and authorizes it before producing a `ValidatedPlan` for the scanner.

User text, planner output, and MCP arguments are untrusted. Policy configuration,
the policy guard, command builder, and executor are server-controlled. The agent
cannot invoke Nmap directly or access a general-purpose shell. The command
builder accepts only a validated plan and produces a fixed argument vector.

Initial implementation order: M1 lab/scanner/parser, M2 policy enforcement,
M3 MCP integration, M4 planners and CLI, then M5 evaluation.

## Status (2026-11-08)

M1 (lab/scanner/parser), M2 (policy guard), M3 (reporter/audit), M4 (real
end-to-end CLI run against the lab), and M5 (unit + integration + end-to-end
tests) are implemented and verified by a passing test suite (118 tests
without the Docker lab, 123 with it running). M6 (evaluation) is implemented
and run for the conditions that do not require an LLM (C1, C4, latency); see
`docs/evaluation.md` for real measured results and for why C2/C3 were not
run. See `docs/progress-checklist.md` for the authoritative, item-by-item
implemented/tested status and `README.md` section 21 for setup and usage.
