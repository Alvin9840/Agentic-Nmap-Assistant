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
