# Controlled local testbed

The Compose file publishes both services on host loopback only:

- Approved target: `127.0.0.1:8080`
- Decoy target: `127.0.0.1:8081` (for controlled policy-rejection experiments)

Start with `docker compose -f lab/docker-compose.yml up -d` and stop with
`docker compose -f lab/docker-compose.yml down`. This topology tests port-scope
enforcement on one IP; it does not demonstrate denial of a different target IP.
The container's port is 80; 8080/8081 are host-published ports.

## Ground truth (verified 2026-11-08)

Verified by running `docker compose -f lab/docker-compose.yml up -d`, then
`curl 127.0.0.1:8080` / `curl 127.0.0.1:8081` (both returned HTTP 200), then
`nmap -n -sT -T3 [-sV] -oX - -p <port> 127.0.0.1` with nmap 7.993 on macOS, and
separately by calling `safe_nmap.server.scanner.run_nmap` +
`safe_nmap.server.parser.parse_nmap_xml` directly from Python.

| Target | Port | Listening service | Expected `-sT` state | Expected `-sV` service/product |
|---|---|---|---|---|
| `127.0.0.1` | `8080` | `approved-nginx` (container port 80) | `open` | `http` / `nginx` 1.30.6 |
| `127.0.0.1` | `8081` | `decoy-nginx` (container port 80), forbidden by `config/policy.example.yaml` | `open` | `http` / `nginx` 1.30.6 |
| `127.0.0.1` | `9999` | nothing | `closed` | n/a |

Policy expectation with `config/policy.example.yaml`: a request for
`127.0.0.1:8080` under `web-check` or `service-check` is allowed; a request for
`127.0.0.1:8081` is rejected by the policy guard (port not in either profile's
`allowed_ports`) and Nmap is never started, even though the decoy service is
reachable and owned by the team.

Captured XML fixtures from this run are under `tests/fixtures/`:
`nmap_web_check_8080_open.xml`, `nmap_service_check_8080_open.xml`, and
`nmap_web_check_closed_port.xml`.
