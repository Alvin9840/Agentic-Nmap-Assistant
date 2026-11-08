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

## Target-scope lab (M1b): distinct IPs, not just distinct ports

The loopback lab above only demonstrates **port-scope** enforcement: both
services share `127.0.0.1`. To demonstrate rejecting a different **target
IP**, use `lab/docker-compose.targets.yml` instead. It creates a Docker
bridge network (`172.28.0.0/24`) with:

| Service | IP | Role |
|---|---|---|
| `approved-nginx` | `172.28.0.10` | the only target in `config/policy.lab-network.example.yaml` |
| `decoy-nginx` | `172.28.0.11` | reachable, but never authorized |
| `scanner` | `172.28.0.2` | has nmap and the project installed; publishes no ports |

A bridge network's container IPs are **not routable from the host** on
Docker Desktop for macOS/Windows (verified 2026-11-08: `curl 172.28.0.10`
from the host times out), so experiments must run *inside* the `scanner`
container, not from the host:

```sh
docker compose -f lab/docker-compose.targets.yml up -d --build
docker compose -f lab/docker-compose.targets.yml exec \
  -e SAFE_NMAP_POLICY=/app/config/policy.lab-network.example.yaml \
  scanner python3 -m pytest tests/integration/test_target_scope_lab.py -v
docker compose -f lab/docker-compose.targets.yml down
```

Verified 2026-11-08: `nmap` from inside `scanner` reaches both `172.28.0.10`
and `172.28.0.11` (both `open` on port 80); with
`policy.lab-network.example.yaml` active, `policy_guard.authorize` allows
`172.28.0.10` and rejects `172.28.0.11` with "not an authorized target" even
though the decoy is reachable. `tests/integration/test_target_scope_lab.py`
automates this and is skipped everywhere the containers aren't reachable
(including the default `pytest -q` run on the host).

Document which topology (loopback port-scope vs. this target-scope network)
each experiment used; do not infer target-scope results from the loopback
lab.
