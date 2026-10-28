# Controlled local testbed

The Compose file publishes both services on host loopback only:

- Approved target: `127.0.0.1:8080`
- Decoy target: `127.0.0.1:8081` (for controlled policy-rejection experiments)

Start with `docker compose -f lab/docker-compose.yml up -d` and stop with
`docker compose -f lab/docker-compose.yml down`. This topology tests port-scope
enforcement on one IP; it does not demonstrate denial of a different target IP.
The container's port is 80; 8080/8081 are host-published ports.
