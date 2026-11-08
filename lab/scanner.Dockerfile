# Minimal image for the target-scope lab: runs nmap *inside* the Docker
# network so it can reach container-only IPs that the host cannot (a
# user-defined bridge network's addresses are not routable from the host on
# Docker Desktop for Mac/Windows, unlike the loopback lab's published ports).
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests
RUN pip install --no-cache-dir -e ".[dev]"
