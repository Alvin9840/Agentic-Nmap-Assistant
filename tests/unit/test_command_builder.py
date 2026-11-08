"""Unit tests for fixed Nmap argv construction."""

from safe_nmap.server.command_builder import build_nmap_command
from safe_nmap.shared.schemas import ValidatedPlan


def _plan(**overrides) -> ValidatedPlan:
    defaults = {
        "original_target": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "ports": [8080],
        "profile": "web-check",
        "timeout_seconds": 60,
        "service_detection": False,
    }
    defaults.update(overrides)
    return ValidatedPlan(**defaults)


def test_build_nmap_command_without_service_detection():
    command = build_nmap_command(_plan())
    assert command == ["nmap", "-n", "-sT", "-T3", "-oX", "-", "-p", "8080", "127.0.0.1"]


def test_build_nmap_command_with_service_detection_adds_sv():
    command = build_nmap_command(_plan(service_detection=True))
    assert command == [
        "nmap",
        "-n",
        "-sT",
        "-T3",
        "-oX",
        "-",
        "-sV",
        "-p",
        "8080",
        "127.0.0.1",
    ]


def test_build_nmap_command_joins_multiple_ports_in_request_order():
    command = build_nmap_command(_plan(ports=[8080, 8081, 22]))
    port_index = command.index("-p")
    assert command[port_index + 1] == "8080,8081,22"


def test_build_nmap_command_uses_resolved_ip_not_original_target():
    command = build_nmap_command(_plan(original_target="localhost", resolved_ip="127.0.0.1"))
    assert command[-1] == "127.0.0.1"
    assert "localhost" not in command
