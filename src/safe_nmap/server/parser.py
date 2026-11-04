"""Parse Nmap XML output into shared structured findings."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from pydantic import ValidationError

from safe_nmap.shared.schemas import Finding


class NmapParseError(ValueError):
    """Raised when Nmap XML is malformed or contains invalid port data."""


def parse_nmap_xml(xml_output: str) -> list[Finding]:
    """Parse per-port Nmap results into ``Finding`` objects.

    Ports absent from Nmap's XML are not inferred as closed. A valid document
    with no ``<port>`` entries therefore returns an empty list.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapParseError("Nmap returned malformed XML.") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("Unexpected XML root; expected <nmaprun>.")

    findings: list[Finding] = []
    for port_element in root.findall("./host/ports/port"):
        port_text = port_element.get("portid")
        protocol = port_element.get("protocol")
        state_element = port_element.find("state")
        state = state_element.get("state") if state_element is not None else None

        if not port_text or not protocol or not state:
            raise NmapParseError(
                "A <port> entry is missing its port number, protocol, or state."
            )

        try:
            port = int(port_text)
            service_element = port_element.find("service")
            finding = Finding(
                port=port,
                protocol=protocol,
                state=state,
                service=_optional_attribute(service_element, "name"),
                product=_optional_attribute(service_element, "product"),
                version=_optional_attribute(service_element, "version"),
            )
        except (ValueError, ValidationError) as exc:
            raise NmapParseError(
                f"A <port> entry contains invalid data: {port_text!r}."
            ) from exc

        findings.append(finding)

    return findings


def _optional_attribute(element: ET.Element | None, name: str) -> str | None:
    """Return a nonempty XML attribute, or ``None`` when it is absent/empty."""
    if element is None:
        return None
    value = element.get(name)
    return value or None
