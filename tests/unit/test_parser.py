"""Unit tests for Nmap XML parsing into structured findings."""

import pytest

from safe_nmap.server.parser import NmapParseError, parse_nmap_xml


def test_parse_open_port_with_service_details():
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="8080">
            <state state="open"/>
            <service name="http" product="nginx" version="1.18.0"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    findings = parse_nmap_xml(xml)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.port == 8080
    assert finding.protocol == "tcp"
    assert finding.state == "open"
    assert finding.service == "http"
    assert finding.product == "nginx"
    assert finding.version == "1.18.0"


def test_parse_closed_port_without_service_element():
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="8081">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    findings = parse_nmap_xml(xml)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.state == "closed"
    assert finding.service is None
    assert finding.product is None
    assert finding.version is None


def test_parse_host_with_no_ports_returns_empty_list_not_closed():
    xml = "<nmaprun><host><ports></ports></host></nmaprun>"
    assert parse_nmap_xml(xml) == []


def test_parse_malformed_xml_raises_parse_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<nmaprun><host>")


def test_parse_wrong_root_element_raises_parse_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<unexpected></unexpected>")


def test_parse_port_missing_state_raises_parse_error():
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="8080"></port>
        </ports>
      </host>
    </nmaprun>
    """
    with pytest.raises(NmapParseError):
        parse_nmap_xml(xml)


def test_parse_port_with_invalid_port_number_raises_parse_error():
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="not-a-number">
            <state state="open"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    with pytest.raises(NmapParseError):
        parse_nmap_xml(xml)


def test_parse_service_with_missing_product_preserves_none():
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="8080">
            <state state="open"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    finding = parse_nmap_xml(xml)[0]
    assert finding.service == "http"
    assert finding.product is None
    assert finding.version is None
