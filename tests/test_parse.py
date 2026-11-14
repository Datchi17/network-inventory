import pytest
from xmlbuilder import document, host, port

from netinv.model import NetinvError
from netinv.parse import parse_file, parse_xml


def test_hosts_are_sorted_numerically_and_down_hosts_are_ignored(scan_a):
    assert [h.ip for h in scan_a.hosts] == ["192.0.2.2", "192.0.2.3", "192.0.2.20", "192.0.2.50", "192.0.2.70"]


def test_hosthint_is_not_a_host(scan_a):
    assert "192.0.2.99" not in [h.ip for h in scan_a.hosts]


def test_host_fields(scan_a):
    web = next(h for h in scan_a.hosts if h.ip == "192.0.2.20")
    assert web.hostname == "web.example.net"
    assert web.mac == "00:00:5E:00:53:20"
    assert [p.label for p in web.ports] == ["22/tcp", "80/tcp", "443/tcp"]


def test_host_without_open_port_is_kept(scan_a):
    quiet = next(h for h in scan_a.hosts if h.ip == "192.0.2.3")
    assert quiet.ports == ()
    assert quiet.hostname == ""


def test_service_details(scan_a):
    ssh = next(h for h in scan_a.hosts if h.ip == "192.0.2.2").ports[0]
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13.5")
    assert ssh.extrainfo == "Ubuntu Linux; protocol 2.0"


def test_ssl_tunnel_is_visible_in_the_service_name(scan_a):
    web = next(h for h in scan_a.hosts if h.ip == "192.0.2.20")
    assert [p.service for p in web.ports] == ["ssh", "http", "ssl/http"]


def test_only_open_ports_are_kept():
    xml = document([host("10.0.0.5", [port(22, "ssh"), port(23, "telnet", state="closed"),
                                       port(25, "smtp", state="filtered"), port(53, "domain", state="open|filtered")])])
    assert [p.number for p in parse_xml(xml).hosts[0].ports] == [22]


def test_ports_are_sorted_and_tcp_comes_before_udp():
    xml = document([host("10.0.0.5", [port(161, "snmp", proto="udp"), port(443, "https"), port(22, "ssh")])])
    assert [p.label for p in parse_xml(xml).hosts[0].ports] == ["22/tcp", "443/tcp", "161/udp"]


def test_mac_is_uppercased_and_vendor_kept():
    xml = document([host("10.0.0.5", mac="b8:27:eb:12:34:56", vendor="Raspberry Pi Foundation")])
    found = parse_xml(xml).hosts[0]
    assert (found.mac, found.vendor) == ("B8:27:EB:12:34:56", "Raspberry Pi Foundation")


def test_ipv6_and_mixed_sorting():
    xml = document([host("2001:db8::10", addrtype="ipv6"), host("10.0.0.2"), host("2001:db8::2", addrtype="ipv6")])
    assert [h.ip for h in parse_xml(xml).hosts] == ["10.0.0.2", "2001:db8::2", "2001:db8::10"]


def test_ipv6_address_is_normalised():
    xml = document([host("2001:0DB8:0:0:0:0:0:1", addrtype="ipv6")])
    assert parse_xml(xml).hosts[0].ip == "2001:db8::1"


def test_scan_metadata(scan_a):
    assert scan_a.start == 1794532996
    assert scan_a.started == "2026-11-13 01:23:16 UTC"
    assert scan_a.nmap_version == "7.94SVN"
    assert scan_a.tool == "Nmap 7.94SVN"
    assert scan_a.command == "nmap -T4 -sV -oX - 192.0.2.0/24"
    assert scan_a.open_port_count == 6


def test_missing_start_date_is_reported_as_unknown():
    scan = parse_xml('<nmaprun version="7.94SVN"></nmaprun>')
    assert scan.hosts == ()
    assert scan.started == "inconnue"


def test_accepts_bytes_and_text(scan_a_xml):
    assert parse_xml(scan_a_xml.encode("utf-8")) == parse_xml(scan_a_xml)


def test_parse_file(xml_files, scan_a):
    assert parse_file(xml_files[0]) == scan_a


@pytest.mark.parametrize(
    "bad, message",
    [
        ("pas du xml", "XML illisible"),
        ("<autre/>", "pas un rapport XML de Nmap"),
        (document([host("pas-une-ip")]), "adresse IP invalide"),
        (document([host("10.0.0.5", [port("abc", "ssh")])]), "portid"),
        ('<nmaprun start="hier"></nmaprun>', "start"),
    ],
)
def test_invalid_input_raises_a_clear_error(bad, message):
    with pytest.raises(NetinvError, match=message):
        parse_xml(bad)


def test_missing_file_raises_a_clear_error(tmp_path):
    with pytest.raises(NetinvError, match="lecture impossible"):
        parse_file(tmp_path / "absent.xml")
