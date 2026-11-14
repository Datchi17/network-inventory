import ipaddress

import pytest
from xmlbuilder import document, host, port

from netinv.anonymize import anonymize
from netinv.diff import compare
from netinv.model import Host, NetinvError, Scan
from netinv.parse import parse_xml
from netinv.report import diff_markdown, inventory_markdown, to_csv

DOC_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
SECRETS = [
    "192.168.1.10", "192.168.1.2", "10.0.0.7", "192.168.1.0/24",
    "B8:27:EB", "AA:BB:CC", "Raspberry", "nas-salon", "routeur", "freebox",
]


@pytest.fixture
def real_scan():
    return parse_xml(
        document(
            [
                host("192.168.1.10", [port(22, "ssh", "OpenSSH", "9.6", "Linux; hostname=nas-salon")],
                     mac="B8:27:EB:12:34:56", vendor="Raspberry Pi Foundation", hostname="nas-salon.lan"),
                host("192.168.1.2", [port(80, "http")], mac="AA:BB:CC:DD:EE:FF", hostname="routeur.freebox.lan"),
                host("10.0.0.7"),
            ],
            args="nmap -sV 192.168.1.0/24 10.0.0.7",
        )
    )


def test_nothing_real_survives_in_any_output(real_scan):
    (anon,) = anonymize(real_scan)
    output = inventory_markdown(anon) + to_csv(anon) + repr(anon)
    for secret in SECRETS:
        assert secret not in output, secret


def test_values_are_replaced_by_documentation_values(real_scan):
    (anon,) = anonymize(real_scan)
    for found in anon.hosts:
        assert any(ipaddress.ip_address(found.ip) in net for net in DOC_NETWORKS)
        assert found.mac == "" or found.mac.startswith("00:00:5E:00:53:")
        assert found.hostname == "" or found.hostname.endswith(".example.net")
        assert found.vendor == ""
        assert all(p.extrainfo == "" for p in found.ports)


def test_numbering_follows_numeric_address_order(real_scan):
    (anon,) = anonymize(real_scan)
    assert [h.ip for h in anon.hosts] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert [h.hostname for h in anon.hosts] == ["", "host-01.example.net", "host-02.example.net"]
    assert [h.mac for h in anon.hosts] == ["", "00:00:5E:00:53:00", "00:00:5E:00:53:01"]


def test_same_real_value_gives_same_fake_value_in_both_scans(scan_a, scan_b):
    anon_a, anon_b = anonymize(scan_a, scan_b)
    fake = {h.ip for h in anon_a.hosts} & {h.ip for h in anon_b.hosts}
    real = {h.ip for h in scan_a.hosts} & {h.ip for h in scan_b.hosts}
    assert len(fake) == len(real) == 3  # .2, .3 et .20 sont dans les deux scans


def test_diff_keeps_its_shape_after_anonymization(scan_a, scan_b):
    before = compare(scan_a, scan_b)
    anon_a, anon_b = anonymize(scan_a, scan_b)
    after = compare(anon_a, anon_b)
    for field in ("new_hosts", "gone_hosts", "moved_hosts", "opened", "closed", "service_changes", "mac_changes"):
        assert len(getattr(after, field)) == len(getattr(before, field)), field


def test_commands_stay_equal_or_different(scan_a, scan_b):
    same_a, same_b = anonymize(scan_a, scan_b)
    assert same_a.command == same_b.command != ""
    other = parse_xml(document([host("10.0.0.5")], args="nmap -p 1-100 10.0.0.5"))
    diff_a, diff_b = anonymize(scan_a, other)
    assert diff_a.command != diff_b.command
    assert "Attention" in diff_markdown(compare(diff_a, diff_b), diff_a, diff_b, "a", "b")
    assert "10.0.0.5" not in diff_markdown(compare(diff_a, diff_b), diff_a, diff_b, "a", "b")


def test_result_is_deterministic(scan_a, scan_b):
    assert anonymize(scan_a, scan_b) == anonymize(scan_a, scan_b)


def test_input_scans_are_not_modified(real_scan):
    snapshot = repr(real_scan)
    anonymize(real_scan)
    assert repr(real_scan) == snapshot


def test_ipv4_capacity():
    hosts = tuple(Host(ip=f"10.0.{i // 250}.{i % 250 + 1}") for i in range(762))
    (anon,) = anonymize(Scan(hosts))
    assert anon.hosts[0].ip == "192.0.2.1"
    assert anon.hosts[253].ip == "192.0.2.254"
    assert anon.hosts[254].ip == "198.51.100.1"
    assert anon.hosts[761].ip == "203.0.113.254"
    assert len({h.ip for h in anon.hosts}) == 762
    with pytest.raises(NetinvError, match="trop d'adresses IPv4"):
        anonymize(Scan(hosts + (Host(ip="10.9.9.9"),)))


def test_ipv6_is_mapped_to_the_documentation_prefix():
    scan = Scan((Host(ip="fd00::2"), Host(ip="fd00::10")))
    (anon,) = anonymize(scan)
    assert [h.ip for h in anon.hosts] == ["2001:db8::1", "2001:db8::2"]


def test_mac_capacity():
    hosts = tuple(
        Host(ip=f"10.0.{i // 250}.{i % 250 + 1}", mac=f"02:00:00:00:{i // 256:02X}:{i % 256:02X}") for i in range(257)
    )
    with pytest.raises(NetinvError, match="trop d'adresses MAC"):
        anonymize(Scan(hosts))
    assert len(anonymize(Scan(hosts[:256]))[0].hosts) == 256
