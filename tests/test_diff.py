from dataclasses import replace

from xmlbuilder import document, host, port

from netinv.diff import compare
from netinv.parse import parse_xml


def labels(events):
    return [(e.host.ip, e.port.label) for e in events]


def test_full_scenario(scan_a, scan_b):
    diff = compare(scan_a, scan_b)
    assert [h.ip for h in diff.new_hosts] == ["192.0.2.60"]
    assert [h.ip for h in diff.gone_hosts] == ["192.0.2.50"]
    assert [(m.before.ip, m.after.ip) for m in diff.moved_hosts] == [("192.0.2.70", "192.0.2.71")]
    assert labels(diff.opened) == [("192.0.2.20", "8080/tcp"), ("192.0.2.71", "8080/tcp")]
    assert labels(diff.closed) == [("192.0.2.20", "80/tcp")]
    assert [(c.host.ip, c.after.label, c.before.version, c.after.version) for c in diff.service_changes] == [
        ("192.0.2.20", "443/tcp", "1.24.0", "1.26.0")
    ]
    assert [(c.host.ip, c.before, c.after) for c in diff.mac_changes] == [
        ("192.0.2.2", "00:00:5E:00:53:02", "00:00:5E:00:53:99")
    ]
    assert diff.total == 8
    assert not diff.is_empty


def test_identical_scans_have_no_difference(scan_a):
    diff = compare(scan_a, scan_a)
    assert diff.is_empty
    assert diff.total == 0


def test_the_other_way_round_swaps_new_and_gone(scan_a, scan_b):
    forward, backward = compare(scan_a, scan_b), compare(scan_b, scan_a)
    assert backward.new_hosts == forward.gone_hosts
    assert backward.gone_hosts == forward.new_hosts
    assert labels(backward.opened) == labels(forward.closed) == [("192.0.2.20", "80/tcp")]
    assert [(m.before.ip, m.after.ip) for m in backward.moved_hosts] == [("192.0.2.71", "192.0.2.70")]


def test_ports_of_a_new_host_are_not_reported_as_opened(scan_a, scan_b):
    diff = compare(scan_a, scan_b)
    assert "192.0.2.60" not in [e.host.ip for e in diff.opened]
    assert [p.label for p in diff.new_hosts[0].ports] == ["3389/tcp"]


def test_moved_host_still_gets_its_ports_compared(scan_a, scan_b):
    diff = compare(scan_a, scan_b)
    assert ("192.0.2.71", "8080/tcp") in labels(diff.opened)


def test_host_that_loses_all_its_ports_is_not_gone():
    old = parse_xml(document([host("10.0.0.5", [port(22, "ssh")])]))
    new = parse_xml(document([host("10.0.0.5")]))
    diff = compare(old, new)
    assert diff.gone_hosts == ()
    assert labels(diff.closed) == [("10.0.0.5", "22/tcp")]


def test_extrainfo_change_is_not_a_service_change():
    old = parse_xml(document([host("10.0.0.5", [port(80, "http", "nginx", "1.24.0", "Ubuntu")])]))
    new = parse_xml(document([host("10.0.0.5", [port(80, "http", "nginx", "1.24.0", "Debian")])]))
    assert compare(old, new).is_empty


def test_missing_mac_in_one_scan_is_not_a_mac_change():
    old = parse_xml(document([host("10.0.0.5", mac="00:00:5E:00:53:01")]))
    new = parse_xml(document([host("10.0.0.5")]))
    assert compare(old, new).mac_changes == ()


def test_shared_mac_is_not_matched_when_ambiguous():
    old = parse_xml(document([host("10.0.0.5", mac="00:00:5E:00:53:01"), host("10.0.0.6", mac="00:00:5E:00:53:01")]))
    new = parse_xml(document([host("10.0.0.9", mac="00:00:5E:00:53:01")]))
    diff = compare(old, new)
    assert diff.moved_hosts == ()
    assert [h.ip for h in diff.gone_hosts] == ["10.0.0.5", "10.0.0.6"]
    assert [h.ip for h in diff.new_hosts] == ["10.0.0.9"]


def test_without_mac_a_changed_address_is_gone_plus_new():
    old = parse_xml(document([host("10.0.0.5", [port(22, "ssh")])]))
    new = parse_xml(document([host("10.0.0.9", [port(22, "ssh")])]))
    diff = compare(old, new)
    assert diff.moved_hosts == ()
    assert [h.ip for h in diff.gone_hosts] == ["10.0.0.5"]
    assert [h.ip for h in diff.new_hosts] == ["10.0.0.9"]


def test_results_are_sorted_numerically():
    old = parse_xml(document([host("10.0.0.1")]))
    new = parse_xml(document([host("10.0.0.1"), host("10.0.0.100"), host("10.0.0.20"), host("10.0.0.3")]))
    assert [h.ip for h in compare(old, new).new_hosts] == ["10.0.0.3", "10.0.0.20", "10.0.0.100"]


def test_scans_with_different_start_dates_still_compare(scan_a):
    later = replace(scan_a, start=scan_a.start + 3600)
    assert compare(scan_a, later).is_empty
