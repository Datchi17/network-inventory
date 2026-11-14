import pytest
from xmlbuilder import document, host, port

from netinv.parse import parse_xml

SSH = dict(service="ssh", product="OpenSSH", version="9.6p1 Ubuntu 3ubuntu13.5", extrainfo="Ubuntu Linux; protocol 2.0")
NGINX = dict(service="http", product="nginx", version="1.24.0", extrainfo="Ubuntu")
PYTHON_HTTP = dict(service="http", product="SimpleHTTPServer", version="0.6", extrainfo="Python 3.12.3")


@pytest.fixture
def scan_a_xml():
    """Scan de départ. Les hôtes sont volontairement dans le désordre (.20 avant .2)."""
    return document(
        [
            host("192.0.2.20", [port(22, **SSH), port(80, **NGINX), port(443, tunnel="ssl", **NGINX)],
                 mac="00:00:5E:00:53:20", hostname="web.example.net"),
            host("192.0.2.2", [port(22, **SSH)], mac="00:00:5E:00:53:02"),
            host("192.0.2.3"),
            host("192.0.2.4", state="down"),
            host("192.0.2.50", [port(3389, "ms-wbt-server", "Microsoft Terminal Services")], mac="00:00:5E:00:53:50"),
            host("192.0.2.70", [port(22, **SSH)], mac="00:00:5E:00:53:70"),
        ],
        start=1794532996,
    )


@pytest.fixture
def scan_b_xml():
    """Scan suivant : port 80 fermé, 8080 ouvert, nginx mis à jour sur 443, MAC changé en .2,
    .50 disparu, .60 nouveau, .70 devenu .71 (même MAC)."""
    new_nginx = dict(NGINX, version="1.26.0")
    return document(
        [
            host("192.0.2.20", [port(22, **SSH), port(443, tunnel="ssl", **new_nginx), port(8080, **PYTHON_HTTP)],
                 mac="00:00:5E:00:53:20", hostname="web.example.net"),
            host("192.0.2.2", [port(22, **SSH)], mac="00:00:5E:00:53:99"),
            host("192.0.2.3"),
            host("192.0.2.4", state="down"),
            host("192.0.2.60", [port(3389, "ms-wbt-server", "Microsoft Terminal Services")], mac="00:00:5E:00:53:60"),
            host("192.0.2.71", [port(22, **SSH), port(8080, **PYTHON_HTTP)], mac="00:00:5E:00:53:70"),
        ],
        start=1794533300,
    )


@pytest.fixture
def scan_a(scan_a_xml):
    return parse_xml(scan_a_xml)


@pytest.fixture
def scan_b(scan_b_xml):
    return parse_xml(scan_b_xml)


@pytest.fixture
def xml_files(tmp_path, scan_a_xml, scan_b_xml):
    """Les deux scans écrits sur disque : (chemin A, chemin B)."""
    path_a, path_b = tmp_path / "a.xml", tmp_path / "b.xml"
    path_a.write_text(scan_a_xml, encoding="utf-8")
    path_b.write_text(scan_b_xml, encoding="utf-8")
    return path_a, path_b
