import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from xmlbuilder import document, host, port

from netinv import cli
from netinv.cli import main
from netinv.model import NetinvError
from netinv.parse import parse_file

ROOT = Path(__file__).resolve().parent.parent
needs_nmap = pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap n'est pas installé")


@pytest.fixture
def private_files(tmp_path):
    """Deux scans avec de « vraies » adresses privées, pour vérifier l'anonymisation."""
    first = document([host("192.168.1.10", [port(22, "ssh")], mac="B8:27:EB:12:34:56", hostname="nas-salon.lan")])
    second = document(
        [
            host("192.168.1.10", [port(22, "ssh"), port(80, "http")], mac="B8:27:EB:12:34:56",
                 hostname="nas-salon.lan"),
            host("192.168.1.77"),
        ]
    )
    a, b = tmp_path / "a.xml", tmp_path / "b.xml"
    a.write_text(first, encoding="utf-8")
    b.write_text(second, encoding="utf-8")
    return a, b


def run(argv, capsys):
    code = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- report -------------------------------------------------------------------------------------


def test_report_prints_markdown_by_default(xml_files, capsys):
    code, out, _ = run(["report", xml_files[0]], capsys)
    assert code == 0
    assert out.startswith("# Inventaire réseau\n")


def test_report_writes_csv_and_markdown_and_creates_folders(xml_files, tmp_path, capsys):
    csv_path, md_path = tmp_path / "out" / "inv.csv", tmp_path / "out" / "deeper" / "inv.md"
    code, out, _ = run(["report", xml_files[0], "--csv", csv_path, "--md", md_path], capsys)
    assert code == 0
    assert csv_path.read_text(encoding="utf-8").startswith("ip,hostname,mac,")
    assert md_path.read_text(encoding="utf-8").startswith("# Inventaire réseau\n")
    assert f"CSV écrit : {csv_path}" in out and f"Rapport écrit : {md_path}" in out


def test_report_semicolon_delimiter(xml_files, tmp_path, capsys):
    csv_path = tmp_path / "inv.csv"
    assert run(["report", xml_files[0], "--csv", csv_path, "--delimiter", ";"], capsys)[0] == 0
    assert csv_path.read_text(encoding="utf-8").startswith("ip;hostname;mac;")


def test_report_invalid_delimiter_writes_nothing(xml_files, tmp_path, capsys):
    md_path = tmp_path / "inv.md"
    argv = ["report", xml_files[0], "--csv", tmp_path / "x.csv", "--md", md_path, "--delimiter", "ab"]
    code, _, err = run(argv, capsys)
    assert code == 2
    assert "erreur : le séparateur CSV" in err
    assert not md_path.exists() and not (tmp_path / "x.csv").exists()


def test_report_anonymize(private_files, tmp_path, capsys):
    md_path, csv_path = tmp_path / "inv.md", tmp_path / "inv.csv"
    assert run(["report", private_files[1], "--anonymize", "--md", md_path, "--csv", csv_path], capsys)[0] == 0
    for text in (md_path.read_text(encoding="utf-8"), csv_path.read_text(encoding="utf-8")):
        for secret in ("192.168.1", "B8:27", "nas-salon"):
            assert secret not in text
        assert "192.0.2.1" in text


def test_report_missing_file(tmp_path, capsys):
    code, out, err = run(["report", tmp_path / "absent.xml"], capsys)
    assert (code, out) == (2, "")
    assert err.startswith("erreur : lecture impossible")


def test_report_not_an_nmap_file(tmp_path, capsys):
    bad = tmp_path / "bad.xml"
    bad.write_text("<html></html>", encoding="utf-8")
    code, _, err = run(["report", bad], capsys)
    assert code == 2 and "pas un rapport XML de Nmap" in err


# --- diff ---------------------------------------------------------------------------------------


def test_diff_prints_markdown(xml_files, capsys):
    code, out, _ = run(["diff", *xml_files], capsys)
    assert code == 0  # sans --exit-code, des différences ne sont pas une erreur
    assert out.startswith("# Changements entre deux scans\n")
    assert "| Fichier | a.xml | b.xml |" in out


def test_diff_writes_a_file(xml_files, tmp_path, capsys):
    target = tmp_path / "reports" / "diff.md"
    code, out, _ = run(["diff", *xml_files, "--md", target], capsys)
    assert code == 0
    assert target.read_text(encoding="utf-8").startswith("# Changements entre deux scans\n")
    assert out == f"Rapport écrit : {target} (8 changement(s))\n"


def test_diff_exit_code(xml_files, capsys):
    assert run(["diff", *xml_files, "--exit-code"], capsys)[0] == 1
    assert run(["diff", xml_files[0], xml_files[0], "--exit-code"], capsys)[0] == 0
    assert run(["diff", xml_files[0], xml_files[0]], capsys)[0] == 0


def test_diff_anonymize(private_files, capsys):
    code, out, _ = run(["diff", *private_files, "--anonymize"], capsys)
    assert code == 0
    for secret in ("192.168.1", "B8:27", "nas-salon"):
        assert secret not in out
    assert "**Résumé :** 1 nouvel hôte · 1 port ouvert" in out


# --- scan (Nmap simulé) --------------------------------------------------------------------------


@pytest.fixture
def fake_nmap(monkeypatch, scan_a_xml):
    calls = []

    def fake(command, timeout):
        calls.append((command, timeout))
        return scan_a_xml.encode("utf-8"), ""

    monkeypatch.setattr(cli, "run_nmap", fake)
    return calls


def test_scan_writes_exactly_what_nmap_returned(fake_nmap, scan_a_xml, tmp_path, capsys):
    target = tmp_path / "scans" / "a.xml"
    code, out, err = run(["scan", "192.168.1.0/24", "-o", target], capsys)
    assert code == 0
    assert target.read_bytes() == scan_a_xml.encode("utf-8")
    assert out == f"5 hôte(s) actif(s), 6 port(s) ouvert(s) -> {target}\n"
    assert err.startswith("Scan en cours : nmap -T4 -sV -oX - 192.168.1.0/24")
    assert fake_nmap == [(["nmap", "-T4", "-sV", "-oX", "-", "192.168.1.0/24"], 1800)]


def test_scan_passes_the_options(fake_nmap, tmp_path, capsys):
    argv = ["scan", "10.0.0.1", "10.0.0.2", "-p", "22,80", "--no-version", "--no-dns", "--sudo", "--timeout", "60",
            "--nmap-bin", "/opt/nmap", "-o", tmp_path / "a.xml"]
    assert run(argv, capsys)[0] == 0
    assert fake_nmap == [(["sudo", "/opt/nmap", "-T4", "-n", "-p", "22,80", "-oX", "-", "10.0.0.1", "10.0.0.2"], 60)]


def test_scan_never_overwrites_without_force(fake_nmap, tmp_path, capsys):
    target = tmp_path / "a.xml"
    target.write_text("précieux", encoding="utf-8")
    code, _, err = run(["scan", "10.0.0.1", "-o", target], capsys)
    assert code == 2 and "existe déjà" in err
    assert target.read_text(encoding="utf-8") == "précieux"
    assert fake_nmap == []  # on n'a même pas lancé Nmap
    assert run(["scan", "10.0.0.1", "-o", target, "--force"], capsys)[0] == 0
    assert target.read_text(encoding="utf-8").startswith("<?xml")


def test_scan_refuses_public_addresses_without_running_nmap(fake_nmap, tmp_path, capsys):
    code, _, err = run(["scan", "8.8.8.8", "-o", tmp_path / "a.xml"], capsys)
    assert code == 2 and "pas dans un réseau privé" in err
    assert fake_nmap == [] and not (tmp_path / "a.xml").exists()
    assert run(["scan", "8.8.8.8", "--allow-public", "-o", tmp_path / "a.xml"], capsys)[0] == 0


def test_scan_refuses_bad_ports(fake_nmap, capsys):
    code, _, err = run(["scan", "10.0.0.1", "-p", "22;ls"], capsys)
    assert code == 2 and "ports invalides" in err and fake_nmap == []


def test_scan_does_not_write_a_file_when_the_output_is_not_nmap_xml(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "run_nmap", lambda command, timeout: (b"n'importe quoi", ""))
    code, _, err = run(["scan", "10.0.0.1", "-o", tmp_path / "a.xml"], capsys)
    assert code == 2 and "XML illisible" in err
    assert not (tmp_path / "a.xml").exists()


def test_scan_reports_nmap_failure(monkeypatch, tmp_path, capsys):
    def failing(command, timeout):
        raise NetinvError("Nmap a échoué (code 1) : boom")

    monkeypatch.setattr(cli, "run_nmap", failing)
    code, _, err = run(["scan", "10.0.0.1", "-o", tmp_path / "a.xml"], capsys)
    assert code == 2 and "erreur : Nmap a échoué (code 1) : boom" in err


def test_scan_forwards_nmap_warnings(monkeypatch, scan_a_xml, tmp_path, capsys):
    monkeypatch.setattr(cli, "run_nmap", lambda command, timeout: (scan_a_xml.encode("utf-8"), "Warning: truc"))
    _, _, err = run(["scan", "10.0.0.1", "-o", tmp_path / "a.xml"], capsys)
    assert "Warning: truc" in err


def test_scan_default_file_name(fake_nmap, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "10.0.0.1"], capsys)[0] == 0
    created = list((tmp_path / "scans").glob("scan-*.xml"))
    assert len(created) == 1
    assert created[0].name.endswith(".xml") and len(created[0].name) == len("scan-20261113-012316.xml")


# --- ligne de commande -------------------------------------------------------------------------


def test_no_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as stop:
        main([])
    assert stop.value.code == 2


def test_version(capsys):
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0
    assert capsys.readouterr().out == "netinv 1.0.0\n"


def test_module_entry_point():
    done = subprocess.run([sys.executable, "-m", "netinv", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert (done.returncode, done.stdout) == (0, "netinv 1.0.0\n")


# --- vrai Nmap, sur la boucle locale (aucun réseau externe, aucun droit spécial) ----------------------


class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
        try:
            self.request.recv(1024)
        except OSError:
            pass


class BannerServer(socketserver.ThreadingTCPServer):
    """Faux serveur SSH sur 127.0.0.1 : il répond avec une bannière OpenSSH, Nmap l'identifie."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), BannerHandler, bind_and_activate=False)
        self.server_bind()  # le port est réservé mais le serveur n'écoute pas encore : port « fermé »
        self.port = self.server_address[1]
        self.thread = None

    def start(self):
        self.server_activate()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.thread is not None:
            self.shutdown()
            self.thread = None
        self.server_close()


@pytest.fixture
def make_server():
    created = []

    def make():
        server = BannerServer()
        created.append(server)
        return server

    yield make
    for server in created:
        server.stop()


@needs_nmap
def test_real_nmap_finds_an_open_port(tmp_path, capsys):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    try:
        number = listener.getsockname()[1]
        code, _, _ = run(["scan", "127.0.0.1", "-p", number, "--no-version", "-o", tmp_path / "real.xml"], capsys)
    finally:
        listener.close()
    assert code == 0
    scan = parse_file(tmp_path / "real.xml")
    assert [h.ip for h in scan.hosts] == ["127.0.0.1"]
    assert [p.number for p in scan.hosts[0].ports] == [number]
    assert scan.nmap_version != "" and scan.start > 0


@needs_nmap
def test_real_nmap_identifies_the_service(tmp_path, make_server, capsys):
    server = make_server()
    server.start()
    assert run(["scan", "127.0.0.1", "-p", server.port, "-o", tmp_path / "real.xml"], capsys)[0] == 0
    found = parse_file(tmp_path / "real.xml").hosts[0].ports[0]
    assert (found.service, found.product, found.version) == ("ssh", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13.5")


@needs_nmap
def test_real_scans_then_diff(tmp_path, make_server, capsys):
    one, two = make_server(), make_server()
    ports = f"{one.port},{two.port}"
    one.start()
    assert run(["scan", "127.0.0.1", "-p", ports, "-o", tmp_path / "a.xml"], capsys)[0] == 0
    one.stop()  # le port de `one` se ferme...
    two.start()  # ...et celui de `two` s'ouvre
    assert run(["scan", "127.0.0.1", "-p", ports, "-o", tmp_path / "b.xml"], capsys)[0] == 0
    assert run(["scan", "127.0.0.1", "-p", ports, "-o", tmp_path / "c.xml"], capsys)[0] == 0

    code, out, _ = run(["diff", tmp_path / "a.xml", tmp_path / "b.xml", "--exit-code"], capsys)
    assert code == 1
    assert "**Résumé :** 1 port ouvert · 1 port fermé" in out
    assert f"| {two.port}/tcp | OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (ssh) |" in out
    assert f"| {one.port}/tcp | OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (ssh) |" in out

    code, out, _ = run(["diff", tmp_path / "b.xml", tmp_path / "c.xml", "--exit-code"], capsys)
    assert code == 0 and "aucun changement" in out  # deux vrais scans identiques : aucune différence
