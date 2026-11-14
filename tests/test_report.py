import csv
import io

import pytest
from xmlbuilder import document, host, port

from netinv.diff import compare
from netinv.model import Host, NetinvError, Port, Scan
from netinv.parse import parse_xml
from netinv.report import diff_markdown, inventory_markdown, to_csv


def rows(text, delimiter=","):
    return list(csv.reader(io.StringIO(text), delimiter=delimiter))


def test_csv_has_one_row_per_port_and_one_row_for_a_host_without_port(scan_a):
    table = rows(to_csv(scan_a))
    assert table[0] == [
        "ip", "hostname", "mac", "vendor", "proto", "port", "service", "product", "version", "extrainfo"
    ]
    assert len(table) == 8  # en-tête + .2 (1 port) + .3 (aucun) + .20 (3 ports) + .50 (1) + .70 (1)
    assert table[1][:2] == ["192.0.2.2", ""]
    assert table[2] == ["192.0.2.3", "", "", "", "", "", "", "", "", ""]
    assert table[3][:6] == ["192.0.2.20", "web.example.net", "00:00:5E:00:53:20", "", "tcp", "22"]


def test_csv_delimiter(scan_a):
    text = to_csv(scan_a, ";")
    assert text.splitlines()[0].startswith("ip;hostname;")
    assert rows(text, ";") == rows(to_csv(scan_a))


@pytest.mark.parametrize("delimiter", ["", ";;", '"', "\n"])
def test_csv_invalid_delimiter(scan_a, delimiter):
    with pytest.raises(NetinvError, match="séparateur"):
        to_csv(scan_a, delimiter)


def test_csv_neutralises_spreadsheet_formulas():
    xml = document([host("10.0.0.5", [port(80, "http", "=HYPERLINK(\"http://x\",\"clic\")", "+1", "@SUM(A1)")])])
    cells = rows(to_csv(parse_xml(xml)))[1]
    assert cells[7] == "'=HYPERLINK(\"http://x\",\"clic\")"
    assert cells[8] == "'+1"
    assert cells[9] == "'@SUM(A1)"


@pytest.mark.parametrize("first", ["=", "+", "-", "@", "\t", "\r", "\n"])
def test_csv_neutralises_every_formula_prefix(first):
    scan = Scan(hosts=(Host(ip="10.0.0.5", ports=(Port("tcp", 80, product=first + "x"),)),))
    assert rows(to_csv(scan))[1][7] == "'" + first + "x"


def test_csv_ends_with_a_single_newline_and_no_carriage_return(scan_a):
    text = to_csv(scan_a)
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\r" not in text


def test_inventory_markdown(scan_a):
    text = inventory_markdown(scan_a)
    assert text.startswith("# Inventaire réseau\n")
    assert "- **Date du scan :** 2026-11-13 01:23:16 UTC" in text
    assert "- **Hôtes actifs :** 5" in text
    assert "- **Ports ouverts :** 6" in text
    assert "| 192.0.2.20 | web.example.net | 00:00:5E:00:53:20 | 22/tcp, 80/tcp, 443/tcp |" in text
    assert "### 192.0.2.20 (web.example.net)" in text
    assert "| 443/tcp | ssl/http | nginx | 1.24.0 |" in text
    assert "Aucun port ouvert détecté." in text
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_inventory_markdown_without_host():
    text = inventory_markdown(parse_xml(document([])))
    assert "Aucun hôte actif détecté." in text
    assert "## Vue d'ensemble" not in text


def test_markdown_escapes_untrusted_banners():
    xml = document([host("10.0.0.5", [port(80, "http", "a|b", "<script>alert(1)</script>", "x & y")])])
    text = inventory_markdown(parse_xml(xml))
    assert "a\\|b" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>" not in text


def test_vendor_is_shown_next_to_the_mac():
    xml = document([host("10.0.0.5", mac="B8:27:EB:12:34:56", vendor="Raspberry Pi Foundation")])
    assert "B8:27:EB:12:34:56 (Raspberry Pi Foundation)" in inventory_markdown(parse_xml(xml))


def test_diff_markdown_full(scan_a, scan_b):
    text = diff_markdown(compare(scan_a, scan_b), scan_a, scan_b, "a.xml", "b.xml")
    assert text.startswith("# Changements entre deux scans\n")
    assert "| Fichier | a.xml | b.xml |" in text
    assert (
        "**Résumé :** 1 nouvel hôte · 1 hôte disparu · 1 adresse IP modifiée · 2 ports ouverts · "
        "1 port fermé · 1 service modifié · 1 adresse MAC modifiée"
    ) in text
    for title in (
        "## Nouveaux hôtes",
        "## Ports nouvellement ouverts",
        "## Services modifiés",
        "## Adresses MAC modifiées",
        "## Adresses IP modifiées (même adresse MAC)",
        "## Hôtes disparus",
        "## Ports fermés",
    ):
        assert title in text
    assert "| 192.0.2.20 (web.example.net) | 443/tcp | nginx 1.24.0 (ssl/http) | nginx 1.26.0 (ssl/http) |" in text
    assert "| 00:00:5E:00:53:70 | 192.0.2.70 | 192.0.2.71 | — |" in text
    assert "Attention" not in text  # même commande Nmap des deux côtés
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_diff_markdown_without_change(scan_a):
    text = diff_markdown(compare(scan_a, scan_a), scan_a, scan_a, "a.xml", "a.xml")
    assert "**Résumé :** aucun changement" in text
    assert "Aucun changement détecté." in text
    assert "## Nouveaux hôtes" not in text


def test_diff_markdown_warns_when_commands_differ():
    old = parse_xml(document([host("10.0.0.5")], args="nmap -sV 10.0.0.5"))
    new = parse_xml(document([host("10.0.0.5")], args="nmap -sV -p 1-100 10.0.0.5"))
    text = diff_markdown(compare(old, new), old, new, "a.xml", "b.xml")
    assert "**Attention :**" in text


def test_diff_markdown_singular_and_plural():
    old = parse_xml(document([host("10.0.0.5")]))
    one = parse_xml(document([host("10.0.0.5", [port(22, "ssh")])]))
    two = parse_xml(document([host("10.0.0.5", [port(22, "ssh"), port(80, "http")])]))
    assert "**Résumé :** 1 port ouvert\n" in diff_markdown(compare(old, one), old, one, "a", "b")
    assert "**Résumé :** 2 ports ouverts\n" in diff_markdown(compare(old, two), old, two, "a", "b")
