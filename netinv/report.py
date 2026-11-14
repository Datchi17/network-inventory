"""Production des rapports : CSV (inventaire) et Markdown (inventaire, différences)."""

from __future__ import annotations

import csv
import io

from .diff import Diff
from .model import Host, NetinvError, Scan

CSV_COLUMNS = ("ip", "hostname", "mac", "vendor", "proto", "port", "service", "product", "version", "extrainfo")


# --- CSV ---------------------------------------------------------------------------------------


def to_csv(scan: Scan, delimiter: str = ",") -> str:
    """Une ligne par port ouvert ; une ligne sans port pour un hôte qui n'en a aucun."""
    if len(delimiter) != 1 or delimiter in '"\r\n':
        raise NetinvError("le séparateur CSV doit être un seul caractère (virgule, point-virgule...)")
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for host in scan.hosts:
        head = [host.ip, host.hostname, host.mac, host.vendor]
        if not host.ports:
            writer.writerow([_cell(value) for value in head + [""] * 6])
        for port in host.ports:
            tail = [port.proto, str(port.number), port.service, port.product, port.version, port.extrainfo]
            writer.writerow([_cell(value) for value in head + tail])
    return buffer.getvalue()


def _cell(value: str) -> str:
    """Neutralise l'injection de formules : un tableur exécute une cellule qui commence par = + - @
    (ou par une tabulation ou un saut de ligne).

    Les bannières des services viennent du réseau, donc d'une source non fiable.
    """
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r", "\n") else value


# --- Markdown ----------------------------------------------------------------------------------


def _md(value: str) -> str:
    """Valeur sûre dans un tableau Markdown (même raison : la bannière n'est pas de confiance)."""
    text = " ".join(str(value).split())
    for old, new in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|")):
        text = text.replace(old, new)
    return text or "—"


def _mac(host: Host) -> str:
    return _md(f"{host.mac} ({host.vendor})" if host.mac and host.vendor else host.mac)


def _finish(lines: list[str]) -> str:
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines + [""]


def _host_rows(hosts: tuple[Host, ...]) -> list[list[str]]:
    return [
        [_md(h.ip), _md(h.hostname), _mac(h), _md(", ".join(p.label for p in h.ports))]
        for h in hosts
    ]


def inventory_markdown(scan: Scan) -> str:
    lines = [
        "# Inventaire réseau",
        "",
        f"- **Date du scan :** {scan.started}",
        f"- **Outil :** {_md(scan.tool)}",
        f"- **Hôtes actifs :** {len(scan.hosts)}",
        f"- **Ports ouverts :** {scan.open_port_count}",
        "",
    ]
    if not scan.hosts:
        return _finish(lines + ["Aucun hôte actif détecté.", ""])
    lines += ["## Vue d'ensemble", ""]
    lines += _table(["Adresse IP", "Nom", "MAC", "Ports ouverts"], _host_rows(scan.hosts))
    lines += ["## Détail par hôte", ""]
    for host in scan.hosts:
        lines += [f"### {_md(host.title)}", ""]
        if not host.ports:
            lines += ["Aucun port ouvert détecté.", ""]
            continue
        rows = [[p.label, _md(p.service), _md(p.product), _md(p.version)] for p in host.ports]
        lines += _table(["Port", "Service", "Produit", "Version"], rows)
    return _finish(lines)


def diff_markdown(diff: Diff, old: Scan, new: Scan, old_name: str, new_name: str) -> str:
    lines = [
        "# Changements entre deux scans",
        "",
        "| | Scan A (avant) | Scan B (après) |",
        "|---|---|---|",
        f"| Fichier | {_md(old_name)} | {_md(new_name)} |",
        f"| Date | {old.started} | {new.started} |",
        f"| Hôtes actifs | {len(old.hosts)} | {len(new.hosts)} |",
        f"| Ports ouverts | {old.open_port_count} | {new.open_port_count} |",
        "",
    ]
    if old.command and new.command and old.command != new.command:
        lines += [
            "> **Attention :** les deux scans n'ont pas été lancés avec la même commande Nmap. "
            "Une différence de cibles ou d'options peut produire des écarts qui ne viennent pas du réseau.",
            "",
        ]
    counts = [
        (len(diff.new_hosts), "nouvel hôte", "nouveaux hôtes"),
        (len(diff.gone_hosts), "hôte disparu", "hôtes disparus"),
        (len(diff.moved_hosts), "adresse IP modifiée", "adresses IP modifiées"),
        (len(diff.opened), "port ouvert", "ports ouverts"),
        (len(diff.closed), "port fermé", "ports fermés"),
        (len(diff.service_changes), "service modifié", "services modifiés"),
        (len(diff.mac_changes), "adresse MAC modifiée", "adresses MAC modifiées"),
    ]
    summary = [f"{n} {one if n == 1 else many}" for n, one, many in counts if n]
    lines += ["**Résumé :** " + (" · ".join(summary) if summary else "aucun changement"), ""]
    if diff.is_empty:
        return _finish(lines + ["Aucun changement détecté.", ""])

    if diff.new_hosts:
        lines += ["## Nouveaux hôtes", ""]
        lines += _table(["Adresse IP", "Nom", "MAC", "Ports ouverts"], _host_rows(diff.new_hosts))
    if diff.opened:
        lines += ["## Ports nouvellement ouverts", ""]
        rows = [[_md(e.host.title), e.port.label, _md(e.port.describe())] for e in diff.opened]
        lines += _table(["Hôte", "Port", "Service"], rows)
    if diff.service_changes:
        lines += ["## Services modifiés", ""]
        rows = [
            [_md(c.host.title), c.after.label, _md(c.before.describe()), _md(c.after.describe())]
            for c in diff.service_changes
        ]
        lines += _table(["Hôte", "Port", "Avant", "Après"], rows)
    if diff.mac_changes:
        lines += ["## Adresses MAC modifiées", ""]
        lines += [
            "Pour une même adresse IP, l'adresse MAC a changé. Causes possibles : machine ou carte réseau "
            "remplacée, pont ou réseau virtuel qui recalcule son MAC, ou usurpation (ARP spoofing). À vérifier.",
            "",
        ]
        rows = [[_md(c.host.title), _md(c.before), _md(c.after)] for c in diff.mac_changes]
        lines += _table(["Hôte", "MAC avant", "MAC après"], rows)
    if diff.moved_hosts:
        lines += ["## Adresses IP modifiées (même adresse MAC)", ""]
        rows = [[_md(m.after.mac), _md(m.before.ip), _md(m.after.ip), _md(m.after.hostname)] for m in diff.moved_hosts]
        lines += _table(["MAC", "IP avant", "IP après", "Nom"], rows)
    if diff.gone_hosts:
        lines += ["## Hôtes disparus", ""]
        lines += _table(["Adresse IP", "Nom", "MAC", "Ports ouverts (avant)"], _host_rows(diff.gone_hosts))
    if diff.closed:
        lines += ["## Ports fermés", ""]
        rows = [[_md(e.host.title), e.port.label, _md(e.port.describe())] for e in diff.closed]
        lines += _table(["Hôte", "Port", "Service (avant)"], rows)
    return _finish(lines)
