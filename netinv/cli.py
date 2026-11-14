"""Ligne de commande : scan, report, diff."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .anonymize import anonymize
from .diff import compare
from .model import NetinvError
from .parse import parse_file, parse_xml
from .report import diff_markdown, inventory_markdown, to_csv
from .scan import build_command, run_nmap, validate_ports, validate_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netinv",
        description="Inventaire réseau avec Nmap et détection de changements. "
        "À utiliser uniquement sur ton propre réseau ou labo.",
    )
    parser.add_argument("--version", action="version", version=f"netinv {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="commande")

    scan = sub.add_parser("scan", help="lancer Nmap et enregistrer le XML")
    scan.add_argument("targets", nargs="+", metavar="CIBLE", help="adresse IPv4 ou réseau CIDR (ex. 192.168.1.0/24)")
    scan.add_argument("-o", "--output", help="fichier XML de sortie (défaut : scans/scan-DATE.xml)")
    scan.add_argument("-p", "--ports", help="ports à scanner (ex. 1-1024 ou 22,80) ; défaut : les 1000 plus courants")
    scan.add_argument("--no-version", action="store_true", help="pas de détection des versions (plus rapide)")
    scan.add_argument("--no-dns", action="store_true", help="pas de DNS inverse (plus rapide, mais pas de noms)")
    scan.add_argument("--sudo", action="store_true", help="lancer Nmap avec sudo (ARP et adresses MAC)")
    scan.add_argument("--allow-public", action="store_true", help="autoriser les adresses publiques (si à toi)")
    scan.add_argument("--force", action="store_true", help="écraser le fichier de sortie s'il existe")
    scan.add_argument("--timeout", type=int, default=1800, help="durée maximale du scan en secondes (défaut : 1800)")
    scan.add_argument("--nmap-bin", default="nmap", help="chemin de l'exécutable Nmap (défaut : nmap)")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="écrire un CSV et/ou un rapport Markdown à partir d'un scan")
    report.add_argument("scan", help="fichier XML d'un scan")
    report.add_argument("--csv", help="fichier CSV à écrire")
    report.add_argument("--md", help="rapport Markdown à écrire (sans --csv ni --md : affiché à l'écran)")
    report.add_argument("--delimiter", default=",", help="séparateur du CSV (défaut : virgule ; ';' pour Excel FR)")
    report.add_argument("--anonymize", action="store_true", help="remplacer adresses, noms et MAC par du fictif")
    report.set_defaults(func=cmd_report)

    diff = sub.add_parser("diff", help="comparer deux scans")
    diff.add_argument("old", help="scan de départ (XML)")
    diff.add_argument("new", help="scan plus récent (XML)")
    diff.add_argument("--md", help="rapport Markdown à écrire (sinon : affiché à l'écran)")
    diff.add_argument("--anonymize", action="store_true", help="remplacer adresses, noms et MAC par du fictif")
    diff.add_argument("--exit-code", action="store_true", help="code de sortie 1 s'il y a des changements")
    diff.set_defaults(func=cmd_diff)
    return parser


def _write_text(path: str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def cmd_scan(args: argparse.Namespace) -> int:
    targets = validate_targets(args.targets, allow_public=args.allow_public)
    ports = validate_ports(args.ports) if args.ports else None
    if args.output:
        output = Path(args.output)
    else:
        output = Path("scans") / f"scan-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.xml"
    if output.exists() and not args.force:
        raise NetinvError(f"{output} existe déjà : choisis un autre nom, ou ajoute --force pour l'écraser")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = build_command(targets, ports, not args.no_version, args.sudo, args.nmap_bin, not args.no_dns)
    print("Scan en cours : " + " ".join(command), file=sys.stderr)
    xml, warnings = run_nmap(command, args.timeout)
    scan = parse_xml(xml)  # vérifie que la sortie est bien un XML Nmap exploitable avant d'écrire
    if warnings:
        print(warnings, file=sys.stderr)
    output.write_bytes(xml)
    print(f"{len(scan.hosts)} hôte(s) actif(s), {scan.open_port_count} port(s) ouvert(s) -> {output}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scan = parse_file(args.scan)
    if args.anonymize:
        (scan,) = anonymize(scan)
    markdown = inventory_markdown(scan)
    csv_text = to_csv(scan, args.delimiter) if args.csv else None
    if not args.csv and not args.md:
        sys.stdout.write(markdown)
        return 0
    if csv_text is not None:
        _write_text(args.csv, csv_text)
        print(f"CSV écrit : {args.csv}")
    if args.md:
        _write_text(args.md, markdown)
        print(f"Rapport écrit : {args.md}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    old, new = parse_file(args.old), parse_file(args.new)
    if args.anonymize:
        old, new = anonymize(old, new)
    diff = compare(old, new)
    markdown = diff_markdown(diff, old, new, Path(args.old).name, Path(args.new).name)
    if args.md:
        _write_text(args.md, markdown)
        print(f"Rapport écrit : {args.md} ({diff.total} changement(s))")
    else:
        sys.stdout.write(markdown)
    return 1 if args.exit_code and not diff.is_empty else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (NetinvError, OSError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 2
