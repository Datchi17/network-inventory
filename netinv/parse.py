"""Lecture du rapport XML produit par Nmap (option -oX)."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

from .model import Host, NetinvError, Port, Scan


def parse_file(path: str | Path) -> Scan:
    """Lit un fichier XML Nmap."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise NetinvError(f"lecture impossible : {path} ({exc.strerror or exc})") from exc
    return parse_xml(data)


def parse_xml(data: str | bytes) -> Scan:
    """Transforme un XML Nmap (texte ou octets) en objet Scan.

    Seuls les hôtes « up » sont gardés, et seuls les ports « open » : un port
    fermé ou filtré n'est pas une exposition. Les hôtes et les ports sont triés.
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NetinvError(f"XML illisible : {exc}") from exc
    if root.tag != "nmaprun":
        raise NetinvError("ce n'est pas un rapport XML de Nmap (balise <nmaprun> absente)")
    hosts = [host for node in root.findall("host") if (host := _parse_host(node)) is not None]
    hosts.sort(key=lambda host: host.sort_key)
    return Scan(
        hosts=tuple(hosts),
        start=_to_int(root.get("start"), "start"),
        nmap_version=root.get("version", ""),
        command=root.get("args", ""),
    )


def _to_int(value: str | None, what: str) -> int:
    if value is None or value == "":
        return 0
    try:
        return int(value)
    except ValueError:
        raise NetinvError(f"valeur numérique invalide pour {what} : « {value} »") from None


def _parse_host(node: ET.Element) -> Host | None:
    status = node.find("status")
    if status is not None and status.get("state") != "up":
        return None
    ip = mac = vendor = ""
    for address in node.findall("address"):
        kind, value = address.get("addrtype"), address.get("addr", "")
        if kind in ("ipv4", "ipv6") and not ip:
            try:
                ip = str(ipaddress.ip_address(value))
            except ValueError:
                raise NetinvError(f"adresse IP invalide dans le XML : « {value} »") from None
        elif kind == "mac" and not mac:
            mac, vendor = value.upper(), address.get("vendor", "")
    if not ip:
        return None
    names = [name.get("name", "") for name in node.findall("hostnames/hostname")]
    ports = [_parse_port(port) for port in node.findall("ports/port")]
    ports = [port for port in ports if port is not None]
    ports.sort(key=lambda port: port.key)
    return Host(
        ip=ip,
        hostname=next((name for name in names if name), ""),
        mac=mac,
        vendor=vendor,
        ports=tuple(ports),
    )


def _parse_port(node: ET.Element) -> Port | None:
    state = node.find("state")
    if state is None or state.get("state") != "open":
        return None
    service = node.find("service")
    info = service.attrib if service is not None else {}
    name = info.get("name", "")
    if info.get("tunnel") and name:
        name = f"{info['tunnel']}/{name}"  # comme Nmap : « ssl/http » = HTTPS
    return Port(
        proto=node.get("protocol", "tcp"),
        number=_to_int(node.get("portid"), "portid"),
        service=name,
        product=info.get("product", ""),
        version=info.get("version", ""),
        extrainfo=info.get("extrainfo", ""),
    )
