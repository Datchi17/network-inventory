"""Anonymisation : adresses, noms et MAC remplacés par des valeurs réservées à la documentation."""

from __future__ import annotations

import ipaddress
from dataclasses import replace

from .model import Host, NetinvError, Scan

IPV4_BLOCKS = ("192.0.2", "198.51.100", "203.0.113")  # réservés à la documentation (RFC 5737)
IPV4_PER_BLOCK = 254
IPV6_BASE = ipaddress.IPv6Address("2001:db8::")  # idem (RFC 3849)
MAC_PREFIX = "00:00:5E:00:53"  # idem (RFC 7042) : 256 adresses
MAC_MAX = 256


def anonymize(*scans: Scan) -> tuple[Scan, ...]:
    """Anonymise plusieurs scans avec la MÊME correspondance (même vraie adresse, même fausse).

    C'est indispensable pour une comparaison : si l'hôte X devenait .1 dans un
    scan et .2 dans l'autre, le rapport de différences serait faux.
    On supprime aussi : le fabricant (déduit du MAC), extrainfo (peut contenir des noms
    de machines) et la ligne de commande Nmap (elle contient les vraies adresses).
    """
    hosts = sorted((host for scan in scans for host in scan.hosts), key=lambda host: host.sort_key)
    ip_map = _map_ips([host.ip for host in hosts])
    mac_map = _map_in_order([host.mac for host in hosts], _fake_mac)
    name_map = _map_in_order([host.hostname for host in hosts], lambda n: f"host-{n + 1:02d}.example.net")
    command_map = _map_in_order([scan.command for scan in scans], lambda n: f"commande Nmap n°{n + 1}")

    def convert(host: Host) -> Host:
        return replace(
            host,
            ip=ip_map[host.ip],
            hostname=name_map.get(host.hostname, ""),
            mac=mac_map.get(host.mac, ""),
            vendor="",
            ports=tuple(replace(port, extrainfo="") for port in host.ports),
        )

    result = []
    for scan in scans:
        converted = sorted((convert(host) for host in scan.hosts), key=lambda host: host.sort_key)
        result.append(replace(scan, hosts=tuple(converted), command=command_map.get(scan.command, "")))
    return tuple(result)


def _map_in_order(values: list[str], make) -> dict[str, str]:
    """Numérote les valeurs non vides dans l'ordre où on les rencontre."""
    mapping: dict[str, str] = {}
    for value in values:
        if value and value not in mapping:
            mapping[value] = make(len(mapping))
    return mapping


def _fake_mac(index: int) -> str:
    if index >= MAC_MAX:
        raise NetinvError(f"trop d'adresses MAC à anonymiser (maximum {MAC_MAX})")
    return f"{MAC_PREFIX}:{index:02X}"


def _map_ips(ips: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    counters = {4: 0, 6: 0}
    for ip in ips:  # déjà triées : la 1re adresse devient .1, etc.
        if ip in mapping:
            continue
        version = ipaddress.ip_address(ip).version
        index = counters[version]
        counters[version] += 1
        if version == 4:
            block, offset = divmod(index, IPV4_PER_BLOCK)
            if block >= len(IPV4_BLOCKS):
                maximum = IPV4_PER_BLOCK * len(IPV4_BLOCKS)
                raise NetinvError(f"trop d'adresses IPv4 à anonymiser (maximum {maximum})")
            mapping[ip] = f"{IPV4_BLOCKS[block]}.{offset + 1}"
        else:
            mapping[ip] = str(IPV6_BASE + index + 1)
    return mapping
