"""Structures de données : un scan contient des hôtes, un hôte contient des ports ouverts."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone


class NetinvError(Exception):
    """Erreur prévisible (fichier illisible, cible refusée...) : affichée sans traceback."""


def ip_sort_key(ip: str) -> tuple[int, int]:
    """Tri numérique : 10.0.0.2 avant 10.0.0.10 (le tri alphabétique ferait l'inverse)."""
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))


@dataclass(frozen=True)
class Port:
    proto: str
    number: int
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""

    @property
    def key(self) -> tuple[str, int]:
        """Identifie un port : (« tcp », 80)."""
        return (self.proto, self.number)

    @property
    def label(self) -> str:
        return f"{self.number}/{self.proto}"

    @property
    def signature(self) -> tuple[str, str, str]:
        """Ce qui sert à dire qu'un service a changé (extrainfo est volontairement ignoré)."""
        return (self.service, self.product, self.version)

    def describe(self) -> str:
        """Texte lisible : « nginx 1.24.0 (http) »."""
        name = " ".join(part for part in (self.product, self.version) if part)
        if name and self.service:
            return f"{name} ({self.service})"
        return name or self.service or "inconnu"


@dataclass(frozen=True)
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    ports: tuple[Port, ...] = ()

    @property
    def sort_key(self) -> tuple[int, int]:
        return ip_sort_key(self.ip)

    @property
    def title(self) -> str:
        """« 10.0.0.2 » ou « 10.0.0.2 (ctrl) »."""
        return f"{self.ip} ({self.hostname})" if self.hostname else self.ip


@dataclass(frozen=True)
class Scan:
    hosts: tuple[Host, ...]
    start: int = 0
    nmap_version: str = ""
    command: str = ""

    @property
    def started(self) -> str:
        """Date du scan en UTC, ou « inconnue »."""
        if self.start <= 0:
            return "inconnue"
        try:
            moment = datetime.fromtimestamp(self.start, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return "inconnue"
        return moment.strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def tool(self) -> str:
        return f"Nmap {self.nmap_version}" if self.nmap_version else "Nmap"

    @property
    def open_port_count(self) -> int:
        return sum(len(host.ports) for host in self.hosts)
