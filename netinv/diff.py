"""Comparaison de deux scans : hôtes nouveaux ou disparus, ports et services qui changent."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Host, Port, Scan


@dataclass(frozen=True)
class PortEvent:
    """Un port ouvert ou fermé, avec l'hôte concerné (tel qu'il est dans le 2e scan)."""

    host: Host
    port: Port


@dataclass(frozen=True)
class ServiceChange:
    host: Host
    before: Port
    after: Port


@dataclass(frozen=True)
class MacChange:
    host: Host
    before: str
    after: str


@dataclass(frozen=True)
class MovedHost:
    """Même adresse MAC, autre adresse IP (nouveau bail DHCP, par exemple)."""

    before: Host
    after: Host


@dataclass(frozen=True)
class Diff:
    new_hosts: tuple[Host, ...] = ()
    gone_hosts: tuple[Host, ...] = ()
    moved_hosts: tuple[MovedHost, ...] = ()
    opened: tuple[PortEvent, ...] = ()
    closed: tuple[PortEvent, ...] = ()
    service_changes: tuple[ServiceChange, ...] = ()
    mac_changes: tuple[MacChange, ...] = ()

    @property
    def total(self) -> int:
        return (
            len(self.new_hosts)
            + len(self.gone_hosts)
            + len(self.moved_hosts)
            + len(self.opened)
            + len(self.closed)
            + len(self.service_changes)
            + len(self.mac_changes)
        )

    @property
    def is_empty(self) -> bool:
        return self.total == 0


def compare(old: Scan, new: Scan) -> Diff:
    """Compare deux scans. Un hôte est identifié par son adresse IP."""
    before = {host.ip: host for host in old.hosts}
    after = {host.ip: host for host in new.hosts}
    appeared = [after[ip] for ip in after.keys() - before.keys()]
    vanished = [before[ip] for ip in before.keys() - after.keys()]

    moved = _match_moved(vanished, appeared)
    moved_old = {pair.before.ip for pair in moved}
    moved_new = {pair.after.ip for pair in moved}
    new_hosts = [host for host in appeared if host.ip not in moved_new]
    gone_hosts = [host for host in vanished if host.ip not in moved_old]

    # Les ports se comparent pour les hôtes présents dans les deux scans,
    # y compris ceux qui ont changé d'adresse IP (même MAC).
    pairs = [(before[ip], after[ip]) for ip in before.keys() & after.keys()]
    pairs += [(pair.before, pair.after) for pair in moved]

    opened: list[PortEvent] = []
    closed: list[PortEvent] = []
    services: list[ServiceChange] = []
    macs: list[MacChange] = []
    for host_a, host_b in pairs:
        ports_a = {port.key: port for port in host_a.ports}
        ports_b = {port.key: port for port in host_b.ports}
        opened += [PortEvent(host_b, ports_b[key]) for key in ports_b.keys() - ports_a.keys()]
        closed += [PortEvent(host_b, ports_a[key]) for key in ports_a.keys() - ports_b.keys()]
        for key in ports_a.keys() & ports_b.keys():
            if ports_a[key].signature != ports_b[key].signature:
                services.append(ServiceChange(host_b, ports_a[key], ports_b[key]))
        if host_a.mac and host_b.mac and host_a.mac != host_b.mac:
            macs.append(MacChange(host_b, host_a.mac, host_b.mac))

    return Diff(
        new_hosts=tuple(sorted(new_hosts, key=lambda host: host.sort_key)),
        gone_hosts=tuple(sorted(gone_hosts, key=lambda host: host.sort_key)),
        moved_hosts=tuple(sorted(moved, key=lambda pair: pair.after.sort_key)),
        opened=tuple(sorted(opened, key=_event_key)),
        closed=tuple(sorted(closed, key=_event_key)),
        service_changes=tuple(sorted(services, key=lambda c: (c.host.sort_key, c.after.key))),
        mac_changes=tuple(sorted(macs, key=lambda c: c.host.sort_key)),
    )


def _event_key(event: PortEvent) -> tuple:
    return (event.host.sort_key, event.port.key)


def _match_moved(vanished: list[Host], appeared: list[Host]) -> list[MovedHost]:
    """Associe un hôte disparu et un hôte apparu qui ont la même adresse MAC.

    On n'associe que s'il y en a exactement un de chaque côté : si plusieurs
    adresses IP partagent un même MAC (routeur, proxy ARP...), on ne devine pas.
    """
    gone_by_mac = _group_by_mac(vanished)
    new_by_mac = _group_by_mac(appeared)
    moved = []
    for mac, olds in gone_by_mac.items():
        news = new_by_mac.get(mac, [])
        if len(olds) == 1 and len(news) == 1:
            moved.append(MovedHost(olds[0], news[0]))
    return moved


def _group_by_mac(hosts: list[Host]) -> dict[str, list[Host]]:
    groups: dict[str, list[Host]] = {}
    for host in hosts:
        if host.mac:
            groups.setdefault(host.mac, []).append(host)
    return groups
