"""Lancer Nmap en sécurité : cibles validées, commande construite sans shell."""

from __future__ import annotations

import ipaddress
import re
import subprocess

from .model import NetinvError

# Seuls ces réseaux sont acceptés sans --allow-public : réseaux privés (RFC 1918),
# espace partagé 100.64.0.0/10 (CGNAT, Tailscale...), boucle locale et lien local.
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)
MAX_ADDRESSES = 65536  # un /16 au plus : une faute de frappe ne doit pas lancer un scan géant
TARGET_RE = re.compile(r"[0-9.]+(/[0-9]{1,2})?")
PORTS_RE = re.compile(r"[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*")


def validate_targets(targets: list[str], allow_public: bool = False) -> list[str]:
    """Accepte uniquement des adresses IPv4 ou des réseaux CIDR, et refuse les réseaux publics."""
    if not targets:
        raise NetinvError("aucune cible : donne au moins une adresse IP ou un réseau (ex. 192.168.1.0/24)")
    for target in targets:
        network = None
        if TARGET_RE.fullmatch(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                pass
        if network is None:
            raise NetinvError(
                f"cible invalide : « {target} » (attendu : adresse IPv4 ou réseau CIDR, ex. 192.168.1.0/24)"
            )
        if network.num_addresses > MAX_ADDRESSES:
            raise NetinvError(f"réseau trop grand : {target} (maximum {MAX_ADDRESSES} adresses, soit un /16)")
        if not allow_public and not any(network.subnet_of(local) for local in LOCAL_NETWORKS):
            raise NetinvError(
                f"{target} n'est pas dans un réseau privé : refusé. Scanne uniquement ce qui t'appartient. "
                "Si c'est le cas (ex. ton serveur), ajoute --allow-public."
            )
    return list(targets)


def validate_ports(spec: str) -> str:
    """Accepte « 22 », « 1-1024 », « 22,80,8000-8100 » ; refuse tout le reste."""
    if not PORTS_RE.fullmatch(spec):
        raise NetinvError(f"ports invalides : « {spec} » (attendu : 22 ou 1-1024 ou 22,80,8000-8100)")
    for part in spec.split(","):
        low, _, high = part.partition("-")
        first, last = int(low), int(high or low)
        if not 1 <= first <= last <= 65535:
            raise NetinvError(f"ports invalides : « {part} » (les ports vont de 1 à 65535, dans l'ordre)")
    return spec


def build_command(
    targets: list[str],
    ports: str | None = None,
    version_detection: bool = True,
    sudo: bool = False,
    nmap_bin: str = "nmap",
    resolve_names: bool = True,
) -> list[str]:
    """Construit la commande sous forme de liste (jamais de shell, donc pas d'injection possible).

    -oX - : le XML sort sur la sortie standard et c'est notre programme qui écrit le fichier
    (avec sudo, un fichier écrit par Nmap appartiendrait à root).
    On n'utilise PAS --open : il cache les hôtes sans port ouvert, qui sembleraient « disparus ».
    """
    command = ["sudo"] if sudo else []
    command += [nmap_bin, "-T4"]
    if not resolve_names:
        command.append("-n")  # pas de DNS inverse : plus rapide, et les adresses du réseau ne sont pas envoyées au DNS
    if version_detection:
        command.append("-sV")
    if ports:
        command += ["-p", ports]
    command += ["-oX", "-"]
    return command + targets


def run_nmap(command: list[str], timeout: int = 1800) -> tuple[bytes, str]:
    """Lance Nmap ; renvoie (XML en octets, avertissements éventuels)."""
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise NetinvError(
            f"commande introuvable : {exc.filename} (Nmap est-il installé ? sudo apt install nmap)"
        ) from exc
    except subprocess.TimeoutExpired:
        raise NetinvError(f"Nmap n'a pas fini en {timeout} s : scan abandonné") from None
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        raise NetinvError(f"Nmap a échoué (code {result.returncode}) : {stderr or 'aucun message'}")
    return result.stdout, stderr
