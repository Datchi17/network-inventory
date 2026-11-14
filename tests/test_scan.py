import subprocess

import pytest

from netinv import scan as scan_module
from netinv.model import NetinvError
from netinv.scan import build_command, run_nmap, validate_ports, validate_targets


@pytest.mark.parametrize(
    "target",
    ["192.168.1.0/24", "10.1.2.3", "172.16.5.0/24", "172.31.255.255", "100.64.1.1", "127.0.0.1",
     "169.254.1.1", "192.168.1.5/24", "10.0.0.0/16"],
)
def test_local_targets_are_accepted(target):
    assert validate_targets([target]) == [target]


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "1.1.1.0/24", "172.32.0.1", "172.15.255.255", "192.169.0.1", "11.0.0.1", "100.128.0.1",
     "0.0.0.0", "255.255.255.255", "192.0.2.1"],
)
def test_public_targets_are_refused(target):
    with pytest.raises(NetinvError, match="pas dans un réseau privé"):
        validate_targets([target])


def test_one_public_target_among_private_ones_refuses_everything():
    with pytest.raises(NetinvError, match="8.8.8.8"):
        validate_targets(["10.0.0.1", "8.8.8.8"])


def test_allow_public_is_an_explicit_opt_in():
    assert validate_targets(["8.8.8.8"], allow_public=True) == ["8.8.8.8"]


@pytest.mark.parametrize(
    "target",
    ["", "-sV", "scanme.nmap.org", "10.0.0", "10.0.0.256", "10.0.0.0/33", "10.0.0.1-50", "10.0.0.1,2",
     "::1", "fe80::1", "10.0.0.0/255.255.255.0", "10.0.0.1; rm -rf /", " 10.0.0.1", "10.0.0.1\n", "10.0.0.01"],
)
def test_invalid_targets_are_refused(target):
    with pytest.raises(NetinvError, match="cible invalide"):
        validate_targets([target])


@pytest.mark.parametrize("target", ["10.0.0.0/15", "10.0.0.0/8", "192.168.0.0/15", "172.0.0.0/11", "0.0.0.0/0"])
def test_too_large_network_is_refused(target):
    # Un réseau qui contient à la fois du privé et du public est forcément plus grand qu'un /16 :
    # la limite de taille l'arrête avant même le contrôle « privé ».
    with pytest.raises(NetinvError, match="trop grand"):
        validate_targets([target])


def test_no_target_is_refused():
    with pytest.raises(NetinvError, match="aucune cible"):
        validate_targets([])


@pytest.mark.parametrize("spec", ["22", "1-1024", "22,80,8000-8100", "65535", "1-65535"])
def test_valid_ports(spec):
    assert validate_ports(spec) == spec


@pytest.mark.parametrize(
    "spec", ["", "0", "65536", "80-22", "22,", ",22", "22-", "-22", "a", "22;ls", "1-2-3", "100000", "0-10", " 22"]
)
def test_invalid_ports(spec):
    with pytest.raises(NetinvError, match="ports invalides"):
        validate_ports(spec)


def test_default_command():
    assert build_command(["10.0.0.0/24"]) == ["nmap", "-T4", "-sV", "-oX", "-", "10.0.0.0/24"]


def test_command_with_every_option():
    command = build_command(
        ["10.0.0.1", "10.0.0.2"],
        ports="22,80",
        version_detection=False,
        sudo=True,
        nmap_bin="/opt/nmap",
        resolve_names=False,
    )
    assert command == ["sudo", "/opt/nmap", "-T4", "-n", "-p", "22,80", "-oX", "-", "10.0.0.1", "10.0.0.2"]


def test_command_never_uses_the_open_option():
    # --open cacherait les hôtes sans port ouvert : ils sembleraient « disparus » d'un scan à l'autre.
    assert "--open" not in build_command(["10.0.0.1"], ports="1-100", sudo=True)


class Recorder:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.error:
            raise self.error
        return self.result


def test_run_nmap_returns_xml_and_warnings(monkeypatch):
    recorder = Recorder(subprocess.CompletedProcess(["nmap"], 0, stdout=b"<nmaprun/>", stderr=b"Warning: truc\n"))
    monkeypatch.setattr(scan_module.subprocess, "run", recorder)
    assert run_nmap(["nmap", "-oX", "-", "10.0.0.1"], timeout=5) == (b"<nmaprun/>", "Warning: truc")
    command, kwargs = recorder.calls[0]
    assert command == ["nmap", "-oX", "-", "10.0.0.1"]
    assert kwargs["timeout"] == 5 and kwargs["capture_output"] is True
    assert "shell" not in kwargs  # jamais de shell


def test_run_nmap_failure(monkeypatch):
    recorder = Recorder(subprocess.CompletedProcess(["nmap"], 1, stdout=b"", stderr=b"boom"))
    monkeypatch.setattr(scan_module.subprocess, "run", recorder)
    with pytest.raises(NetinvError, match="code 1.*boom"):
        run_nmap(["nmap"])


def test_run_nmap_not_installed(monkeypatch):
    monkeypatch.setattr(scan_module.subprocess, "run", Recorder(error=FileNotFoundError(2, "No such file", "nmap")))
    with pytest.raises(NetinvError, match="introuvable : nmap"):
        run_nmap(["nmap"])


def test_run_nmap_timeout(monkeypatch):
    monkeypatch.setattr(scan_module.subprocess, "run", Recorder(error=subprocess.TimeoutExpired("nmap", 3)))
    with pytest.raises(NetinvError, match="pas fini en 3 s"):
        run_nmap(["nmap"], timeout=3)
