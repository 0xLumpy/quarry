"""Shared pytest fixtures + the offline network-deny guard for the Quarry CI.

Two layers enforce "offline CI makes no network call" (C18):

1. A SESSION guard installed in ``pytest_configure`` when ``QUARRY_OFFLINE_CI`` is set (the CI workflow
   sets it). Because it is installed BEFORE collection, it also covers IMPORT-TIME network — e.g.
   ``netguard._own_ips()`` runs a ``getaddrinfo`` + UDP connect at import; both are try/except-swallowed,
   so the block is safe (the module still imports, ``_OWN_IPS`` is just empty, which no offline test needs).
2. A per-test AUTOUSE fixture for local dev runs (no env var), so plain ``pytest`` still blocks runtime
   network for every test not marked ``live``/``integration``.

Both use the same ``_BLOCKERS`` set, which covers sockets, resolver helpers, UDP, AND subprocess — a
scanner launched via ``subprocess``/``exec_tool`` would otherwise get normal network despite the socket
patches (they only affect the pytest process, not a child).
"""
from __future__ import annotations

import socket
import subprocess

import pytest


class NetworkDenied(RuntimeError):
    """Raised when an offline test attempts a real network connection or spawns a subprocess."""


def _blocked(*a, **k):
    raise NetworkDenied("offline test attempted network/subprocess (mark it `live`/`integration` if it "
                        "genuinely needs one)")


# (target-object, attribute) pairs to patch. Patch the CONNECT/RESOLVE/SEND entry points and subprocess
# spawn — NOT socket.socket itself (replacing the class breaks `ssl.SSLSocket(socket.socket)` subclassing).
def _blockers():
    return [
        (socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
        (socket, "create_connection"), (socket, "getaddrinfo"),
        (socket, "gethostbyname"), (socket, "gethostbyname_ex"),
        (subprocess, "Popen"), (subprocess, "run"),
    ]


# ── layer 1: session guard (CI), installed before collection so import-time network is covered ──
_saved: list = []


def pytest_configure(config):
    import os
    if not os.environ.get("QUARRY_OFFLINE_CI"):
        return
    for obj, attr in _blockers():
        _saved.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, _blocked)


def pytest_unconfigure(config):
    for obj, attr, original in _saved:
        setattr(obj, attr, original)
    _saved.clear()


# ── layer 2: per-test autouse guard (local dev) ──
@pytest.fixture(autouse=True)
def _network_deny(request, monkeypatch):
    """Block network+subprocess for every test not marked `live`/`integration`."""
    if request.node.get_closest_marker("live") or request.node.get_closest_marker("integration"):
        return
    for obj, attr in _blockers():
        monkeypatch.setattr(obj, attr, _blocked)


# ── shared fixtures ──
@pytest.fixture
def run_result():
    from quarry_recon.runner import RunResult, Status

    def _make(status=Status.SUCCESS, exit_code=0, stderr_tail="", raw_path=None, stdout_lines=0):
        return RunResult("tool", [], status, exit_code, 0.1, raw_path, stdout_lines, stderr_tail=stderr_tail)

    return _make


@pytest.fixture
def profile(tmp_path):
    from quarry_recon.config import TargetProfile

    def _make(body: str = "", apex: str = "example.com"):
        p = tmp_path / "target.yaml"
        p.write_text(f"TARGET: t\nAPEX_DOMAINS:\n  - {apex}\n{body}")
        return TargetProfile.load(p)

    return _make


@pytest.fixture(autouse=True)
def _no_provider_pacing(request, monkeypatch):
    """Offline tests have no provider to be polite to, so they must not SLEEP for one.

    Shodan requests are paced at ~1/s in production (we generated our own 429s without it, and paid up
    to 300 s for each). Offline the network is blocked outright, so the interval protects nothing and
    only makes the suite three times slower. Tests that assert the pacing MECHANISM set the interval
    themselves; `live`/`integration` tests keep the real one."""
    if request.node.get_closest_marker("live") or request.node.get_closest_marker("integration"):
        return
    try:
        from quarry_recon.phases import probe
    except Exception:
        return
    monkeypatch.setattr(probe, "_SHODAN_MIN_INTERVAL_S", 0.0, raising=False)
