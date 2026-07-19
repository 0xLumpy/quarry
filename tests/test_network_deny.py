"""Prove the offline network-deny guard actually bites — the C18 'CI makes no network call' invariant.

If this ever passes silently (a real connection succeeds), the guard has regressed and offline tests
could be reaching the network without anyone noticing.
"""
import socket
import subprocess

import pytest

from conftest import NetworkDenied

pytestmark = pytest.mark.offline


def test_tcp_connect_is_blocked():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(NetworkDenied):
        s.connect(("1.1.1.1", 80))


def test_create_connection_is_blocked():
    with pytest.raises(NetworkDenied):
        socket.create_connection(("1.1.1.1", 80), timeout=1)


@pytest.mark.parametrize("call", [
    lambda: socket.getaddrinfo("example.com", 80),
    lambda: socket.gethostbyname("example.com"),
    lambda: socket.gethostbyname_ex("example.com"),
])
def test_resolvers_are_blocked(call):
    with pytest.raises(NetworkDenied):
        call()


def test_udp_sendto_is_blocked():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(NetworkDenied):
        s.sendto(b"x", ("1.1.1.1", 53))


@pytest.mark.parametrize("spawn", [
    lambda: subprocess.run(["true"]),
    lambda: subprocess.Popen(["true"]),
])
def test_subprocess_spawn_is_blocked(spawn):
    # a scanner launched via exec_tool/subprocess would otherwise get normal network despite socket patches
    with pytest.raises(NetworkDenied):
        spawn()
