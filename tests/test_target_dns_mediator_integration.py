"""Loopback integration checks for the bounded target-DNS mediator."""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from quarry_recon import network_broker, network_dns
from quarry_recon.network_broker import (
    BrokerPolicy,
    ControlEndpointRegistry,
    NetworkEffectFence,
)


pytestmark = [pytest.mark.integration, pytest.mark.requires_tool("python")]


def _policy():
    return BrokerPolicy(
        "a" * 32, "dns.dnsx_records", "dnsx", False, (), ("10.203.0.2",),
        ("1.1.1.1",), ("example.test",), (), (), (),
        authority_class="target", transport_profile="target-dns",
        peer_mode="deny-all", resolver_mode="mediated-public",
    )


def _query() -> bytes:
    name = b"\x03www\x07example\x04test\x00"
    return b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
        + name + b"\x00\x01\x00\x01"


def _mediator(monkeypatch):
    monkeypatch.setattr(
        network_dns, "_exchange",
        lambda _policy, _resolver, query, **_kwargs:
            query[:2] + b"\x81\x80" + query[4:],
    )
    mediator = network_dns.TargetDNSMediator(
        _policy(), authentication=b"m" * 32, deadline_monotonic=time.monotonic() + 5,
        effect_fence=NetworkEffectFence(),
    )
    mediator.start()
    return mediator


def _persistent_authentication() -> bytes:
    return network_dns._DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC + b"m" * 32


def _destination(endpoint: tuple[str, int]):
    host, port = endpoint
    return network_broker._Destination(
        socket.AF_INET, host, port,
        struct.pack("=H", socket.AF_INET) + struct.pack("!H", port)
        + socket.inet_aton(host) + b"\x00" * 8,
    )


def _notification(fd: int, notification_id: int = 17):
    notification = network_broker._SeccompNotif()
    notification.id = notification_id
    notification.pid = 123
    notification.data.args[0] = fd
    return notification


def _broker_auth_session(authentication: bytes):
    """A real socket/effect-fence seam without a seccomp listener."""
    session = object.__new__(network_broker.NetworkBrokerSession)
    session._dns_mediator_authentication = authentication
    session._policy = SimpleNamespace(
        request_id="a" * 32, transport_profile="target-dns",
    )
    session._deadline = time.monotonic() + 2.0
    session._stop = threading.Event()
    session._local_stop = threading.Event()
    session._effect_fence = NetworkEffectFence()
    session._effect_lock = session._effect_fence
    session._retained_lock = threading.Lock()
    session._retained_connections = set()
    session._records_lock = threading.Lock()
    session._records = []
    session._record_bytes = 0
    session._open_plans = {}
    session._dropped = 0
    session._fatal = None
    session._listener_hup = False
    session._listener_fd = -1
    session._child_pidfd = -1
    session._thread = None
    session._profile = "standard"
    session._operation_lock = threading.Lock()
    session._operation_threads = set()
    session._control_registry = ControlEndpointRegistry()
    session._control_owner_token = object()
    session._control_listeners = {}
    session._control_connections = set()
    session._singleton_controls = {}
    session._require_valid = lambda _notification_id: None
    return session


@pytest.mark.parametrize("syscall", ("sendto", "sendmsg"))
def test_addressed_udp_broker_envelope_is_exact_and_returns_query_length(
        monkeypatch, syscall):
    authentication = b"a" * 32
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(1)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query = _query()
    destination = _destination(receiver.getsockname())
    session = _broker_auth_session(authentication)
    responses, records = [], []
    session._classify_destination = lambda *_args, **_kwargs: (
        destination, "allow", "fixture mediator",
    )
    session._target_dns_client_allowed = lambda *_args: ("allow", "attested")
    session._target_dns_payload_allowed = lambda *_args: ("allow", "DNS query")
    session._record = lambda **record: records.append(record) is None
    session._respond = lambda notification_id, *, value=0, error=0: (
        responses.append((notification_id, value, error)) is None
    )
    monkeypatch.setattr(network_broker, "_copy_destination", lambda *_args, **_kwargs: destination)
    monkeypatch.setattr(
        network_broker, "_duplicate_tracee_fd",
        lambda *_args, **_kwargs: os.dup(sender.fileno()),
    )
    monkeypatch.setattr(
        network_broker, "_socket_metadata",
        lambda _fd: (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP),
    )
    monkeypatch.setattr(network_broker, "_require_same_tracee_ofd", lambda *_args, **_kwargs: None)
    notification = _notification(sender.fileno())
    try:
        if syscall == "sendto":
            notification.data.args[1] = 1
            notification.data.args[2] = len(query)
            notification.data.args[3] = 0
            notification.data.args[4] = 1
            notification.data.args[5] = len(destination.raw)
            monkeypatch.setattr(network_broker, "_copy_payload", lambda *_args, **_kwargs: query)
            session._handle_sendto(notification)
        else:
            message = SimpleNamespace(
                destination=destination,
                passed_fds=(),
                payload_buffers=(query,),
                iovectors=(SimpleNamespace(length=len(query)),),
                header=None,
            )
            notification.data.args[1] = 1
            notification.data.args[2] = 0
            monkeypatch.setattr(network_broker, "_copy_message", lambda *_args, **_kwargs: message)
            session._handle_sendmsg(notification)
        wire, _peer = receiver.recvfrom(512)
        assert wire == network_broker._DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC + authentication + query
        # The tracee receives the return value of its original call, rather
        # than the longer broker-only envelope.
        assert responses == [(notification.id, len(query), 0)]
        assert [record["stage"] for record in records] == ["planned", "settled"]
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize(
    ("kind", "protocol", "magic"),
    (
        (socket.SOCK_DGRAM, socket.IPPROTO_UDP,
         network_broker._DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC),
        (socket.SOCK_STREAM, socket.IPPROTO_TCP,
         network_broker._DNS_MEDIATOR_TCP_AUTH_MAGIC),
    ),
)
def test_connected_broker_authentication_precedes_connect_acknowledgement(
        monkeypatch, kind, protocol, magic):
    authentication = b"c" * 32
    listener = socket.socket(socket.AF_INET, kind)
    listener.bind(("127.0.0.1", 0))
    if kind == socket.SOCK_STREAM:
        listener.listen(1)
    listener.settimeout(1)
    client = socket.socket(socket.AF_INET, kind)
    destination = _destination(listener.getsockname())
    session = _broker_auth_session(authentication)
    events, responses = [], []
    session._control_endpoint = lambda *_args, **_kwargs: None
    session._singleton_endpoint = lambda *_args, **_kwargs: None
    session._target_dns_client_allowed = lambda *_args: ("allow", "attested")
    session._record = lambda **_record: True
    session._journal_capacity = lambda _count: True

    def connect(fd, _destination, **_kwargs):
        handle = socket.socket(fileno=fd)
        try:
            handle.connect(listener.getsockname())
        finally:
            handle.detach()
        return 0, 0, None

    def respond(notification_id, *, value=0, error=0):
        if kind == socket.SOCK_DGRAM:
            wire, _peer = listener.recvfrom(512)
        else:
            accepted, _peer = listener.accept()
            try:
                accepted.settimeout(1)
                wire = accepted.recv(512)
            finally:
                accepted.close()
        events.append(("wire", wire))
        responses.append((notification_id, value, error))
        events.append(("ack", notification_id))
        return True

    session._connect = connect
    session._respond = respond
    monkeypatch.setattr(network_broker, "_copy_destination", lambda *_args, **_kwargs: destination)
    monkeypatch.setattr(
        network_broker, "_duplicate_tracee_fd",
        lambda *_args, **_kwargs: os.dup(client.fileno()),
    )
    monkeypatch.setattr(
        network_broker, "_socket_metadata",
        lambda _fd: (socket.AF_INET, kind, protocol),
    )
    monkeypatch.setattr(network_broker, "_require_same_tracee_ofd", lambda *_args, **_kwargs: None)
    notification = _notification(client.fileno())
    notification.data.args[1] = 1
    notification.data.args[2] = len(destination.raw)
    try:
        session._handle_connect(notification)
        assert events == [
            ("wire", magic + authentication),
            ("ack", notification.id),
        ]
        assert responses == [(notification.id, 0, 0)]
        if kind == socket.SOCK_DGRAM:
            # The source-port grant stays alive after the tracee's duplicate
            # closes and is reclaimed by normal session stop/settlement.
            assert session.summary()["retained_connections"] == 1
            client.close()
            session.stop()
            assert session.summary()["retained_connections"] == 0
            client = None
    finally:
        if client is not None:
            client.close()
        listener.close()


def test_missing_or_invalid_authentication_fails_closed():
    mediator = network_dns.TargetDNSMediator(
        _policy(), authentication=b"m" * 32, deadline_monotonic=time.monotonic() + 5,
        effect_fence=NetworkEffectFence(),
    )
    query, peer = _query(), ("127.0.0.1", 53535)
    assert mediator._udp_query_authorized(query, peer) is None
    assert mediator._udp_query_authorized(
        network_dns._DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC + b"x" * 32 + query,
        peer,
    ) is None
    assert not mediator._consume_udp_authentication(
        network_dns._DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC + b"x" * 32,
        peer,
    )

    client, broker = socket.socketpair()
    try:
        mediator._tcp_auth_pending[broker] = bytearray()
        client.sendall(network_dns._DNS_MEDIATOR_TCP_AUTH_MAGIC + b"x" * 32)
        assert mediator._consume_tcp_authentication(broker) is False
    finally:
        client.close()
        broker.close()


def test_capacity_pressure_backpressures_without_dropping(monkeypatch):
    mediator = _mediator(monkeypatch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    held = 0
    try:
        for _ in range(network_dns._MAX_MEDIATOR_CLIENTS):
            assert mediator._slots.acquire(blocking=False)
            held += 1
        client.settimeout(0.05)
        query = _query()
        client.sendto(_persistent_authentication(), mediator.endpoint)
        client.sendto(query, mediator.endpoint)
        with pytest.raises(TimeoutError):
            client.recv(512)
        assert mediator.summary()["fatal"] is None
        assert mediator.summary()["queries"] == 0

        mediator._slots.release()
        held -= 1
        client.settimeout(1)
        assert client.recv(512)[2:4] == b"\x81\x80"
        assert mediator.summary()["fatal"] is None
        assert mediator.summary()["queries"] == 1
    finally:
        for _ in range(held):
            mediator._slots.release()
        client.close()
        mediator.stop()


def test_connected_tcp_dns_framing(monkeypatch):
    mediator = _mediator(monkeypatch)
    client = socket.create_connection(mediator.endpoint, timeout=1)
    try:
        query = _query()
        client.sendall(network_dns._DNS_MEDIATOR_TCP_AUTH_MAGIC + b"m" * 32)
        client.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", client.recv(2))[0]
        response = b""
        while len(response) < length:
            response += client.recv(length - len(response))
        assert response[2:4] == b"\x81\x80"
        assert network_dns._response_question_matches(query, response)
    finally:
        client.close()
        mediator.stop()
    assert mediator.summary()["complete"] is True


def test_unauthenticated_loopback_datagrams_never_reserve_a_query_slot(monkeypatch):
    mediator = _mediator(monkeypatch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    held = 0
    try:
        for _ in range(network_dns._MAX_MEDIATOR_CLIENTS):
            assert mediator._slots.acquire(blocking=False)
            held += 1
        client.sendto(_query(), mediator.endpoint)
        time.sleep(0.05)
        assert mediator.summary()["queries"] == 0
        assert mediator._slots.acquire(blocking=False) is False
    finally:
        for _ in range(held):
            mediator._slots.release()
        client.close()
        mediator.stop()


def test_addressed_udp_envelope_is_single_use_and_wire_compatible(monkeypatch):
    mediator = _mediator(monkeypatch)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        query = _query()
        envelope = network_dns._DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC + b"m" * 32 + query
        client.settimeout(1)
        client.sendto(envelope, mediator.endpoint)
        response, _peer = client.recvfrom(512)
        assert response[2:4] == b"\x81\x80"
        assert network_dns._response_question_matches(query, response)
        # The naked retry cannot inherit authorization from the addressed
        # envelope, even though it uses the exact same source port.
        client.sendto(query, mediator.endpoint)
        client.settimeout(0.05)
        with pytest.raises(TimeoutError):
            client.recvfrom(512)
        assert mediator.summary()["queries"] == 1
    finally:
        client.close()
        mediator.stop()


def test_unauthenticated_tcp_never_starts_a_query_task(monkeypatch):
    mediator = _mediator(monkeypatch)
    client = socket.create_connection(mediator.endpoint, timeout=1)
    held = 0
    try:
        for _ in range(network_dns._MAX_MEDIATOR_CLIENTS):
            assert mediator._slots.acquire(blocking=False)
            held += 1
        query = _query()
        client.sendall(struct.pack("!H", len(query)) + query)
        time.sleep(0.05)
        assert mediator.summary()["queries"] == 0
        assert mediator._slots.acquire(blocking=False) is False
    finally:
        for _ in range(held):
            mediator._slots.release()
        client.close()
        mediator.stop()
