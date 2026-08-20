"""Bounded literal-resolver DNS for the runner-owned browser proxy."""
from __future__ import annotations

import ipaddress
import errno
import hmac
import os
import select
import socket
import struct
import threading
import time

from . import normalize
from .network_broker import (
    BrokerPolicy,
    NetworkBrokerRefused,
    NetworkEffectFence,
)


_MAX_DNS_MESSAGE_BYTES = 64 * 1024
_MAX_DNS_POINTERS = 32
_MAX_DNS_RECORDS = 512
_MAX_DNS_CNAME_DEPTH = 8
_DNSSEC_META_TYPES = frozenset({43, 46, 47, 48, 50, 51, 59, 60})
_DNS_HEADER = struct.Struct("!HHHHHH")
_MAX_MEDIATOR_CLIENTS = 32
_MAX_MEDIATOR_AUTH_PEERS = 512
_DNS_MEDIATOR_TCP_AUTH_MAGIC = b"QDT1"
_DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC = b"QDP1"
_DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC = b"QDQ1"
_DNS_MEDIATOR_AUTH_BYTES = 4 + 32


class NetworkDNSRefused(NetworkBrokerRefused):
    """The explicit resolver exchange was malformed or unauthorised."""


class TargetDNSMediator:
    """One held loopback DNS endpoint for a target-DNS tracee.

    The tracee can use either connected UDP or TCP fallback, but every request
    is checked against its source policy here before the existing literal
    resolver exchange is allowed to acquire the shared effect fence.
    """

    def __init__(self, policy: BrokerPolicy, *, authentication: bytes,
                 deadline_monotonic: float, effect_fence: NetworkEffectFence):
        if (type(policy) is not BrokerPolicy
                or policy.transport_profile != "target-dns"
                or type(deadline_monotonic) not in {int, float}
                or deadline_monotonic <= time.monotonic()
                or type(effect_fence) is not NetworkEffectFence
                or type(authentication) is not bytes
                or len(authentication) != 32):
            raise NetworkDNSRefused("network_dns_mediator_invalid")
        self._policy = policy
        self._deadline = float(deadline_monotonic)
        self._fence = effect_fence
        self._authentication = authentication
        self._stop = threading.Event()
        self._state_lock = threading.Lock()
        self._fatal: str | None = None
        self._queries = 0
        self._rejected = 0
        self._upstream_planned = 0
        self._upstream_settled = 0
        self._upstream_denied = 0
        self._clients_lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._tcp_auth_pending: dict[socket.socket, bytearray] = {}
        self._udp_persistent_peers: set[tuple[str, int]] = set()
        self._tasks_lock = threading.Lock()
        self._tasks: set[threading.Thread] = set()
        self._slots = threading.BoundedSemaphore(_MAX_MEDIATOR_CLIENTS)
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._endpoint: tuple[str, int] | None = None

    @property
    def endpoint(self) -> tuple[str, int]:
        if self._endpoint is None:
            raise NetworkDNSRefused("network_dns_mediator_not_started")
        return self._endpoint

    def start(self) -> None:
        if self._thread is not None:
            raise NetworkDNSRefused("network_dns_mediator_started_twice")
        tcp = udp = None
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(_MAX_MEDIATOR_CLIENTS)
            host, port = tcp.getsockname()
            if host != "127.0.0.1" or not isinstance(port, int) or port <= 0:
                raise NetworkDNSRefused("network_dns_mediator_endpoint_invalid")
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((host, port))
            tcp.setblocking(False)
            udp.setblocking(False)
            self._fence.track_socket(tcp)
            self._fence.track_socket(udp)
            self._tcp, self._udp, self._endpoint = tcp, udp, (host, port)
            thread = threading.Thread(
                target=self._run, name="quarry-target-dns", daemon=False,
            )
            self._thread = thread
            thread.start()
        except BaseException:
            for handle in (udp, tcp):
                if handle is None:
                    continue
                try:
                    self._fence.close_tracked_socket(handle)
                except NetworkBrokerRefused:
                    try:
                        handle.close()
                    except OSError:
                        pass
            self._udp = self._tcp = None
            self._endpoint = None
            raise

    def stop(self) -> None:
        """Close both held listeners and join every mediator task."""
        self._stop.set()
        faults: list[BaseException] = []
        for attr in ("_udp", "_tcp"):
            handle = getattr(self, attr)
            if handle is not None:
                try:
                    self._fence.close_tracked_socket(handle)
                except BaseException as exc:
                    self._set_fatal("network_dns_mediator_listener_close_failed")
                    faults.append(exc)
                else:
                    setattr(self, attr, None)
        with self._clients_lock:
            clients = tuple(self._clients)
        for handle in clients:
            try:
                self._fence.close_tracked_socket(handle)
            except BaseException as exc:
                self._set_fatal("network_dns_mediator_client_close_failed")
                faults.append(exc)
        deadline = time.monotonic() + 5.0
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                self._set_fatal("network_dns_mediator_join_failed")
                faults.append(NetworkDNSRefused("network_dns_mediator_join_failed"))
        while True:
            with self._tasks_lock:
                tasks = tuple(task for task in self._tasks
                              if task is not threading.current_thread())
            if not tasks:
                break
            for task in tasks:
                task.join(timeout=max(0.0, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                if any(task.is_alive() for task in tasks):
                    self._set_fatal("network_dns_mediator_join_failed")
                    faults.append(NetworkDNSRefused("network_dns_mediator_join_failed"))
                break
        if faults:
            raise faults[0]

    def summary(self) -> dict:
        with self._state_lock:
            fatal, queries, rejected = self._fatal, self._queries, self._rejected
            upstream = {
                "planned": self._upstream_planned,
                "settled": self._upstream_settled,
                "denied": self._upstream_denied,
            }
        with self._tasks_lock:
            active = sum(task.is_alive() for task in self._tasks)
        thread = self._thread
        return {
            "endpoint": self._endpoint,
            "queries": queries,
            "rejected": rejected,
            "upstream": upstream,
            "fatal": fatal,
            "complete": (
                fatal is None and self._udp is None and self._tcp is None
                and active == 0 and (thread is None or not thread.is_alive())
                and upstream["planned"] == upstream["settled"]
            ),
        }

    def _set_fatal(self, reason: str) -> None:
        with self._state_lock:
            self._fatal = self._fatal or reason
        self._stop.set()
        self._fence.cancel()

    def _on_upstream(self, stage, _peer, _port, decision, _reason) -> None:
        if stage not in {"dns-planned", "dns-settled"} or decision not in {"allow", "deny"}:
            self._set_fatal("network_dns_mediator_event_invalid")
            raise NetworkDNSRefused("network_dns_mediator_event_invalid")
        with self._state_lock:
            if stage == "dns-planned":
                self._upstream_planned += 1
            else:
                self._upstream_settled += 1
                if decision == "deny":
                    self._upstream_denied += 1

    def _failure(self, query: bytes, *, refused: bool = False) -> bytes | None:
        if len(query) < _DNS_HEADER.size:
            return None
        flags = 0x8185 if refused else 0x8182
        return query[:2] + struct.pack("!H", flags) + query[4:]

    def _relay(self, query: bytes) -> bytes | None:
        decision, _reason = self._policy.decide_dns_question(query)
        if decision != "allow":
            with self._state_lock:
                self._rejected += 1
            return self._failure(query, refused=True)
        with self._state_lock:
            self._queries += 1
        transaction = struct.unpack_from("!H", query)[0]
        for resolver in self._policy.resolver_ips:
            if self._stop.is_set() or self._fence.is_set():
                break
            try:
                response = _exchange(
                    self._policy, resolver, query,
                    deadline_monotonic=min(self._deadline, time.monotonic() + 5.0),
                    transaction=transaction, on_event=self._on_upstream,
                    effect_fence=self._fence,
                )
                if not _response_question_matches(query, response):
                    raise NetworkDNSRefused("network_dns_mediator_response_mismatch")
                return response
            except (OSError, TimeoutError, NetworkDNSRefused):
                if self._fence.is_set():
                    break
        if not self._stop.is_set() and not self._fence.is_set():
            self._set_fatal("network_dns_mediator_upstream_failed")
        return self._failure(query)

    def _start_task(self, target, *args, slot_reserved: bool = False) -> bool:
        if self._stop.is_set():
            if slot_reserved:
                self._slots.release()
            return False
        if not slot_reserved and not self._slots.acquire(blocking=False):
            return False

        def task() -> None:
            try:
                target(*args)
            except BaseException:
                self._set_fatal("network_dns_mediator_task_failed")
            finally:
                self._slots.release()
                with self._tasks_lock:
                    self._tasks.discard(threading.current_thread())

        thread = threading.Thread(target=task, name="quarry-target-dns-query",
                                  daemon=False)
        with self._tasks_lock:
            self._tasks.add(thread)
        try:
            thread.start()
        except BaseException as exc:
            with self._tasks_lock:
                self._tasks.discard(thread)
            self._slots.release()
            self._set_fatal("network_dns_mediator_task_start_failed")
            if not isinstance(exc, Exception):
                raise
            return False
        return True

    def _serve_udp(self, query: bytes, peer) -> None:
        response = self._relay(query)
        udp = self._udp
        if response is not None and udp is not None and not self._stop.is_set():
            try:
                with self._fence:
                    udp.sendto(response, peer)
            except (OSError, NetworkBrokerRefused):
                if not self._stop.is_set():
                    self._set_fatal("network_dns_mediator_udp_response_failed")

    @staticmethod
    def _auth_peer(peer) -> tuple[str, int] | None:
        """Return a canonical loopback UDP peer suitable for bounded state."""
        if (type(peer) is not tuple or len(peer) != 2
                or type(peer[0]) is not str or type(peer[1]) is not int
                or not 1 <= peer[1] <= 65535):
            return None
        try:
            address = ipaddress.ip_address(peer[0])
        except ValueError:
            return None
        if address.version != 4 or str(address) != "127.0.0.1":
            return None
        return str(address), peer[1]

    def _persistent_authentication_datagram(self, query: bytes) -> bool:
        if type(query) is not bytes or len(query) != _DNS_MEDIATOR_AUTH_BYTES:
            return False
        return (query[:4] == _DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC
                and hmac.compare_digest(query[4:], self._authentication))

    def _consume_udp_authentication(self, query: bytes, peer) -> bool:
        """Consume only an exact broker auth datagram, never a DNS query."""
        auth_peer = self._auth_peer(peer)
        if not self._persistent_authentication_datagram(query) or auth_peer is None:
            return False
        if (auth_peer not in self._udp_persistent_peers
                and len(self._udp_persistent_peers) >= _MAX_MEDIATOR_AUTH_PEERS):
            return True
        self._udp_persistent_peers.add(auth_peer)
        return True

    def _udp_query_authorized(self, query: bytes, peer) -> bytes | None:
        auth_peer = self._auth_peer(peer)
        if auth_peer is None:
            return None
        if auth_peer in self._udp_persistent_peers:
            return query
        if (len(query) < _DNS_MEDIATOR_AUTH_BYTES
                or query[:4] != _DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC
                or not hmac.compare_digest(query[4:_DNS_MEDIATOR_AUTH_BYTES],
                                           self._authentication)):
            return None
        # The exact broker envelope is consumed as one datagram.  There is no
        # reusable source-port grant for addressed sendto/sendmsg traffic.
        return query[_DNS_MEDIATOR_AUTH_BYTES:]

    def _close_client(self, handle: socket.socket) -> None:
        try:
            self._fence.close_tracked_socket(handle)
        except BaseException:
            self._set_fatal("network_dns_mediator_client_close_failed")
        else:
            with self._clients_lock:
                self._clients.discard(handle)
            self._tcp_auth_pending.pop(handle, None)

    def _consume_tcp_authentication(self, handle: socket.socket) -> bool | None:
        """Return True once the fixed preamble is verified, False if invalid."""
        pending = self._tcp_auth_pending.get(handle)
        if pending is None:
            return False
        expected = _DNS_MEDIATOR_TCP_AUTH_MAGIC + self._authentication
        if len(pending) == _DNS_MEDIATOR_AUTH_BYTES:
            return hmac.compare_digest(bytes(pending), expected)
        try:
            block = handle.recv(_DNS_MEDIATOR_AUTH_BYTES - len(pending))
        except BlockingIOError:
            return None
        except OSError:
            return False
        if not block:
            return False
        pending.extend(block)
        if len(pending) < _DNS_MEDIATOR_AUTH_BYTES:
            return None
        return hmac.compare_digest(bytes(pending), expected)

    def _serve_tcp(self, handle: socket.socket) -> None:
        try:
            while not self._stop.is_set() and not self._fence.is_set():
                length = struct.unpack("!H", _read_exact(
                    handle, 2, deadline_monotonic=self._deadline,
                    effect_fence=self._fence,
                ))[0]
                if not 17 <= length <= 512:
                    return
                query = _read_exact(
                    handle, length, deadline_monotonic=self._deadline,
                    effect_fence=self._fence,
                )
                response = self._relay(query)
                if response is None:
                    return
                _send_all(
                    handle, struct.pack("!H", len(response)) + response,
                    deadline_monotonic=self._deadline, effect_fence=self._fence,
                )
        except (OSError, TimeoutError, NetworkDNSRefused):
            pass
        finally:
            try:
                self._fence.close_tracked_socket(handle)
            except BaseException:
                # Keep the socket in both ownership registries: a failed close
                # must remain cancellable rather than being forgotten.
                self._set_fatal("network_dns_mediator_client_close_failed")
            else:
                with self._clients_lock:
                    self._clients.discard(handle)

    def _run(self) -> None:
        while (not self._stop.is_set() and not self._fence.is_set()
               and time.monotonic() < self._deadline):
            udp, tcp = self._udp, self._tcp
            if udp is None or tcp is None:
                return
            try:
                with self._clients_lock:
                    pending = tuple(self._tcp_auth_pending)
                readable, _writable, _errors = select.select(
                    (udp, tcp, *pending), (), (), 0.05,
                )
            except (OSError, ValueError):
                if not self._stop.is_set() and not self._fence.is_set():
                    self._set_fatal("network_dns_mediator_listener_failed")
                return
            if udp in readable:
                # Leave datagrams in the bounded kernel receive queue while all
                # workers are occupied.  dnsx/massdns can legitimately have
                # more outstanding queries than this mediator has threads;
                # transient pressure must apply backpressure, not cancel the
                # invocation after already consuming and dropping a query.
                try:
                    query, peer = udp.recvfrom(
                        512 + _DNS_MEDIATOR_AUTH_BYTES, socket.MSG_PEEK,
                    )
                except BlockingIOError:
                    continue
                except OSError:
                    if not self._stop.is_set() and not self._fence.is_set():
                        self._set_fatal("network_dns_mediator_listener_failed")
                    return
                if self._persistent_authentication_datagram(query):
                    try:
                        query, peer = udp.recvfrom(512 + _DNS_MEDIATOR_AUTH_BYTES)
                    except (BlockingIOError, OSError):
                        continue
                    self._consume_udp_authentication(query, peer)
                    continue
                authorized_query = self._udp_query_authorized(query, peer)
                if authorized_query is None:
                    try:
                        udp.recvfrom(512 + _DNS_MEDIATOR_AUTH_BYTES)
                    except (BlockingIOError, OSError):
                        pass
                    continue
                if not self._slots.acquire(blocking=False):
                    time.sleep(0.005)
                    continue
                slot_reserved = True
                try:
                    query, peer = udp.recvfrom(512)
                except BlockingIOError:
                    self._slots.release()
                    slot_reserved = False
                except OSError:
                    self._slots.release()
                    slot_reserved = False
                    if not self._stop.is_set() and not self._fence.is_set():
                        self._set_fatal("network_dns_mediator_listener_failed")
                    return
                else:
                    slot_reserved = False
                    self._start_task(
                        self._serve_udp, authorized_query, peer, slot_reserved=True,
                    )
                finally:
                    if slot_reserved:
                        self._slots.release()
            if tcp in readable:
                handle = None
                try:
                    handle, _peer = tcp.accept()
                    self._fence.track_socket(handle)
                    with self._clients_lock:
                        if len(self._clients) >= _MAX_MEDIATOR_AUTH_PEERS:
                            raise NetworkDNSRefused("network_dns_mediator_client_capacity")
                        self._clients.add(handle)
                    handle.setblocking(False)
                    self._tcp_auth_pending[handle] = bytearray()
                except BlockingIOError:
                    pass
                except (OSError, NetworkBrokerRefused):
                    if handle is not None:
                        self._close_client(handle)
                    if not self._stop.is_set():
                        self._set_fatal("network_dns_mediator_listener_failed")
                        return
            for handle in tuple(readable):
                if handle in {udp, tcp}:
                    continue
                authenticated = self._consume_tcp_authentication(handle)
                if authenticated is None:
                    continue
                if authenticated is not True:
                    self._close_client(handle)
                    continue
                self._tcp_auth_pending.pop(handle, None)
                if not self._slots.acquire(blocking=False):
                    # Authentication cannot consume query capacity.  A valid
                    # client waits until a slot is actually available.
                    self._tcp_auth_pending[handle] = bytearray(
                        _DNS_MEDIATOR_TCP_AUTH_MAGIC + self._authentication,
                    )
                    continue
                self._start_task(self._serve_tcp, handle, slot_reserved=True)
        if not self._stop.is_set() and time.monotonic() >= self._deadline:
            self._set_fatal("network_dns_mediator_deadline_expired")


def _question_end(message: bytes) -> int | None:
    """Return the exact uncompressed IN question boundary, if present."""
    if len(message) < _DNS_HEADER.size:
        return None
    try:
        _transaction, _flags, questions, _answers, _authority, _additional = \
            _DNS_HEADER.unpack_from(message)
    except struct.error:
        return None
    if questions != 1:
        return None
    cursor = _DNS_HEADER.size
    while True:
        if cursor >= len(message):
            return None
        size = message[cursor]
        cursor += 1
        if size == 0:
            break
        if size > 63 or size & 0xC0 or cursor + size > len(message):
            return None
        cursor += size
    return cursor + 4 if cursor + 4 <= len(message) else None


def _response_question_matches(query: bytes, response: bytes) -> bool:
    """Bind a resolver response to the exact question accepted for this hop."""
    query_end = _question_end(query)
    response_end = _question_end(response)
    if query_end is None or response_end is None:
        return False
    flags = struct.unpack_from("!H", response, 2)[0]
    return bool(flags & 0x8000) and response[12:response_end] == query[12:query_end]


def _encode_name(host: str) -> bytes:
    labels = host.split(".")
    encoded = bytearray()
    for label in labels:
        body = label.encode("ascii", "strict")
        if not 1 <= len(body) <= 63:
            raise NetworkDNSRefused("network_dns_name_invalid")
        encoded.append(len(body))
        encoded.extend(body)
    encoded.append(0)
    if len(encoded) > 255:
        raise NetworkDNSRefused("network_dns_name_invalid")
    return bytes(encoded)


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    resumed = None
    pointers: set[int] = set()
    while True:
        if not 0 <= cursor < len(message):
            raise NetworkDNSRefused("network_dns_response_malformed")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise NetworkDNSRefused("network_dns_response_malformed")
            target = ((length & 0x3F) << 8) | message[cursor + 1]
            if (target >= cursor or target >= len(message) or target in pointers
                    or len(pointers) >= _MAX_DNS_POINTERS):
                raise NetworkDNSRefused("network_dns_response_malformed")
            pointers.add(target)
            if resumed is None:
                resumed = cursor + 2
            cursor = target
            continue
        if length & 0xC0 or length > 63:
            raise NetworkDNSRefused("network_dns_response_malformed")
        cursor += 1
        if length == 0:
            break
        if cursor + length > len(message):
            raise NetworkDNSRefused("network_dns_response_malformed")
        try:
            label = message[cursor:cursor + length].decode("ascii", "strict").lower()
        except UnicodeError as exc:
            raise NetworkDNSRefused("network_dns_response_malformed") from exc
        if (not label or label[0] == "-" or label[-1] == "-"
                or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                       for char in label)):
            raise NetworkDNSRefused("network_dns_response_malformed")
        labels.append(label)
        cursor += length
    name = ".".join(labels)
    if name and normalize.canon_host_strict(name) != name:
        raise NetworkDNSRefused("network_dns_response_malformed")
    return name, resumed if resumed is not None else cursor


def _wait(handle: socket.socket, *, deadline_monotonic: float,
          effect_fence: NetworkEffectFence, readable: bool = False,
          writable: bool = False) -> None:
    while True:
        if effect_fence.is_set():
            raise NetworkDNSRefused("network_dns_exchange_cancelled")
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("network DNS deadline expired")
        reads = (handle,) if readable else ()
        writes = (handle,) if writable else ()
        ready_read, ready_write, exceptional = select.select(
            reads, writes, (handle,), min(0.05, remaining),
        )
        if exceptional:
            raise NetworkDNSRefused("network_dns_exchange_failed")
        if (readable and ready_read) or (writable and ready_write):
            return


def _read_exact(handle: socket.socket, size: int, *,
                deadline_monotonic: float,
                effect_fence: NetworkEffectFence) -> bytes:
    result = bytearray()
    while len(result) < size:
        _wait(
            handle, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence, readable=True,
        )
        try:
            block = handle.recv(size - len(result))
        except BlockingIOError:
            continue
        if not block:
            raise NetworkDNSRefused("network_dns_tcp_response_truncated")
        result.extend(block)
    return bytes(result)


def _connect(handle: socket.socket, endpoint, *,
             deadline_monotonic: float,
             effect_fence: NetworkEffectFence) -> None:
    handle.setblocking(False)
    with effect_fence:
        error = handle.connect_ex(endpoint)
    if error not in {
            0, errno.EISCONN, errno.EINPROGRESS,
            errno.EALREADY, errno.EWOULDBLOCK,
    }:
        raise OSError(error, "network DNS resolver connect failed")
    while error not in {0, errno.EISCONN}:
        _wait(
            handle, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence, writable=True,
        )
        error = handle.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, "network DNS resolver connect failed")


def _send_all(handle: socket.socket, body: bytes, *,
              deadline_monotonic: float,
              effect_fence: NetworkEffectFence) -> None:
    view = memoryview(body)
    while view:
        _wait(
            handle, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence, writable=True,
        )
        try:
            with effect_fence:
                written = handle.send(view)
        except BlockingIOError:
            continue
        if written <= 0:
            raise NetworkDNSRefused("network_dns_send_failed")
        view = view[written:]


def _wire_query(host: str, query_type: int, transaction: int) -> bytes:
    return (
        _DNS_HEADER.pack(transaction, 0x0100, 1, 0, 0, 0)
        + _encode_name(host) + struct.pack("!HH", query_type, 1)
    )


def _authorized_resolver(policy: BrokerPolicy, peer: str, kind: int,
                         protocol: int) -> None:
    decision, _reason = policy.decide_dns(peer, 53, kind, protocol)
    if decision != "allow":
        raise NetworkDNSRefused("network_dns_resolver_refused")


def _exchange(policy: BrokerPolicy, resolver: str, request: bytes,
              *, deadline_monotonic: float, transaction: int, on_event,
              effect_fence: NetworkEffectFence) -> bytes:
    address = ipaddress.ip_address(resolver)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    endpoint = (resolver, 53) if family == socket.AF_INET else (resolver, 53, 0, 0)

    def emit(*event) -> None:
        try:
            on_event(*event)
        except BaseException:
            # A durable trace fault invalidates every sibling effect sharing
            # this invocation fence.  Cancel synchronously before the callback
            # failure can escape to its caller.
            effect_fence.cancel()
            raise

    _authorized_resolver(policy, resolver, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    emit("dns-planned", resolver, 53, "allow", "explicit UDP resolver query")
    udp = None
    udp_tracked = False
    try:
        udp = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        effect_fence.track_socket(udp)
        udp_tracked = True
        _connect(
            udp, endpoint, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence,
        )
        observed = ipaddress.ip_address(udp.getpeername()[0])
        selected = str(getattr(observed, "ipv4_mapped", None) or observed)
        if selected != resolver:
            raise NetworkDNSRefused("network_dns_resolver_peer_unverified")
        _authorized_resolver(
            policy, selected, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        _send_all(
            udp, request, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence,
        )
        _wait(
            udp, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence, readable=True,
        )
        response = udp.recv(_MAX_DNS_MESSAGE_BYTES + 1)
        if len(response) > _MAX_DNS_MESSAGE_BYTES:
            raise NetworkDNSRefused("network_dns_response_oversize")
        if len(response) < _DNS_HEADER.size:
            raise NetworkDNSRefused("network_dns_response_malformed")
        observed_id, flags, _questions, _answers, _authority, _additional = \
            _DNS_HEADER.unpack_from(response)
        if observed_id != transaction:
            raise NetworkDNSRefused("network_dns_transaction_mismatch")
    except BaseException:
        emit(
            "dns-settled", resolver, 53, "deny",
            "explicit UDP resolver exchange did not settle",
        )
        raise
    finally:
        if udp is not None:
            if udp_tracked:
                effect_fence.close_tracked_socket(udp)
            else:
                udp.close()
    if not flags & 0x0200:
        emit("dns-settled", resolver, 53, "allow", "explicit UDP resolver response")
        return response
    emit(
        "dns-settled", resolver, 53, "allow",
        "explicit UDP resolver response required TCP retry",
    )

    _authorized_resolver(policy, resolver, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    emit("dns-planned", resolver, 53, "allow", "explicit TCP resolver retry")
    tcp = None
    tcp_tracked = False
    try:
        tcp = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        effect_fence.track_socket(tcp)
        tcp_tracked = True
        _connect(
            tcp, endpoint, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence,
        )
        observed = ipaddress.ip_address(tcp.getpeername()[0])
        selected = str(getattr(observed, "ipv4_mapped", None) or observed)
        if selected != resolver:
            raise NetworkDNSRefused("network_dns_resolver_peer_unverified")
        _authorized_resolver(
            policy, selected, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        )
        _send_all(
            tcp, struct.pack("!H", len(request)) + request,
            deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence,
        )
        length = struct.unpack(
            "!H", _read_exact(
                tcp, 2, deadline_monotonic=deadline_monotonic,
                effect_fence=effect_fence,
            ),
        )[0]
        if length < _DNS_HEADER.size or length > _MAX_DNS_MESSAGE_BYTES:
            raise NetworkDNSRefused("network_dns_response_oversize")
        response = _read_exact(
            tcp, length, deadline_monotonic=deadline_monotonic,
            effect_fence=effect_fence,
        )
        observed_id, _flags, _questions, _answers, _authority, _additional = \
            _DNS_HEADER.unpack_from(response)
        if observed_id != transaction:
            raise NetworkDNSRefused("network_dns_transaction_mismatch")
    except BaseException:
        emit(
            "dns-settled", resolver, 53, "deny",
            "explicit TCP resolver exchange did not settle",
        )
        raise
    finally:
        if tcp is not None:
            if tcp_tracked:
                effect_fence.close_tracked_socket(tcp)
            else:
                tcp.close()
    emit("dns-settled", resolver, 53, "allow", "explicit TCP resolver response")
    return response


def _parse_response(message: bytes, *, transaction: int, host: str,
                    query_type: int, include_chain: bool = False):
    if len(message) < _DNS_HEADER.size:
        raise NetworkDNSRefused("network_dns_response_malformed")
    observed_id, flags, questions, answers, authority, additional = \
        _DNS_HEADER.unpack_from(message)
    if (observed_id != transaction or not flags & 0x8000
            or flags & 0x7800 or questions != 1
            or answers + authority + additional > _MAX_DNS_RECORDS):
        raise NetworkDNSRefused("network_dns_response_malformed")
    offset = _DNS_HEADER.size
    question, offset = _decode_name(message, offset)
    if offset + 4 > len(message):
        raise NetworkDNSRefused("network_dns_response_malformed")
    observed_type, observed_class = struct.unpack_from("!HH", message, offset)
    offset += 4
    if question != host or observed_type != query_type or observed_class != 1:
        raise NetworkDNSRefused("network_dns_response_malformed")
    sections = []
    for count in (answers, authority, additional):
        records = []
        for _index in range(count):
            owner, offset = _decode_name(message, offset)
            if offset + 10 > len(message):
                raise NetworkDNSRefused("network_dns_response_malformed")
            kind, record_class, _ttl, length = struct.unpack_from(
                "!HHIH", message, offset,
            )
            offset += 10
            end = offset + length
            if end > len(message):
                raise NetworkDNSRefused("network_dns_response_malformed")
            records.append((owner, kind, record_class, offset, end))
            offset = end
        sections.append(tuple(records))
    if offset != len(message):
        raise NetworkDNSRefused("network_dns_response_malformed")
    # Authority and Additional are parsed to prove exact wire framing, but may
    # never satisfy the requested owner/type obligation.  Only Answer carries
    # address/CNAME authority for this transaction.
    answer_records = sections[0]
    cname_by_owner: dict[str, str] = {}
    data_by_owner: dict[str, set[int]] = {}
    addresses: dict[tuple[str, int], list[str]] = {}
    for owner, kind, record_class, start, end in answer_records:
        if record_class != 1:
            continue
        if kind == 5:
            target, consumed = _decode_name(message, start)
            previous = cname_by_owner.get(owner)
            if consumed != end or previous not in {None, target}:
                raise NetworkDNSRefused("network_dns_response_malformed")
            cname_by_owner[owner] = target
            continue
        if kind not in _DNSSEC_META_TYPES:
            data_by_owner.setdefault(owner, set()).add(kind)
        if kind in {1, 28}:
            expected = 4 if kind == 1 else 16
            if end - start != expected:
                raise NetworkDNSRefused("network_dns_response_malformed")
            value = ipaddress.ip_address(message[start:end])
            addresses.setdefault((owner, kind), []).append(
                str(getattr(value, "ipv4_mapped", None) or value),
            )
    if any(data_by_owner.get(owner) for owner in cname_by_owner):
        raise NetworkDNSRefused("network_dns_response_malformed")

    current = host
    seen = {current}
    path = []
    values: tuple[str, ...] = ()
    unresolved = None
    state = "nodata"
    for _depth in range(_MAX_DNS_CNAME_DEPTH + 1):
        observed = addresses.get((current, query_type), ())
        if observed:
            values = tuple(sorted(
                set(observed), key=lambda item: int(ipaddress.ip_address(item)),
            ))
            state = "ok"
            break
        cname = cname_by_owner.get(current)
        if cname is None:
            if current != host:
                unresolved = current
                state = "indeterminate"
            break
        if len(path) >= _MAX_DNS_CNAME_DEPTH:
            unresolved = cname
            state = "indeterminate"
            break
        if cname in seen:
            raise NetworkDNSRefused("network_dns_cname_cycle")
        path.append((current, cname))
        seen.add(cname)
        current = cname

    rcode = flags & 0xF
    if rcode == 3:
        if values:
            raise NetworkDNSRefused("network_dns_response_malformed")
        unresolved, state = None, "nxdomain"
    elif rcode != 0 or flags & 0x0200:
        values, unresolved, state = (), None, "indeterminate"
    result = (values, unresolved, state)
    if include_chain:
        # Include every observed CNAME mapping, not only the followed suffix:
        # a later response cannot hide a conflicting intermediate RRset.
        return (*result, tuple(sorted(cname_by_owner.items())))
    return result


def resolve(policy: BrokerPolicy, host: str, *, timeout: float = 5.0,
            on_event=lambda *_args: None,
            effect_fence: NetworkEffectFence | None = None,
            ) -> tuple[tuple[str, ...], str]:
    """Resolve one canonical host only through policy-declared literal resolvers."""
    if (type(policy) is not BrokerPolicy
            or type(timeout) not in {int, float}
            or not 0 < timeout <= 60 or not callable(on_event)
            or (effect_fence is not None
                and type(effect_fence) is not NetworkEffectFence)):
        raise NetworkDNSRefused("network_dns_request_invalid")
    active_fence = effect_fence or NetworkEffectFence()
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        canonical = normalize.canon_host_strict(host)
        if canonical is None or canonical != host:
            raise NetworkDNSRefused("network_dns_name_invalid")
    else:
        if isinstance(literal, ipaddress.IPv6Address) and literal.scope_id is not None:
            raise NetworkDNSRefused("network_dns_name_invalid")
        return (str(getattr(literal, "ipv4_mapped", None) or literal),), "ok"
    deadline = time.monotonic() + timeout

    def resolve_type(query_type: int):
        current = canonical
        graph: dict[str, str] = {}

        def merge_chain(mappings) -> None:
            for owner, target in mappings:
                previous = graph.get(owner)
                if previous is not None and previous != target:
                    raise NetworkDNSRefused("network_dns_cname_conflict")
                graph[owner] = target
            if len(graph) > _MAX_DNS_CNAME_DEPTH:
                raise NetworkDNSRefused("network_dns_cname_depth")
            for origin in tuple(graph):
                seen = set()
                cursor = origin
                while cursor in graph:
                    if cursor in seen:
                        raise NetworkDNSRefused("network_dns_cname_cycle")
                    seen.add(cursor)
                    cursor = graph[cursor]

        def signature():
            result = []
            cursor = canonical
            seen = set()
            while cursor in graph:
                if cursor in seen or len(result) >= _MAX_DNS_CNAME_DEPTH:
                    raise NetworkDNSRefused("network_dns_cname_cycle")
                seen.add(cursor)
                target = graph[cursor]
                result.append((cursor, target))
                cursor = target
            return tuple(result)

        for _depth in range(_MAX_DNS_CNAME_DEPTH + 1):
            next_name = None
            for resolver in policy.resolver_ips:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return (), "indeterminate", ()
                transaction = int.from_bytes(os.urandom(2), "big")
                try:
                    response = _exchange(
                        policy, resolver,
                        _wire_query(current, query_type, transaction),
                        deadline_monotonic=min(deadline, time.monotonic() + 5.0),
                        transaction=transaction,
                        on_event=on_event,
                        effect_fence=active_fence,
                    )
                    parsed = _parse_response(
                        response, transaction=transaction, host=current,
                        query_type=query_type, include_chain=True,
                    )
                except (OSError, TimeoutError, NetworkDNSRefused):
                    if active_fence.is_set():
                        raise NetworkDNSRefused("network_dns_exchange_cancelled")
                    continue
                if len(parsed) == 3:  # test adapters written against the v1 parser tuple
                    answers, cname, state = parsed
                    mappings = ()
                else:
                    answers, cname, state, mappings = parsed
                try:
                    merge_chain(mappings)
                except NetworkDNSRefused:
                    return (), "indeterminate", ()
                if answers:
                    return answers, "ok", signature()
                if cname is not None:
                    next_name = cname
                    break
                if state in {"nodata", "nxdomain"}:
                    return (), state, signature()
                # SERVFAIL/other indeterminate responses do not satisfy the
                # family obligation; another explicit resolver may still do so.
            if next_name is None:
                return (), "indeterminate", ()
            if next_name == current:
                return (), "indeterminate", ()
            if current not in graph:
                graph[current] = next_name
            try:
                merge_chain(())
            except NetworkDNSRefused:
                return (), "indeterminate", ()
            cursor = current
            traversed = set()
            while cursor in graph and cursor not in traversed:
                traversed.add(cursor)
                cursor = graph[cursor]
                if cursor == next_name:
                    break
            if cursor != next_name:
                return (), "indeterminate", ()
            current = next_name
        return (), "indeterminate", ()

    obligations = tuple(resolve_type(query_type) for query_type in (1, 28))
    states = tuple(state for _answers, state, _chain in obligations)
    if "indeterminate" in states:
        return (), "indeterminate"
    if obligations[0][2] != obligations[1][2]:
        return (), "indeterminate"
    if "nxdomain" in states:
        return ((), "nxdomain") if states == ("nxdomain", "nxdomain") \
            else ((), "indeterminate")
    values = {value for answers, _state, _chain in obligations for value in answers}
    if values:
        return tuple(sorted(values, key=lambda item: (
            ipaddress.ip_address(item).version, int(ipaddress.ip_address(item)),
        ))), "ok"
    return (), "nodata"


__all__ = ("NetworkDNSRefused", "TargetDNSMediator", "resolve")
