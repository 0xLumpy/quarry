"""Bounded worker-owned WebSocket bridge for Chromium's DevTools pipe.

Chromium is launched with its supported ``--remote-debugging-pipe`` transport.
It therefore never owns an INET DevTools listener and never needs a privileged
``accept(2)`` exception.  An attested controller may connect only to this
worker-owned loopback listener through :mod:`network_broker`; the broker both
mints an exact one-shot connection grant and injects a per-request secret before
the controller's first HTTP byte.
"""
from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import select
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass

from .network_broker import (
    BrokerPolicy,
    ControlEndpointRegistry,
    NetworkBrokerRefused,
    NetworkEffectFence,
)


class CDPBridgeRefused(RuntimeError):
    """The DevTools control transport was malformed or lost authority."""


_MAX_CDP_HTTP_BYTES = 16 * 1024
_MAX_CDP_MESSAGE_BYTES = 16 * 1024 * 1024
_MAX_CDP_BUFFER_BYTES = 32 * 1024 * 1024
_MAX_CDP_RECORDS = 8192
_MAX_CDP_RECORD_BYTES = 1024
_MAX_CDP_SUMMARY_BYTES = _MAX_CDP_RECORDS * (_MAX_CDP_RECORD_BYTES + 1)
_MAX_CDP_FOREIGN_CLIENTS = 64
_CDP_AUTH_SECONDS = 0.25
_CDP_STOP_SECONDS = 2.0
_WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CDP_METHOD = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}\.[A-Za-z][A-Za-z0-9]{0,127}\Z")
_CERTIFICATE_BYPASS_METHODS = frozenset({
    "Security.setIgnoreCertificateErrors",
    "Security.setOverrideCertificateErrors",
    "Security.handleCertificateError",
})
_REQUEST_OVERRIDE_METHODS = frozenset({
    "Fetch.continueRequest",
    "Network.continueInterceptedRequest",
})
_REQUEST_HEADER_METHODS = _REQUEST_OVERRIDE_METHODS | frozenset({
    "Network.setExtraHTTPHeaders",
})
# These methods introduce a second CDP parser or a fresh proxy authority behind
# this admission point.  Inspecting only the outer document would let a
# controller hide a forbidden certificate/URL/header operation in
# ``params.message``, expose the protocol to page code, or replace the pinned
# browser route for a new context.  The attested adapters do not require these
# legacy/delegating surfaces, so refuse them rather than recursively inventing
# Chromium semantics here.
_ENCAPSULATED_AUTHORITY_METHODS = frozenset({
    "Target.sendMessageToTarget",
    "Target.exposeDevToolsProtocol",
    "Target.createBrowserContext",
})
_MAX_CDP_METHODS = 64


@dataclass(frozen=True)
class CDPBridgeRecord:
    sequence: int
    stage: str
    decision: str
    reason: str
    connection: int | None = None
    controller_tgid: int | None = None
    executable_sha256: str | None = None
    executable_bytes: int | None = None

    def to_dict(self) -> dict:
        document = {
            "sequence": self.sequence,
            "stage": self.stage,
            "decision": self.decision,
            "reason": self.reason,
        }
        if self.connection is not None:
            document["connection"] = self.connection
        if self.controller_tgid is not None:
            document["controller_tgid"] = self.controller_tgid
        if self.executable_sha256 is not None:
            document["executable_sha256"] = self.executable_sha256
        if self.executable_bytes is not None:
            document["executable_bytes"] = self.executable_bytes
        return document


class _BridgeCancellation:
    def __init__(self, local: threading.Event, shared):
        self.local = local
        self.shared = shared

    def is_set(self) -> bool:
        return self.local.is_set() or self.shared.is_set()

    def set(self) -> None:
        self.local.set()
        self.shared.set()


def _pipe_identity(fd: int, access: int) -> tuple[int, int]:
    if type(fd) is not int or fd < 0 or access not in {os.O_RDONLY, os.O_WRONLY}:
        raise CDPBridgeRefused("network_cdp_pipe_descriptor_invalid")
    try:
        observed = os.fstat(fd)
        target = os.readlink(f"/proc/self/fd/{fd}")
        status = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise CDPBridgeRefused("network_cdp_pipe_descriptor_invalid") from exc
    if (not stat.S_ISFIFO(observed.st_mode) or not target.startswith("pipe:[")
            or status & os.O_ACCMODE != access):
        raise CDPBridgeRefused("network_cdp_pipe_descriptor_invalid")
    return observed.st_dev, observed.st_ino


def pipe_exec_identity(chrome_read_fd: int,
                       chrome_write_fd: int) -> tuple[tuple[int, str, int, int], ...]:
    """Return the exact fixed-fd identity the child must attest before exec."""
    read_identity = _pipe_identity(chrome_read_fd, os.O_RDONLY)
    write_identity = _pipe_identity(chrome_write_fd, os.O_WRONLY)
    if read_identity == write_identity:
        raise CDPBridgeRefused("network_cdp_pipe_identity_collision")
    return (
        (3, "read", read_identity[0], read_identity[1]),
        (4, "write", write_identity[0], write_identity[1]),
    )


def _read_socket_exact(handle: socket.socket, size: int, *, deadline: float,
                       stop: threading.Event) -> bytes:
    body = bytearray()
    while len(body) < size:
        if stop.is_set() or time.monotonic() >= deadline:
            raise CDPBridgeRefused("network_cdp_control_cancelled")
        readable, _writable, exceptional = select.select(
            (handle,), (), (handle,), min(0.05, deadline - time.monotonic()),
        )
        if exceptional:
            raise CDPBridgeRefused("network_cdp_control_failed")
        if not readable:
            continue
        block = handle.recv(size - len(body))
        if not block:
            raise CDPBridgeRefused("network_cdp_control_truncated")
        body.extend(block)
    return bytes(body)


def _read_http(handle: socket.socket, *, deadline: float,
               stop: threading.Event) -> bytes:
    body = bytearray()
    while True:
        marker = body.find(b"\r\n\r\n")
        if marker >= 0:
            end = marker + 4
            if end != len(body):
                raise CDPBridgeRefused("network_cdp_http_pipelining_refused")
            return bytes(body)
        if len(body) >= _MAX_CDP_HTTP_BYTES:
            raise CDPBridgeRefused("network_cdp_http_header_oversize")
        if stop.is_set() or time.monotonic() >= deadline:
            raise CDPBridgeRefused("network_cdp_control_cancelled")
        readable, _writable, exceptional = select.select(
            (handle,), (), (handle,), min(0.05, deadline - time.monotonic()),
        )
        if exceptional:
            raise CDPBridgeRefused("network_cdp_control_failed")
        if not readable:
            continue
        block = handle.recv(_MAX_CDP_HTTP_BYTES + 1 - len(body))
        if not block:
            raise CDPBridgeRefused("network_cdp_http_header_truncated")
        body.extend(block)


def _write_socket_all(handle: socket.socket, body: bytes, *, deadline: float,
                      stop: threading.Event,
                      effect_fence: NetworkEffectFence) -> None:
    view = memoryview(body)
    while view:
        if stop.is_set() or time.monotonic() >= deadline:
            raise CDPBridgeRefused("network_cdp_control_cancelled")
        _readable, writable, exceptional = select.select(
            (), (handle,), (handle,), min(0.05, deadline - time.monotonic()),
        )
        if exceptional:
            raise CDPBridgeRefused("network_cdp_control_failed")
        if not writable:
            continue
        try:
            with effect_fence:
                written = handle.send(view)
        except BlockingIOError:
            continue
        if written <= 0:
            raise CDPBridgeRefused("network_cdp_control_failed")
        view = view[written:]


def _parse_http(body: bytes) -> tuple[str, dict[str, bytes]]:
    try:
        lines = body[:-4].split(b"\r\n")
        request = lines[0].split(b" ")
    except (IndexError, AttributeError) as exc:
        raise CDPBridgeRefused("network_cdp_http_request_malformed") from exc
    if len(request) != 3 or request[0] != b"GET" or request[2] != b"HTTP/1.1":
        raise CDPBridgeRefused("network_cdp_http_request_malformed")
    try:
        path = request[1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CDPBridgeRefused("network_cdp_http_request_malformed") from exc
    if not path.startswith("/") or any(value in path for value in ("#", "?", "\x00")):
        raise CDPBridgeRefused("network_cdp_http_request_malformed")
    headers: dict[str, bytes] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise CDPBridgeRefused("network_cdp_http_header_malformed")
        raw_name, raw_value = line.split(b":", 1)
        if not _TOKEN.fullmatch(raw_name):
            raise CDPBridgeRefused("network_cdp_http_header_malformed")
        name = raw_name.decode("ascii").lower()
        if name in headers:
            raise CDPBridgeRefused("network_cdp_http_header_duplicate")
        if (not raw_value.startswith(b" ") or raw_value.startswith(b"  ")
                or raw_value.endswith((b" ", b"\t")) or b"\t" in raw_value):
            raise CDPBridgeRefused("network_cdp_http_header_whitespace_invalid")
        value = raw_value[1:]
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value):
            raise CDPBridgeRefused("network_cdp_http_header_malformed")
        headers[name] = value
    if "transfer-encoding" in headers or headers.get("content-length", b"0") != b"0":
        raise CDPBridgeRefused("network_cdp_http_body_refused")
    return path, headers


def _websocket_accept(headers: dict[str, bytes], *, expected_host: str,
                      allow_legacy_nil_key: bool) -> bytes:
    if headers.get("host") != expected_host.encode("ascii"):
        raise CDPBridgeRefused("network_cdp_http_host_refused")
    if headers.get("upgrade", b"").lower() != b"websocket":
        raise CDPBridgeRefused("network_cdp_websocket_upgrade_invalid")
    connection = {
        token.strip().lower() for token in headers.get("connection", b"").split(b",")
    }
    if b"upgrade" not in connection or headers.get("sec-websocket-version") != b"13":
        raise CDPBridgeRefused("network_cdp_websocket_upgrade_invalid")
    if "sec-websocket-extensions" in headers or "sec-websocket-protocol" in headers:
        raise CDPBridgeRefused("network_cdp_websocket_extension_refused")
    if "origin" in headers:
        raise CDPBridgeRefused("network_cdp_websocket_origin_refused")
    key = headers.get("sec-websocket-key")
    if key is None or len(key) > 64:
        raise CDPBridgeRefused("network_cdp_websocket_key_invalid")
    if key == b"nil" and allow_legacy_nil_key:
        # Katana's attested CDP client uses this literal as non-security
        # metadata.  Admission is instead the broker's executable/Tgid/tuple
        # grant plus its unexported per-request preface.
        pass
    else:
        try:
            decoded = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise CDPBridgeRefused("network_cdp_websocket_key_invalid") from exc
        if len(decoded) != 16 or base64.b64encode(decoded) != key:
            raise CDPBridgeRefused("network_cdp_websocket_key_invalid")
    accepted = base64.b64encode(hashlib.sha1(key + _WS_GUID).digest())
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accepted + b"\r\n\r\n"
    )


def _frame(payload: bytes, opcode: int = 1) -> bytes:
    if len(payload) <= 125:
        prefix = bytes((0x80 | opcode, len(payload)))
    elif len(payload) <= 0xFFFF:
        prefix = bytes((0x80 | opcode, 126)) + struct.pack("!H", len(payload))
    else:
        prefix = bytes((0x80 | opcode, 127)) + struct.pack("!Q", len(payload))
    return prefix + payload


class PinnedCDPBridge:
    """One request-owned, one-controller-at-a-time DevTools pipe bridge."""

    def __init__(self, policy: BrokerPolicy, registry: ControlEndpointRegistry,
                 *, chrome_output_fd: int, chrome_input_fd: int,
                 adapter: str, controller_identity: tuple[str, int],
                 expected_controller_tgid: int,
                 deadline_monotonic: float,
                 cancellation_event: threading.Event | None = None,
                 effect_fence: NetworkEffectFence | None = None):
        if type(policy) is not BrokerPolicy or type(registry) is not ControlEndpointRegistry:
            raise CDPBridgeRefused("network_cdp_authority_invalid")
        if (type(deadline_monotonic) not in {int, float}
                or not math.isfinite(deadline_monotonic)
                or deadline_monotonic <= time.monotonic()):
            raise CDPBridgeRefused("network_cdp_deadline_invalid")
        if cancellation_event is not None \
                and not isinstance(cancellation_event, threading.Event):
            raise CDPBridgeRefused("network_cdp_cancellation_invalid")
        if ((effect_fence is not None
                and type(effect_fence) is not NetworkEffectFence)
                or (effect_fence is not None and cancellation_event is not None
                    and effect_fence.event is not cancellation_event)):
            raise CDPBridgeRefused("network_cdp_effect_fence_invalid")
        if (adapter not in {"katana", "gowitness", "nuclei"}
                or type(controller_identity) is not tuple
                or len(controller_identity) != 2
                or controller_identity not in policy.control_clients
                or type(expected_controller_tgid) is not int
                or not 1 <= expected_controller_tgid < (1 << 30)):
            raise CDPBridgeRefused("network_cdp_controller_authority_invalid")
        output_identity = _pipe_identity(chrome_output_fd, os.O_RDONLY)
        input_identity = _pipe_identity(chrome_input_fd, os.O_WRONLY)
        if output_identity == input_identity:
            raise CDPBridgeRefused("network_cdp_pipe_identity_collision")
        self._chrome_output = os.dup(chrome_output_fd)
        self._chrome_input = os.dup(chrome_input_fd)
        for fd in (self._chrome_output, self._chrome_input):
            fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self._pipe_identities = (output_identity, input_identity)
        self._policy = policy
        self._registry = registry
        self._deadline = float(deadline_monotonic)
        self._local_stop = threading.Event()
        self._effect_fence = effect_fence or NetworkEffectFence(cancellation_event)
        self._shared_stop = self._effect_fence
        self._stop = _BridgeCancellation(
            self._local_stop, self._shared_stop,
        )
        self._owner_token = object()
        self._listener: socket.socket | None = None
        self._registration = None
        self._authentication: bytes | None = None
        self._path = "/devtools/browser/" + os.urandom(16).hex()
        self._adapter = adapter
        self._controller_identity = controller_identity
        self._expected_controller_tgid = expected_controller_tgid
        self._thread: threading.Thread | None = None
        self._client: socket.socket | None = None
        self._lock = threading.Lock()
        self._records: list[CDPBridgeRecord] = []
        self._record_bytes = 0
        self._terminal_reservations = 0
        self._dropped = 0
        self._fatal: str | None = None
        self._foreign = 0
        self._connections = 0
        self._settled_connections = 0
        self._messages_to_chrome = 0
        self._messages_from_chrome = 0
        self._method_counts: dict[str, int] = {}
        self._discarded_async_bytes = 0
        self._normal_stop = False
        self._external_cancellation = False

    @property
    def endpoint(self) -> tuple[str, int]:
        listener = self._listener
        if listener is None:
            raise CDPBridgeRefused("network_cdp_not_started")
        peer = listener.getsockname()
        return str(peer[0]), int(peer[1])

    @property
    def websocket_url(self) -> str:
        peer, port = self.endpoint
        return f"ws://{peer}:{port}{self._path}"

    def _track_registration(self, registration) -> None:
        self._effect_fence.track_cleanup(
            registration,
            close=lambda: self._registry.close_worker_listener(registration),
            closed=lambda: self._registry.worker_listener_closed(registration),
        )

    def _close_registration(self) -> None:
        registration = self._registration
        if registration is None:
            return
        if not self._registry.worker_listener_closed(registration):
            try:
                self._effect_fence.close_tracked_cleanup(registration)
            except NetworkBrokerRefused:
                if not self._registry.worker_listener_closed(registration):
                    raise
        self._registration = None

    def _close_listener(self) -> None:
        listener = self._listener
        if listener is None:
            return
        self._effect_fence.close_tracked_socket(listener)
        self._listener = None

    def _close_client(self, client: socket.socket) -> None:
        self._effect_fence.close_tracked_socket(client)
        with self._lock:
            if self._client is client:
                self._client = None

    def _record(self, stage: str, decision: str, reason: str, *,
                connection: int | None = None, grant=None) -> bool:
        with self._lock:
            sequence = len(self._records) + self._dropped
            record = CDPBridgeRecord(
                sequence, stage, decision, reason, connection,
                (int(grant.client_tgid) if grant is not None else None),
                (grant.executable_identity[0] if grant is not None else None),
                (grant.executable_identity[1] if grant is not None else None),
            )
            encoded = json.dumps(
                record.to_dict(), ensure_ascii=True, sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(encoded) > _MAX_CDP_RECORD_BYTES:
                self._fatal = "network_cdp_record_oversize"
                self._stop.set()
                return False
            used_bytes = getattr(self, "_record_bytes", 0)
            if stage == "connection-planned":
                if self._terminal_reservations:
                    self._dropped += 1
                    self._fatal = "network_cdp_connection_plan_duplicate"
                    self._stop.set()
                    return False
                if (len(self._records) + 2 > _MAX_CDP_RECORDS
                        or used_bytes + len(encoded) + 1
                        + (_MAX_CDP_RECORD_BYTES + 1)
                        > _MAX_CDP_SUMMARY_BYTES):
                    self._dropped += 1
                    self._fatal = "network_cdp_record_overflow"
                    self._stop.set()
                    return False
                self._records.append(record)
                self._record_bytes = used_bytes + len(encoded) + 1
                self._terminal_reservations = 1
                return True
            if stage == "connection-settled" and connection == 1:
                if self._terminal_reservations != 1:
                    self._dropped += 1
                    self._fatal = "network_cdp_connection_plan_missing"
                    self._stop.set()
                    return False
                if (used_bytes + len(encoded) + 1
                        > _MAX_CDP_SUMMARY_BYTES):
                    self._dropped += 1
                    self._fatal = "network_cdp_record_overflow"
                    self._stop.set()
                    return False
                self._records.append(record)
                self._record_bytes = used_bytes + len(encoded) + 1
                self._terminal_reservations = 0
                return True
            if (len(self._records) + self._terminal_reservations
                    >= _MAX_CDP_RECORDS
                    or used_bytes + len(encoded) + 1
                    + self._terminal_reservations
                    * (_MAX_CDP_RECORD_BYTES + 1)
                    > _MAX_CDP_SUMMARY_BYTES):
                self._dropped += 1
                self._fatal = "network_cdp_record_overflow"
                self._stop.set()
                return False
            self._records.append(record)
            self._record_bytes = used_bytes + len(encoded) + 1
            return True

    def start(self) -> None:
        if self._thread is not None or self._listener is not None:
            raise CDPBridgeRefused("network_cdp_already_started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self._listener = listener
        primary = None
        try:
            self._effect_fence.track_socket(listener)
            with self._effect_fence:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                listener.bind(("127.0.0.1", 0))
                listener.listen(_MAX_CDP_FOREIGN_CLIENTS + 1)
                listener.setblocking(False)
                if self._effect_fence.is_set():
                    raise NetworkBrokerRefused("network_effect_fence_closed")
                registration = self._registry.register_worker_listener(
                    request_id=self._policy.request_id,
                    listener_fd=listener.fileno(),
                    client_identities=(self._controller_identity,),
                    client_tgids=(self._expected_controller_tgid,),
                    purpose="browser-devtools-pipe", owner_token=self._owner_token,
                )
                self._registration = registration
                self._track_registration(registration)
                if (registration.authentication is None
                        or len(registration.authentication) != 32):
                    raise CDPBridgeRefused(
                        "network_cdp_authentication_invalid",
                    )
                self._authentication = b"QCD1" + registration.authentication
                thread = threading.Thread(
                    target=self._run,
                    name="quarry-cdp-bridge", daemon=False,
                )
                self._thread = thread
                thread.start()
                if self._effect_fence.is_set():
                    raise NetworkBrokerRefused("network_effect_fence_closed")
            return
        except BaseException as exc:
            primary = exc

        self._local_stop.set()
        cleanup_fault = None
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=_CDP_STOP_SECONDS)
            if thread.is_alive():
                cleanup_fault = CDPBridgeRefused(
                    "network_cdp_thread_settlement_failed",
                )
        for cleanup in (self._close_registration, self._close_listener):
            try:
                cleanup()
            except BaseException as exc:
                if cleanup_fault is None:
                    cleanup_fault = exc
        self._authentication = None
        for name in ("_chrome_output", "_chrome_input"):
            fd = getattr(self, name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as exc:
                    if cleanup_fault is None:
                        cleanup_fault = exc
                else:
                    setattr(self, name, -1)
        if cleanup_fault is not None:
            raise cleanup_fault from primary
        raise primary.with_traceback(primary.__traceback__)

    def _run(self) -> None:
        try:
            while not self._stop.is_set() and time.monotonic() < self._deadline:
                listener = self._listener
                registration = self._registration
                if listener is None or registration is None:
                    return
                readable, _writable, exceptional = select.select(
                    (listener,), (), (listener,), 0.05,
                )
                if exceptional:
                    if self._local_stop.is_set():
                        return
                    raise CDPBridgeRefused("network_cdp_listener_failed")
                if not readable:
                    continue
                client = None
                try:
                    # The accepted fd and its cancellation owner are created
                    # in one epoch; cancel cannot return in the middle.
                    with self._effect_fence:
                        client, peer = listener.accept()
                        self._effect_fence.track_socket(client)
                        client.setblocking(False)
                        with self._lock:
                            self._client = client
                except BlockingIOError:
                    continue
                except NetworkBrokerRefused:
                    if client is not None:
                        try:
                            live = client.fileno() >= 0
                        except OSError:
                            live = True
                        if live:
                            with self._lock:
                                self._client = client
                    return
                if peer[0] != "127.0.0.1":
                    self._close_client(client)
                    self._foreign += 1
                    self._record("accept", "deny", "non-loopback controller refused")
                    continue
                grant = self._registry.consume_connection(
                    registration, accepted_fd=client.fileno(),
                    deadline_monotonic=min(
                        self._deadline, time.monotonic() + _CDP_AUTH_SECONDS,
                    ), stop_event=self._stop,
                )
                if grant is None:
                    self._close_client(client)
                    self._foreign += 1
                    self._record("accept", "deny", "controller grant missing")
                    if self._foreign >= _MAX_CDP_FOREIGN_CLIENTS:
                        raise CDPBridgeRefused("network_cdp_foreign_client_capacity")
                    continue
                if grant.client_tgid != self._expected_controller_tgid:
                    self._close_client(client)
                    self._foreign += 1
                    self._record(
                        "accept", "deny", "controller Tgid grant mismatch",
                        grant=grant,
                    )
                    continue
                if self._connections != 0:
                    self._close_client(client)
                    self._record(
                        "connection-settled", "deny",
                        "DevTools controller reconnect refused",
                        connection=self._connections + 1, grant=grant,
                    )
                    raise CDPBridgeRefused("network_cdp_connection_count_exceeded")
                self._connections = 1
                if not self._record(
                        "connection-planned", "allow",
                        "exact controller grant admitted",
                        connection=1, grant=grant):
                    self._close_client(client)
                    raise CDPBridgeRefused("network_cdp_trace_authority_failed")
                try:
                    result = self._serve(client, grant, connection=1)
                except BaseException as exc:
                    self._record(
                        "connection-settled", "deny",
                        (str(exc) if isinstance(exc, CDPBridgeRefused)
                         else "DevTools controller did not settle"),
                        connection=1, grant=grant,
                    )
                    raise
                else:
                    self._settled_connections = 1
                    if not self._record(
                            "connection-settled", "allow", result,
                            connection=1, grant=grant):
                        raise CDPBridgeRefused(
                            "network_cdp_trace_authority_failed",
                        )
                finally:
                    self._close_client(client)
            if time.monotonic() >= self._deadline \
                    and not self._local_stop.is_set():
                raise CDPBridgeRefused("network_cdp_deadline_expired")
            if self._shared_stop.is_set() and not self._local_stop.is_set():
                self._external_cancellation = True
                raise CDPBridgeRefused("network_cdp_external_cancellation")
        except BaseException as exc:
            if not self._stop.is_set():
                self._fatal = (
                    str(exc) if isinstance(exc, CDPBridgeRefused)
                    else "network_cdp_bridge_failed"
                )
                self._stop.set()

    def _serve(self, client: socket.socket, grant, *, connection: int) -> str:
        authentication = self._authentication
        if authentication is None:
            raise CDPBridgeRefused("network_cdp_authentication_invalid")
        handshake_deadline = min(
            self._deadline, time.monotonic() + _CDP_AUTH_SECONDS,
        )
        prefix = _read_socket_exact(
            client, len(authentication), deadline=handshake_deadline,
            stop=self._stop,
        )
        if prefix != authentication:
            raise CDPBridgeRefused("network_cdp_authentication_refused")
        if not self._record(
                "authentication", "allow", "broker-injected preface",
                connection=connection, grant=grant):
            raise CDPBridgeRefused("network_cdp_trace_authority_failed")
        request = _read_http(
            client, deadline=min(self._deadline, time.monotonic() + 1.0),
            stop=self._stop,
        )
        path, headers = _parse_http(request)
        expected_host = f"{self.endpoint[0]}:{self.endpoint[1]}"
        if path != self._path:
            raise CDPBridgeRefused("network_cdp_endpoint_refused")
        legacy_nil = (
            self._adapter == "katana"
            and grant.executable_identity == self._controller_identity
        )
        response = _websocket_accept(
            headers, expected_host=expected_host,
            allow_legacy_nil_key=legacy_nil,
        )
        _write_socket_all(
            client, response, deadline=min(
                self._deadline, time.monotonic() + 1.0,
            ), stop=self._stop, effect_fence=self._effect_fence,
        )
        upgrade_reason = (
            "katana-nil-key-compat"
            if headers.get("sec-websocket-key") == b"nil" else
            "strict DevTools upgrade"
        )
        if not self._record(
                "websocket", "allow", upgrade_reason,
                connection=connection, grant=grant):
            raise CDPBridgeRefused("network_cdp_trace_authority_failed")
        return self._relay(client)

    @staticmethod
    def _document(payload: bytes) -> dict:
        if type(payload) is not bytes or len(payload) > _MAX_CDP_MESSAGE_BYTES:
            raise CDPBridgeRefused("network_cdp_message_invalid")

        def unique_object(pairs):
            document = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError("duplicate JSON object key")
                document[key] = value
            return document

        def refuse_nonfinite(_value):
            raise ValueError("non-finite JSON number")

        try:
            document = json.loads(
                payload,
                object_pairs_hook=unique_object,
                parse_constant=refuse_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CDPBridgeRefused("network_cdp_message_invalid") from exc
        if type(document) is not dict:
            raise CDPBridgeRefused("network_cdp_message_invalid")
        return document

    def _admit_client_document(self, document: dict) -> None:
        method = document.get("method")
        if method is None:
            return
        if type(method) is not str or _CDP_METHOD.fullmatch(method) is None:
            raise CDPBridgeRefused("network_cdp_method_invalid")
        if method in _ENCAPSULATED_AUTHORITY_METHODS:
            raise CDPBridgeRefused(
                "network_cdp_encapsulated_authority_refused",
            )
        if method in _CERTIFICATE_BYPASS_METHODS:
            raise CDPBridgeRefused("network_cdp_certificate_bypass_refused")
        params = document.get("params", {})
        if type(params) is not dict:
            raise CDPBridgeRefused("network_cdp_message_invalid")
        if method in _REQUEST_OVERRIDE_METHODS and "url" in params:
            # A controller may observe and resume a paused request, but it may
            # not substitute an authority after the browser proxy admitted the
            # original request.  Reject even an equal-looking URL: accepting it
            # would make canonicalization and redirect authority depend on the
            # controller's representation.
            raise CDPBridgeRefused("network_cdp_url_override_refused")
        if method in _REQUEST_HEADER_METHODS and "headers" in params:
            self._admit_request_headers(params["headers"])
        if method not in self._method_counts:
            if len(self._method_counts) >= _MAX_CDP_METHODS:
                raise CDPBridgeRefused("network_cdp_method_inventory_oversize")
            self._method_counts[method] = 0
        self._method_counts[method] += 1

    @staticmethod
    def _admit_request_headers(headers) -> None:
        """Refuse controller-provided HTTP authority headers.

        Fetch uses an array of ``HeaderEntry`` objects while Network uses a
        string map.  Supporting both exact CDP shapes is necessary for the two
        attested controllers; accepting another shape would make a malformed
        authority override invisible to this boundary.
        """
        names: list[str] = []
        if type(headers) is dict:
            for name, value in headers.items():
                if type(name) is not str or type(value) is not str:
                    raise CDPBridgeRefused("network_cdp_request_headers_invalid")
                names.append(name)
        elif type(headers) is list:
            for entry in headers:
                if (type(entry) is not dict
                        or set(entry) != {"name", "value"}
                        or type(entry["name"]) is not str
                        or type(entry["value"]) is not str):
                    raise CDPBridgeRefused("network_cdp_request_headers_invalid")
                names.append(entry["name"])
        else:
            raise CDPBridgeRefused("network_cdp_request_headers_invalid")
        for name in names:
            lowered = name.strip().lower()
            if lowered in {"host", ":authority"}:
                raise CDPBridgeRefused("network_cdp_authority_header_refused")
            if (not lowered or "\x00" in name or "\r" in name or "\n" in name):
                raise CDPBridgeRefused("network_cdp_request_headers_invalid")

    def _relay(self, client: socket.socket) -> str:
        network_input = bytearray()
        network_output = bytearray()
        chrome_input = bytearray()
        chrome_output = bytearray()
        fragmented: bytearray | None = None
        pending_ids: set[tuple[str | None, int]] = set()
        response_ids_in_output: set[tuple[str | None, int]] = set()
        while not self._stop.is_set() and time.monotonic() < self._deadline:
            if any(len(value) > _MAX_CDP_BUFFER_BYTES for value in (
                    network_input, network_output, chrome_input, chrome_output)):
                raise CDPBridgeRefused("network_cdp_backpressure_oversize")
            readable = []
            if len(network_input) < _MAX_CDP_BUFFER_BYTES:
                readable.append(client)
            if len(chrome_output) < _MAX_CDP_BUFFER_BYTES:
                readable.append(self._chrome_output)
            writable = []
            if network_output:
                writable.append(client)
            if chrome_input:
                writable.append(self._chrome_input)
            observed_read, observed_write, exceptional = select.select(
                readable, writable, (client,), 0.05,
            )
            if exceptional:
                raise CDPBridgeRefused("network_cdp_control_failed")
            if client in observed_read:
                block = client.recv(min(64 * 1024, _MAX_CDP_BUFFER_BYTES - len(network_input)))
                if not block:
                    if (network_input or chrome_input or fragmented is not None
                            or pending_ids or response_ids_in_output):
                        raise CDPBridgeRefused(
                            "network_cdp_controller_eof_with_pending_data",
                        )
                    discarded = len(network_output) + len(chrome_output)
                    self._discarded_async_bytes += discarded
                    return (
                        "controller-eof-clean"
                        if discarded == 0 else
                        f"controller-eof-clean;unrequested-async-bytes:{discarded}"
                    )
                network_input.extend(block)
            if self._chrome_output in observed_read:
                try:
                    block = os.read(
                        self._chrome_output,
                        min(64 * 1024, _MAX_CDP_BUFFER_BYTES - len(chrome_output)),
                    )
                except BlockingIOError:
                    block = None
                if block == b"":
                    raise CDPBridgeRefused("network_cdp_chrome_pipe_closed")
                if block:
                    chrome_output.extend(block)
            while True:
                parsed = self._parse_client_frame(network_input, fragmented)
                if parsed is None:
                    break
                consumed, opcode, payload, fragmented = parsed
                del network_input[:consumed]
                if opcode == 8:
                    network_output.extend(_frame(payload, 8))
                    if network_output:
                        self._flush_socket(client, network_output)
                    if not network_output and response_ids_in_output:
                        pending_ids.difference_update(response_ids_in_output)
                        response_ids_in_output.clear()
                    if (network_input or chrome_input or fragmented is not None
                            or pending_ids or response_ids_in_output):
                        raise CDPBridgeRefused(
                            "network_cdp_close_with_pending_data",
                        )
                    discarded = len(network_output) + len(chrome_output)
                    self._discarded_async_bytes += discarded
                    return (
                        "websocket-close-clean"
                        if discarded == 0 else
                        f"websocket-close-clean;unrequested-async-bytes:{discarded}"
                    )
                if opcode == 9:
                    network_output.extend(_frame(payload, 10))
                elif opcode == 1:
                    document = self._document(payload)
                    self._admit_client_document(document)
                    identifier = document.get("id")
                    if type(identifier) is int:
                        session = document.get("sessionId")
                        if session is not None and type(session) is not str:
                            raise CDPBridgeRefused("network_cdp_message_invalid")
                        key = (session, identifier)
                        if key in pending_ids:
                            raise CDPBridgeRefused("network_cdp_request_id_duplicate")
                        pending_ids.add(key)
                    chrome_input.extend(payload + b"\x00")
                    self._messages_to_chrome += 1
            while True:
                marker = chrome_output.find(b"\x00")
                if marker < 0:
                    if len(chrome_output) > _MAX_CDP_MESSAGE_BYTES:
                        raise CDPBridgeRefused("network_cdp_chrome_message_oversize")
                    break
                payload = bytes(chrome_output[:marker])
                del chrome_output[:marker + 1]
                if not payload:
                    raise CDPBridgeRefused("network_cdp_chrome_message_invalid")
                document = self._document(payload)
                identifier = document.get("id")
                if type(identifier) is int:
                    session = document.get("sessionId")
                    if session is not None and type(session) is not str:
                        raise CDPBridgeRefused("network_cdp_message_invalid")
                    key = (session, identifier)
                    if key not in pending_ids or key in response_ids_in_output:
                        raise CDPBridgeRefused("network_cdp_response_id_unmatched")
                    response_ids_in_output.add(key)
                network_output.extend(_frame(payload))
                self._messages_from_chrome += 1
            if client in observed_write:
                self._flush_socket(client, network_output)
                if not network_output and response_ids_in_output:
                    pending_ids.difference_update(response_ids_in_output)
                    response_ids_in_output.clear()
            if self._chrome_input in observed_write and chrome_input:
                try:
                    with self._effect_fence:
                        written = os.write(self._chrome_input, chrome_input)
                except BlockingIOError:
                    written = 0
                if written > 0:
                    del chrome_input[:written]
        raise CDPBridgeRefused("network_cdp_control_cancelled")

    def _flush_socket(self, client: socket.socket, buffer: bytearray) -> None:
        if not buffer:
            return
        try:
            with self._effect_fence:
                written = client.send(buffer)
        except BlockingIOError:
            return
        if written <= 0:
            raise CDPBridgeRefused("network_cdp_control_failed")
        del buffer[:written]

    @staticmethod
    def _parse_client_frame(buffer: bytearray,
                            fragmented: bytearray | None):
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        if first & 0x70 or not second & 0x80:
            raise CDPBridgeRefused("network_cdp_websocket_frame_invalid")
        final = bool(first & 0x80)
        opcode = first & 0x0F
        length = second & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < 4:
                return None
            length = struct.unpack_from("!H", buffer, 2)[0]
            if length < 126:
                raise CDPBridgeRefused("network_cdp_websocket_length_noncanonical")
            offset = 4
        elif length == 127:
            if len(buffer) < 10:
                return None
            length = struct.unpack_from("!Q", buffer, 2)[0]
            if length < 65536 or length >> 63:
                raise CDPBridgeRefused("network_cdp_websocket_length_noncanonical")
            offset = 10
        if length > _MAX_CDP_MESSAGE_BYTES or len(buffer) < offset + 4 + length:
            if length > _MAX_CDP_MESSAGE_BYTES:
                raise CDPBridgeRefused("network_cdp_websocket_message_oversize")
            return None
        mask = bytes(buffer[offset:offset + 4])
        offset += 4
        payload = bytes(
            value ^ mask[index & 3]
            for index, value in enumerate(buffer[offset:offset + length])
        )
        consumed = offset + length
        if opcode & 0x8:
            if not final or length > 125 or opcode not in {8, 9, 10}:
                raise CDPBridgeRefused("network_cdp_websocket_control_invalid")
            if opcode == 8 and length == 1:
                raise CDPBridgeRefused("network_cdp_websocket_close_invalid")
            return consumed, opcode, payload, fragmented
        if opcode == 2 or opcode not in {0, 1}:
            raise CDPBridgeRefused("network_cdp_websocket_opcode_refused")
        if opcode == 1:
            if fragmented is not None:
                raise CDPBridgeRefused("network_cdp_websocket_fragment_invalid")
            if final:
                return consumed, 1, payload, None
            fragmented = bytearray(payload)
            return consumed, -1, b"", fragmented
        if fragmented is None:
            raise CDPBridgeRefused("network_cdp_websocket_fragment_invalid")
        fragmented.extend(payload)
        if len(fragmented) > _MAX_CDP_MESSAGE_BYTES:
            raise CDPBridgeRefused("network_cdp_websocket_message_oversize")
        if final:
            payload = bytes(fragmented)
            return consumed, 1, payload, None
        return consumed, -1, b"", fragmented

    def stop(self) -> None:
        deadline = time.monotonic() + _CDP_STOP_SECONDS
        self._normal_stop = True
        if self._shared_stop.is_set():
            self._external_cancellation = True
        self._local_stop.set()
        self._authentication = None
        for cleanup in (self._close_registration, self._close_listener):
            try:
                cleanup()
            except NetworkBrokerRefused as exc:
                self._fatal = self._fatal or str(exc)
        with self._lock:
            client = self._client
        if client is not None:
            try:
                self._close_client(client)
            except NetworkBrokerRefused as exc:
                self._fatal = self._fatal or str(exc)
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                self._fatal = self._fatal or "network_cdp_thread_settlement_failed"
        for name in ("_chrome_output", "_chrome_input"):
            fd = getattr(self, name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)

    def summary(self) -> dict:
        with self._lock:
            records = [record.to_dict() for record in self._records]
            active_client = self._client is not None
        thread_alive = self._thread is not None and self._thread.is_alive()
        return {
            "schema_version": "quarry.network-cdp-summary.v1",
            "request_id": self._policy.request_id,
            "adapter": self._adapter,
            "controller_identity": {
                "sha256": self._controller_identity[0],
                "bytes": self._controller_identity[1],
            },
            "expected_controller_tgid": self._expected_controller_tgid,
            "records": records,
            "dropped_records": self._dropped,
            "open_plans": self._terminal_reservations,
            "foreign_clients": self._foreign,
            "connections": self._connections,
            "settled_connections": self._settled_connections,
            "messages_to_chrome": self._messages_to_chrome,
            "messages_from_chrome": self._messages_from_chrome,
            "method_counts": dict(sorted(self._method_counts.items())),
            "discarded_async_bytes": self._discarded_async_bytes,
            "pipe_identities": [list(value) for value in self._pipe_identities],
            "fatal": self._fatal,
            "external_cancellation": self._external_cancellation,
            "active_client": active_client,
            "thread_alive": thread_alive,
            "complete": (
                self._fatal is None and self._dropped == 0
                and self._terminal_reservations == 0
                and not active_client and not thread_alive
                and self._listener is None and self._registration is None
                and self._chrome_output < 0 and self._chrome_input < 0
                and self._normal_stop and not self._external_cancellation
                and self._connections == 1 and self._settled_connections == 1
                and self._messages_to_chrome > 0
                and self._messages_from_chrome > 0
            ),
        }


__all__ = (
    "CDPBridgeRefused", "PinnedCDPBridge", "pipe_exec_identity",
)
