"""Runner-owned pinned HTTP/CONNECT and SOCKS5 proxy for sandboxed lanes."""
from __future__ import annotations

import errno
import ipaddress
import json
import re
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import normalize
from .network_broker import (
    BrokerPolicy,
    ControlEndpointRegistry,
    NetworkEffectFence,
    NetworkBrokerRefused,
)
from . import network_dns


_MAX_PROXY_HEADER_BYTES = 64 * 1024
_MAX_PROXY_LINE_BYTES = 8 * 1024
_MAX_PROXY_AUTHORITY_BYTES = 1024
_MAX_PROXY_REQUEST_BODY_BYTES = 64 * 1024 * 1024
_MAX_PROXY_CONNECTIONS = 256
_MAX_PROXY_RECORDS = 8192
_MAX_PROXY_RECORD_BYTES = 1024
_MAX_PROXY_SUMMARY_BYTES = _MAX_PROXY_RECORDS * (_MAX_PROXY_RECORD_BYTES + 1)
_MAX_PROXY_BUFFER_BYTES = 64 * 1024
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_NUCLEI_DNS_OPT = struct.Struct("!BHHIH")
_NUCLEI_DNS_OPT_UDP_SIZE = 4096


class BrowserProxyRefused(NetworkBrokerRefused):
    """A browser proxy request or authority was not safely admissible."""


class _SocksProxyRefused(BrowserProxyRefused):
    """A SOCKS5 request was refused after protocol selection."""


@dataclass(frozen=True)
class ProxyRecord:
    sequence: int
    stage: str
    method: str
    host: str | None
    port: int | None
    peer: str | None
    decision: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "stage": self.stage,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "peer": self.peer,
            "decision": self.decision,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class _Request:
    method: str
    host: str
    port: int
    connect: bool
    forwarded_head: bytes
    body_length: int
    initial_body: bytes
    upgrade: bool


def _canonical_host(value: str) -> str:
    if (not value or len(value.encode("ascii", "strict")) > 253
            or value != value.strip() or "%" in value):
        raise BrowserProxyRefused("network_proxy_authority_invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        canonical = normalize.canon_host_strict(value)
        if canonical is None:
            raise BrowserProxyRefused("network_proxy_authority_invalid")
        return canonical
    return str(getattr(address, "ipv4_mapped", None) or address)


def _authority(value: str, *, default_port: int | None,
               require_port: bool) -> tuple[str, int]:
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BrowserProxyRefused("network_proxy_authority_invalid") from exc
    if (not raw or len(raw) > _MAX_PROXY_AUTHORITY_BYTES or b"@" in raw
            or any(byte <= 0x20 or byte == 0x7F for byte in raw)
            or any(byte in b"/?#\\" for byte in raw)):
        raise BrowserProxyRefused("network_proxy_authority_invalid")
    host_text = ""
    port_text = None
    if value.startswith("["):
        close = value.find("]")
        if close <= 1:
            raise BrowserProxyRefused("network_proxy_authority_invalid")
        host_text = value[1:close]
        remainder = value[close + 1:]
        if remainder:
            if not remainder.startswith(":") or not remainder[1:]:
                raise BrowserProxyRefused("network_proxy_authority_invalid")
            port_text = remainder[1:]
        try:
            if ipaddress.ip_address(host_text).version != 6:
                raise ValueError
        except ValueError as exc:
            raise BrowserProxyRefused("network_proxy_authority_invalid") from exc
    else:
        if value.count(":") > 1:
            raise BrowserProxyRefused("network_proxy_authority_invalid")
        if ":" in value:
            host_text, port_text = value.rsplit(":", 1)
            if not port_text:
                raise BrowserProxyRefused("network_proxy_authority_invalid")
        else:
            host_text = value
    if require_port and port_text is None:
        raise BrowserProxyRefused("network_proxy_authority_invalid")
    if port_text is None:
        port = default_port
    elif not port_text.isascii() or not port_text.isdecimal():
        raise BrowserProxyRefused("network_proxy_authority_invalid")
    else:
        port = int(port_text)
    if type(port) is not int or not 1 <= port <= 65535:
        raise BrowserProxyRefused("network_proxy_authority_invalid")
    return _canonical_host(host_text.lower()), port


def _header_authority(value: str, *, default_port: int) -> tuple[str, int]:
    return _authority(value.strip(), default_port=default_port, require_port=False)


def _parse_request(header: bytes, remainder: bytes) -> _Request:
    if (not header.endswith(b"\r\n\r\n")
            or b"\x00" in header or b"\n\n" in header
            or any(byte < 0x20 and byte not in {0x0D, 0x0A} for byte in header)
            or any(byte >= 0x7F for byte in header)):
        raise BrowserProxyRefused("network_proxy_header_invalid")
    lines = header[:-4].split(b"\r\n")
    if (not lines or any(len(line) > _MAX_PROXY_LINE_BYTES for line in lines)
            or any(not line for line in lines)):
        raise BrowserProxyRefused("network_proxy_header_invalid")
    request_parts = lines[0].split(b" ")
    if (len(request_parts) != 3 or not _TOKEN.fullmatch(request_parts[0])
            or request_parts[2] != b"HTTP/1.1"):
        raise BrowserProxyRefused("network_proxy_request_line_invalid")
    try:
        method = request_parts[0].decode("ascii", "strict")
        target = request_parts[1].decode("ascii", "strict")
    except UnicodeError as exc:
        raise BrowserProxyRefused("network_proxy_request_line_invalid") from exc
    if method != method.upper() or not target:
        raise BrowserProxyRefused("network_proxy_request_line_invalid")
    headers: list[tuple[str, str]] = []
    by_name: dict[str, list[str]] = {}
    for raw in lines[1:]:
        if raw[:1] in {b" ", b"\t"} or b":" not in raw:
            raise BrowserProxyRefused("network_proxy_header_invalid")
        name, value = raw.split(b":", 1)
        if not _TOKEN.fullmatch(name):
            raise BrowserProxyRefused("network_proxy_header_invalid")
        value = value.strip(b" \t")
        if any(byte < 0x20 and byte != 0x09 for byte in value):
            raise BrowserProxyRefused("network_proxy_header_invalid")
        key = name.decode("ascii", "strict").lower()
        text = value.decode("ascii", "strict")
        headers.append((key, text))
        by_name.setdefault(key, []).append(text)
    if len(by_name.get("host", ())) != 1:
        raise BrowserProxyRefused("network_proxy_host_header_invalid")
    if ("proxy-authorization" in by_name or "proxy-authenticate" in by_name
            or "transfer-encoding" in by_name
            or len(by_name.get("content-length", ())) > 1):
        raise BrowserProxyRefused("network_proxy_ambiguous_framing_refused")
    raw_length = by_name.get("content-length", ["0"])[0]
    if (not raw_length.isascii() or not raw_length.isdecimal()
            or len(raw_length) > 20):
        raise BrowserProxyRefused("network_proxy_ambiguous_framing_refused")
    body_length = int(raw_length)
    if body_length > _MAX_PROXY_REQUEST_BODY_BYTES or len(remainder) > body_length:
        raise BrowserProxyRefused("network_proxy_request_body_invalid")
    connection_tokens: set[str] = set()
    for value in by_name.get("connection", ()): 
        for token in value.split(","):
            normalized = token.strip().lower()
            if not normalized or _TOKEN.fullmatch(normalized.encode("ascii")) is None:
                raise BrowserProxyRefused("network_proxy_header_invalid")
            connection_tokens.add(normalized)
    if connection_tokens & {
            "host", "content-length", "transfer-encoding", "connection",
            "proxy-authorization", "proxy-authenticate", "te", "trailer",
        }:
        raise BrowserProxyRefused("network_proxy_connection_token_refused")
    upgrade = "upgrade" in connection_tokens
    if upgrade != (len(by_name.get("upgrade", ())) == 1):
        raise BrowserProxyRefused("network_proxy_upgrade_invalid")
    if method == "CONNECT":
        host, port = _authority(target, default_port=None, require_port=True)
        if _header_authority(by_name["host"][0], default_port=port) != (host, port):
            raise BrowserProxyRefused("network_proxy_host_header_invalid")
        if body_length or remainder or upgrade:
            raise BrowserProxyRefused("network_proxy_connect_framing_invalid")
        return _Request(method, host, port, True, b"", 0, b"", False)
    try:
        parts = urlsplit(target)
        parsed_port = parts.port
    except ValueError as exc:
        raise BrowserProxyRefused("network_proxy_absolute_url_invalid") from exc
    if (parts.scheme != "http" or not parts.netloc or parts.username is not None
            or parts.password is not None or parts.fragment or "@" in parts.netloc
            or not parts.hostname):
        raise BrowserProxyRefused("network_proxy_absolute_url_invalid")
    host = _canonical_host(parts.hostname.lower())
    port = parsed_port or 80
    if _header_authority(by_name["host"][0], default_port=80) != (host, port):
        raise BrowserProxyRefused("network_proxy_host_header_invalid")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        request_target = path.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BrowserProxyRefused("network_proxy_absolute_url_invalid") from exc
    hop = {
        "connection", "keep-alive", "proxy-connection", "proxy-authorization",
        "proxy-authenticate", "te", "trailer", "transfer-encoding",
    } | connection_tokens
    if upgrade:
        hop.discard("upgrade")
    rendered = [method.encode("ascii") + b" " + request_target + b" HTTP/1.1"]
    rendered.append(b"Host: " + (
        (b"[" + host.encode("ascii") + b"]") if ":" in host else host.encode("ascii")
    ) + (b"" if port == 80 else b":" + str(port).encode("ascii")))
    for name, value in headers:
        if name == "host" or name in hop:
            continue
        rendered.append(name.encode("ascii") + b": " + value.encode("ascii"))
    if upgrade:
        rendered.append(b"Connection: Upgrade")
    else:
        rendered.append(b"Connection: close")
    forwarded = b"\r\n".join(rendered) + b"\r\n\r\n"
    if len(forwarded) > _MAX_PROXY_HEADER_BYTES:
        raise BrowserProxyRefused("network_proxy_header_oversize")
    return _Request(
        method, host, port, False, forwarded, body_length, remainder, upgrade,
    )


class PinnedBrowserProxy:
    """One private request-scoped proxy and its finite decision journal."""

    def __init__(self, policy: BrokerPolicy, registry: ControlEndpointRegistry,
                 *, deadline_monotonic: float,
                 cancellation_event: threading.Event | None = None,
                 effect_fence: NetworkEffectFence | None = None):
        if (type(policy) is not BrokerPolicy
                or type(registry) is not ControlEndpointRegistry
                or type(deadline_monotonic) not in {int, float}
                or not time.monotonic() < deadline_monotonic
                or (cancellation_event is not None
                    and not isinstance(cancellation_event, threading.Event))
                or (effect_fence is not None
                    and type(effect_fence) is not NetworkEffectFence)
                or (effect_fence is not None and cancellation_event is not None
                    and effect_fence.event is not cancellation_event)):
            raise BrowserProxyRefused("network_proxy_session_invalid")
        self._policy = policy
        self._registry = registry
        self._deadline = float(deadline_monotonic)
        self._local_stop = threading.Event()
        self._effect_fence = effect_fence or NetworkEffectFence(cancellation_event)
        self._shared_stop = self._effect_fence

        class Cancellation:
            def is_set(inner_self):
                return (self._local_stop.is_set()
                        or self._shared_stop.is_set())

            def set(inner_self):
                self._shared_stop.cancel()

        self._stop = Cancellation()
        self._lock = threading.Lock()
        self._records: list[ProxyRecord] = []
        self._record_bytes = 0
        self._open_plans: dict[tuple[int, str], int] = {}
        self._dropped = 0
        self._fatal: str | None = None
        self._listener: socket.socket | None = None
        self._registration = None
        self._authentication: bytes | None = None
        self._owner_token = object()
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self._sockets: set[socket.socket] = set()
        self._slots = threading.BoundedSemaphore(_MAX_PROXY_CONNECTIONS)

    @property
    def endpoint(self) -> tuple[str, int]:
        listener = self._listener
        if listener is None:
            raise BrowserProxyRefused("network_proxy_not_started")
        value = listener.getsockname()
        return str(value[0]), int(value[1])

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

    def start(self) -> None:
        if self._listener is not None:
            raise BrowserProxyRefused("network_proxy_already_started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self._listener = listener
        primary = None
        try:
            self._effect_fence.track_socket(listener)
            with self._effect_fence:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                listener.bind(("127.0.0.1", 0))
                listener.listen(_MAX_PROXY_CONNECTIONS)
                listener.setblocking(False)
                if self._effect_fence.is_set():
                    raise NetworkBrokerRefused("network_effect_fence_closed")
                client_identities = (
                    self._policy.control_clients
                    if self._policy.transport_profile in {
                        "target-http-proxy", "nuclei-authorized-http",
                    }
                    else self._policy.control_helpers
                )
                registration = self._registry.register_worker_listener(
                    request_id=self._policy.request_id,
                    listener_fd=listener.fileno(),
                    client_identities=client_identities,
                    purpose="pinned-browser-proxy", owner_token=self._owner_token,
                )
                self._registration = registration
                self._track_registration(registration)
                if (registration.authentication is None
                        or len(registration.authentication) != 32):
                    raise BrowserProxyRefused(
                        "network_proxy_authentication_invalid",
                    )
                self._authentication = b"QBP1" + registration.authentication
                thread = threading.Thread(
                    target=self._accept,
                    name="quarry-browser-proxy", daemon=False,
                )
                self._accept_thread = thread
                thread.start()
                if self._effect_fence.is_set():
                    raise NetworkBrokerRefused("network_effect_fence_closed")
            return
        except BaseException as exc:
            primary = exc

        self._local_stop.set()
        cleanup_fault = None
        accept = self._accept_thread
        if accept is not None and accept is not threading.current_thread():
            accept.join(timeout=2.0)
            if accept.is_alive():
                cleanup_fault = BrowserProxyRefused(
                    "network_proxy_accept_settlement_failed",
                )
        for cleanup in (self._close_registration, self._close_listener):
            try:
                cleanup()
            except BaseException as exc:
                if cleanup_fault is None:
                    cleanup_fault = exc
        self._authentication = None
        if cleanup_fault is not None:
            raise cleanup_fault from primary
        raise primary.with_traceback(primary.__traceback__)

    def _record(self, *, stage: str, method: str, host=None, port=None,
                peer=None, decision: str, reason: str) -> bool:
        """Append one bounded record and synchronously fence on failure."""
        pair = None
        if stage in {"dns-planned", "dns-settled"}:
            pair = "dns"
        elif stage in {"peer-planned", "peer-settled"}:
            pair = "peer"
        key = (threading.get_ident(), pair) if pair is not None else None
        with self._lock:
            sequence = len(self._records) + self._dropped
            record = ProxyRecord(
                sequence, stage, method, host, port, peer, decision, reason,
            )
            body = json.dumps(
                record.to_dict(), ensure_ascii=True, sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(body) > _MAX_PROXY_RECORD_BYTES:
                self._fatal = "network_proxy_record_oversize"
                self._stop.set()
                return False
            elif stage.endswith("-planned") and key is not None:
                reserved = sum(self._open_plans.values())
                used_bytes = getattr(self, "_record_bytes", 0)
                if key in self._open_plans:
                    self._dropped += 1
                    self._fatal = "network_proxy_plan_duplicate"
                    self._stop.set()
                    return False
                if (len(self._records) + reserved + 2 > _MAX_PROXY_RECORDS
                        or used_bytes + len(body) + 1
                        + (reserved + 1) * (_MAX_PROXY_RECORD_BYTES + 1)
                        > _MAX_PROXY_SUMMARY_BYTES):
                    self._dropped += 1
                    self._fatal = "network_proxy_record_overflow"
                    self._stop.set()
                    return False
                self._records.append(record)
                self._record_bytes = used_bytes + len(body) + 1
                self._open_plans[key] = 1
                return True
            elif stage.endswith("-settled") and key is not None:
                if key not in self._open_plans:
                    self._dropped += 1
                    self._fatal = "network_proxy_plan_missing"
                    self._stop.set()
                    return False
                used_bytes = getattr(self, "_record_bytes", 0)
                if (used_bytes + len(body) + 1
                        + (sum(self._open_plans.values()) - 1)
                        * (_MAX_PROXY_RECORD_BYTES + 1)
                        > _MAX_PROXY_SUMMARY_BYTES):
                    self._dropped += 1
                    self._fatal = "network_proxy_record_overflow"
                    self._stop.set()
                    return False
                self._records.append(record)
                self._record_bytes = used_bytes + len(body) + 1
                self._open_plans.pop(key)
                return True
            elif (len(self._records) + sum(self._open_plans.values())
                  >= _MAX_PROXY_RECORDS
                  or getattr(self, "_record_bytes", 0) + len(body) + 1
                  + sum(self._open_plans.values())
                  * (_MAX_PROXY_RECORD_BYTES + 1)
                  > _MAX_PROXY_SUMMARY_BYTES):
                self._dropped += 1
                self._fatal = "network_proxy_record_overflow"
                self._stop.set()
                return False
            else:
                self._records.append(record)
                self._record_bytes = (
                    getattr(self, "_record_bytes", 0) + len(body) + 1
                )
                return True

    def _track(self, handle: socket.socket) -> None:
        try:
            self._effect_fence.track_socket(handle)
        except BaseException:
            try:
                live = handle.fileno() >= 0
            except OSError:
                live = True
            if live:
                with self._lock:
                    self._sockets.add(handle)
            raise
        with self._lock:
            self._sockets.add(handle)

    def _close_tracked(self, handle: socket.socket) -> None:
        self._effect_fence.close_tracked_socket(handle)
        with self._lock:
            self._sockets.discard(handle)

    def _accept(self) -> None:
        try:
            while not self._stop.is_set() and time.monotonic() < self._deadline:
                listener = self._listener
                if listener is None:
                    return
                readable, _writable, _exceptional = select.select(
                    (listener,), (), (listener,), 0.05,
                )
                if not readable:
                    continue
                client = None
                try:
                    # Accept and ownership registration are one fence epoch:
                    # cancellation cannot acknowledge a newly-created client
                    # before the fence owns and closes it.
                    with self._effect_fence:
                        client, peer = listener.accept()
                        self._effect_fence.track_socket(client)
                        with self._lock:
                            self._sockets.add(client)
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
                                self._sockets.add(client)
                    return
                if peer[0] != "127.0.0.1":
                    self._close_tracked(client)
                    self._record(
                        stage="accept", method="", decision="deny",
                        reason="proxy client is not loopback",
                    )
                    continue
                if not self._slots.acquire(blocking=False):
                    self._close_tracked(client)
                    self._record(
                        stage="accept", method="", decision="deny",
                        reason="proxy connection capacity exhausted",
                    )
                    continue
                thread = threading.Thread(
                    target=self._serve_thread, args=(client,),
                    name="quarry-browser-proxy-client", daemon=False,
                )
                with self._lock:
                    self._threads.add(thread)
                try:
                    thread.start()
                except BaseException:
                    with self._lock:
                        self._threads.discard(thread)
                    self._slots.release()
                    self._close_tracked(client)
                    raise
        except BaseException:
            if not self._stop.is_set():
                self._fatal = "network_proxy_accept_loop_failed"
                self._stop.set()

    def _serve_thread(self, client: socket.socket) -> None:
        current = threading.current_thread()
        try:
            registration = self._registration
            if registration is None:
                raise BrowserProxyRefused("network_proxy_registration_missing")
            grant = self._registry.consume_connection(
                registration, accepted_fd=client.fileno(),
                deadline_monotonic=min(self._deadline, time.monotonic() + 0.5),
                stop_event=self._stop,
            )
            if grant is None:
                raise BrowserProxyRefused("network_proxy_connection_grant_refused")
            self._serve(client)
        except _SocksProxyRefused as exc:
            self._record(
                stage="request", method="SOCKS5", decision="deny", reason=str(exc),
            )
        except BrowserProxyRefused as exc:
            self._record(
                stage="request", method="", decision="deny", reason=str(exc),
            )
            if not self._stop.is_set():
                try:
                    self._send(
                        client,
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
                        b"Content-Length: 0\r\n\r\n",
                    )
                except (OSError, BrowserProxyRefused, NetworkBrokerRefused):
                    pass
        except (OSError, TimeoutError):
            self._record(
                stage="request", method="", decision="deny",
                reason="proxy request transport did not settle",
            )
        except BaseException:
            self._fatal = "network_proxy_client_loop_failed"
            self._stop.set()
        finally:
            self._close_tracked(client)
            self._slots.release()
            with self._lock:
                self._threads.discard(current)

    def _read_exact(self, client: socket.socket, length: int) -> bytes:
        if not 0 <= length <= _MAX_PROXY_HEADER_BYTES:
            raise BrowserProxyRefused("network_proxy_request_oversize")
        client.setblocking(False)
        body = bytearray()
        while len(body) < length:
            if self._stop.is_set() or time.monotonic() >= self._deadline:
                raise BrowserProxyRefused("network_proxy_request_cancelled")
            readable, _writable, exceptional = select.select(
                (client,), (), (client,), 0.05,
            )
            if exceptional:
                raise BrowserProxyRefused("network_proxy_client_failed")
            if not readable:
                continue
            block = client.recv(length - len(body))
            if not block:
                raise BrowserProxyRefused("network_proxy_request_truncated")
            body.extend(block)
        return bytes(body)

    def _authenticate(self, client: socket.socket) -> None:
        authentication = self._authentication
        if authentication is None:
            raise BrowserProxyRefused("network_proxy_authentication_invalid")
        if self._read_exact(client, len(authentication)) != authentication:
            raise BrowserProxyRefused("network_proxy_authentication_refused")

    def _read_header(self, client: socket.socket, initial=b"") -> tuple[bytes, bytes]:
        body = bytearray(initial)
        while not self._stop.is_set() and time.monotonic() < self._deadline:
            marker = body.find(b"\r\n\r\n")
            if marker >= 0:
                end = marker + 4
                return bytes(body[:end]), bytes(body[end:])
            if len(body) >= _MAX_PROXY_HEADER_BYTES:
                raise BrowserProxyRefused("network_proxy_header_oversize")
            readable, _writable, exceptional = select.select(
                (client,), (), (client,), 0.05,
            )
            if exceptional:
                raise BrowserProxyRefused("network_proxy_client_failed")
            if not readable:
                continue
            block = client.recv(min(16 * 1024, _MAX_PROXY_HEADER_BYTES + 1 - len(body)))
            if not block:
                raise BrowserProxyRefused("network_proxy_header_truncated")
            body.extend(block)
        raise BrowserProxyRefused("network_proxy_request_cancelled")

    def _serve_socks(self, client: socket.socket) -> None:
        upstream = None
        replied = False
        try:
            nmethods = self._read_exact(client, 1)[0]
            methods = self._read_exact(client, nmethods)
            if 0 not in methods:
                self._send(client, b"\x05\xff")
                raise _SocksProxyRefused("network_proxy_socks_auth_refused")
            self._send(client, b"\x05\x00")
            version, command, reserved, address_type = self._read_exact(client, 4)
            if version != 5 or command != 1 or reserved != 0:
                raise _SocksProxyRefused("network_proxy_socks_command_refused")
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, self._read_exact(client, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._read_exact(client, 16))
            elif address_type == 3:
                size = self._read_exact(client, 1)[0]
                if size == 0:
                    raise _SocksProxyRefused("network_proxy_socks_authority_invalid")
                try:
                    host = self._read_exact(client, size).decode("ascii")
                except UnicodeDecodeError as exc:
                    raise _SocksProxyRefused(
                        "network_proxy_socks_authority_invalid",
                    ) from exc
            else:
                raise _SocksProxyRefused("network_proxy_socks_address_refused")
            port = int.from_bytes(self._read_exact(client, 2), "big")
            if port == 0:
                raise _SocksProxyRefused("network_proxy_socks_authority_invalid")
            if self._is_nuclei_resolver(host, port):
                self._send(client, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                replied = True
                self._serve_nuclei_dns(client, host)
                return
            # The Nuclei SOCKS boundary has one DNS authority only. In
            # particular, an invocation-approved target IP on port 53 must
            # not fall through to the raw SOCKS relay.
            if (getattr(getattr(self, "_policy", None), "transport_profile", None)
                    == "nuclei-authorized-http" and port == 53):
                raise _SocksProxyRefused("network_proxy_nuclei_resolver_refused")
            upstream = self._dial("SOCKS5", host, port)
            self._send(client, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            replied = True
            self._relay(client, upstream)
        except _SocksProxyRefused:
            raise
        except (BrowserProxyRefused, OSError) as exc:
            if not replied and not self._stop.is_set():
                try:
                    self._send(
                        client,
                        b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00",
                    )
                except (BrowserProxyRefused, OSError, NetworkBrokerRefused):
                    pass
            raise _SocksProxyRefused(str(exc)) from exc
        finally:
            if upstream is not None:
                self._close_tracked(upstream)

    def _is_nuclei_resolver(self, host: str, port: int) -> bool:
        """Select only the DNS-over-TCP tunnel owned by Nuclei's SOCKS lane."""
        policy = getattr(self, "_policy", None)
        if (policy is None or policy.transport_profile != "nuclei-authorized-http"
                or policy.nuclei_protocol_lane != "http,dns" or port != 53):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        canonical = str(getattr(address, "ipv4_mapped", None) or address)
        return canonical == host and canonical in policy.resolver_ips

    def _parse_nuclei_dns_query(self, message: bytes) -> str:
        """Accept one uncompressed, one-question DNS QUERY frame only."""
        if len(message) < network_dns._DNS_HEADER.size + 5 + _NUCLEI_DNS_OPT.size:
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        _transaction, flags, questions, answers, authority, additional = \
            network_dns._DNS_HEADER.unpack_from(message)
        if questions != 1 or answers or authority or additional != 1:
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        try:
            name, offset = network_dns._decode_name(
                message, network_dns._DNS_HEADER.size,
            )
        except network_dns.NetworkDNSRefused as exc:
            raise _SocksProxyRefused("network_proxy_dns_query_malformed") from exc
        # DNS compression in a request is an alternate framing. Re-encoding
        # makes the accepted QUERY wire shape exact and unambiguous.
        if (not name or message[network_dns._DNS_HEADER.size:offset]
                != network_dns._encode_name(name)):
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        query_type, query_class = struct.unpack_from("!HH", message, offset)
        opt_offset = offset + 4
        if query_type == 0 or query_class != 1 or \
                opt_offset + _NUCLEI_DNS_OPT.size != len(message):
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        # Nuclei v3.11's dns.Request.Make emits SetEdns0(4096, false) for
        # every request and adds AD only for TXT. Admit precisely that
        # request shape, not a general EDNS extension channel.
        expected_flags = 0x0120 if query_type == 16 else 0x0100
        owner, opt_type, udp_size, opt_ttl, option_length = \
            _NUCLEI_DNS_OPT.unpack_from(message, opt_offset)
        if (flags != expected_flags or owner != 0 or opt_type != 41
                or udp_size != _NUCLEI_DNS_OPT_UDP_SIZE or opt_ttl != 0
                or option_length != 0):
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        decision, _reason = self._policy.dns_name_allowed(name)
        if decision != "allow":
            raise _SocksProxyRefused("network_proxy_dns_qname_out_of_scope")
        return name

    def _read_dns_frame(self, client: socket.socket) -> bytes:
        length = int.from_bytes(self._read_exact(client, 2), "big")
        if length < network_dns._DNS_HEADER.size + 5:
            raise _SocksProxyRefused("network_proxy_dns_query_malformed")
        return self._read_exact(client, length)

    def _serve_nuclei_dns(self, client: socket.socket, resolver: str) -> None:
        """Mediate every DNS-over-TCP query before any resolver payload flows."""
        while not self._stop.is_set() and time.monotonic() < self._deadline:
            request = self._read_dns_frame(client)
            name = self._parse_nuclei_dns_query(request)
            self._exchange_nuclei_dns(client, resolver, request, name)
        raise _SocksProxyRefused("network_proxy_request_cancelled")

    def _exchange_nuclei_dns(self, client: socket.socket, resolver: str,
                             request: bytes, name: str) -> None:
        decision, reason = self._policy.decide_dns(
            resolver, 53, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        )
        if decision != "allow":
            raise _SocksProxyRefused("network_proxy_dns_resolver_refused")
        if not self._record(
                stage="dns-planned", method="SOCKS5-DNS", host=name, port=53,
                peer=resolver, decision="allow", reason=reason):
            raise _SocksProxyRefused("network_proxy_trace_authority_failed")
        upstream = None
        try:
            address = ipaddress.ip_address(resolver)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            endpoint = (resolver, 53) if family == socket.AF_INET else \
                (resolver, 53, 0, 0)
            upstream = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self._track(upstream)
            network_dns._connect(
                upstream, endpoint, deadline_monotonic=self._deadline,
                effect_fence=self._effect_fence,
            )
            observed = ipaddress.ip_address(upstream.getpeername()[0])
            selected = str(getattr(observed, "ipv4_mapped", None) or observed)
            if selected != resolver:
                raise _SocksProxyRefused("network_proxy_dns_resolver_peer_unverified")
            selected_decision, selected_reason = self._policy.decide_dns(
                selected, 53, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            )
            if selected_decision != "allow":
                raise _SocksProxyRefused("network_proxy_dns_resolver_refused")
            network_dns._send_all(
                upstream, len(request).to_bytes(2, "big") + request,
                deadline_monotonic=self._deadline, effect_fence=self._effect_fence,
            )
            response_length = int.from_bytes(network_dns._read_exact(
                upstream, 2, deadline_monotonic=self._deadline,
                effect_fence=self._effect_fence,
            ), "big")
            if response_length < network_dns._DNS_HEADER.size:
                raise _SocksProxyRefused("network_proxy_dns_response_malformed")
            response = network_dns._read_exact(
                upstream, response_length, deadline_monotonic=self._deadline,
                effect_fence=self._effect_fence,
            )
            self._send(client, response_length.to_bytes(2, "big") + response)
            if not self._record(
                    stage="dns-settled", method="SOCKS5-DNS", host=name,
                    port=53, peer=selected, decision="allow",
                    reason=selected_reason):
                raise _SocksProxyRefused("network_proxy_trace_authority_failed")
        except BaseException:
            self._record(
                stage="dns-settled", method="SOCKS5-DNS", host=name, port=53,
                peer=resolver, decision="deny",
                reason="Nuclei DNS-over-TCP exchange did not settle",
            )
            raise
        finally:
            if upstream is not None:
                self._close_tracked(upstream)

    def _dns_event(self, method: str, host: str, stage: str, peer: str,
                   port: int, decision: str, reason: str) -> None:
        self._record(
            stage=stage, method=method, host=host, port=port, peer=peer,
            decision=decision, reason=reason,
        )
        if self._stop.is_set():
            raise BrowserProxyRefused("network_proxy_trace_authority_failed")

    def _dial(self, method: str, host: str, port: int) -> socket.socket:
        if self._stop.is_set() or time.monotonic() >= self._deadline:
            raise BrowserProxyRefused("network_proxy_request_cancelled")
        host_decision, host_reason = self._policy.host_allowed(host, port)
        self._record(
            stage="authority", method=method, host=host, port=port,
            decision=host_decision, reason=host_reason,
        )
        if self._stop.is_set():
            raise BrowserProxyRefused("network_proxy_trace_authority_failed")
        if host_decision != "allow":
            raise BrowserProxyRefused("network_proxy_authority_out_of_scope")
        answers, state = network_dns.resolve(
            self._policy, host,
            timeout=max(0.05, min(5.0, self._deadline - time.monotonic())),
            on_event=lambda *values: self._dns_event(method, host, *values),
            effect_fence=self._effect_fence,
        )
        if state != "ok" or not answers:
            raise BrowserProxyRefused("network_proxy_resolution_indeterminate")
        decisions = [
            (peer, *self._policy.decide_proxy_resolved(
                host, peer, port, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            ))
            for peer in answers
        ]
        if any(decision != "allow" for _peer, decision, _reason in decisions):
            for peer, decision, reason in decisions:
                self._record(
                    stage="peer-admission", method=method, host=host, port=port,
                    peer=peer, decision=decision, reason=reason,
                )
            raise BrowserProxyRefused("network_proxy_answer_set_refused")
        last_error = None
        for peer, _decision, reason in decisions:
            if not self._record(
                stage="peer-planned", method=method, host=host, port=port,
                peer=peer, decision="allow", reason=reason,
            ):
                raise BrowserProxyRefused(
                    "network_proxy_trace_authority_failed",
                )
            if self._stop.is_set() or time.monotonic() >= self._deadline:
                self._record(
                    stage="peer-settled", method=method, host=host, port=port,
                    peer=peer, decision="deny",
                    reason="literal peer connection was cancelled before contact",
                )
                raise BrowserProxyRefused("network_proxy_trace_authority_failed")
            address = ipaddress.ip_address(peer)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            endpoint = (peer, port) if family == socket.AF_INET else (peer, port, 0, 0)
            upstream = None
            settled = False
            try:
                upstream = socket.socket(
                    family, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                )
                upstream.setblocking(False)
                self._track(upstream)
                attempt_deadline = min(
                    self._deadline, time.monotonic() + 5.0,
                )
                with self._effect_fence:
                    error = upstream.connect_ex(endpoint)
                if error not in {
                        0, errno.EISCONN, errno.EINPROGRESS,
                        errno.EALREADY, errno.EWOULDBLOCK,
                    }:
                    raise OSError(error, "literal peer connect failed")
                while error not in {0, errno.EISCONN}:
                    if (self._stop.is_set()
                            or time.monotonic() >= attempt_deadline):
                        raise BrowserProxyRefused(
                            "network_proxy_literal_connect_cancelled",
                        )
                    _readable, writable, exceptional = select.select(
                        (), (upstream,), (upstream,), 0.05,
                    )
                    if not writable and not exceptional:
                        continue
                    error = upstream.getsockopt(
                        socket.SOL_SOCKET, socket.SO_ERROR,
                    )
                    if error:
                        raise OSError(error, "literal peer connect failed")
                observed = ipaddress.ip_address(upstream.getpeername()[0])
                selected = str(getattr(observed, "ipv4_mapped", None) or observed)
                if selected != peer:
                    raise BrowserProxyRefused("network_proxy_selected_peer_unverified")
                final_decision, final_reason = self._policy.decide_proxy_resolved(
                    host, selected, port, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                )
                if not self._record(
                    stage="peer-settled", method=method, host=host, port=port,
                    peer=selected, decision=final_decision, reason=final_reason,
                ):
                    raise BrowserProxyRefused(
                        "network_proxy_trace_authority_failed",
                    )
                settled = True
                if final_decision != "allow":
                    raise BrowserProxyRefused("network_proxy_selected_peer_refused")
                return upstream
            except BaseException as exc:
                terminal_ok = True
                if not settled:
                    terminal_ok = self._record(
                        stage="peer-settled", method=method, host=host,
                        port=port, peer=peer, decision="deny",
                        reason="literal peer connection did not settle",
                    )
                if upstream is not None:
                    self._close_tracked(upstream)
                if not terminal_ok:
                    raise BrowserProxyRefused(
                        "network_proxy_trace_authority_failed",
                    ) from exc
                # Only a transport failure may select another member of the
                # already all-or-nothing-admitted answer set.  A policy,
                # identity, cancellation, or selected-peer failure invalidates
                # the whole set and must not degrade into partial acceptance.
                if isinstance(exc, OSError) \
                        and not isinstance(exc, NetworkBrokerRefused):
                    last_error = exc
                    continue
                raise
        raise BrowserProxyRefused("network_proxy_literal_connect_failed") from last_error

    def _send(self, handle: socket.socket, body: bytes) -> None:
        handle.setblocking(False)
        view = memoryview(body)
        while view and not self._stop.is_set() and time.monotonic() < self._deadline:
            _readable, writable, exceptional = select.select(
                (), (handle,), (handle,), 0.05,
            )
            if exceptional:
                raise BrowserProxyRefused("network_proxy_relay_failed")
            if not writable:
                continue
            with self._effect_fence:
                written = handle.send(view)
            if written <= 0:
                raise BrowserProxyRefused("network_proxy_relay_failed")
            view = view[written:]
        if view:
            raise BrowserProxyRefused("network_proxy_request_cancelled")

    def _copy_body(self, client: socket.socket, upstream: socket.socket,
                   initial: bytes, total: int) -> None:
        self._send(upstream, initial)
        remaining = total - len(initial)
        while remaining:
            if self._stop.is_set() or time.monotonic() >= self._deadline:
                raise BrowserProxyRefused("network_proxy_request_cancelled")
            readable, _writable, exceptional = select.select(
                (client,), (), (client,), 0.05,
            )
            if exceptional:
                raise BrowserProxyRefused("network_proxy_client_failed")
            if not readable:
                continue
            block = client.recv(min(_MAX_PROXY_BUFFER_BYTES, remaining))
            if not block:
                raise BrowserProxyRefused("network_proxy_request_body_truncated")
            self._send(upstream, block)
            remaining -= len(block)

    def _relay(self, left: socket.socket, right: socket.socket,
               *, initial_to_right=b"", left_reads=True) -> None:
        left.setblocking(False)
        right.setblocking(False)
        buffers = {left: bytearray(), right: bytearray(initial_to_right)}
        peer = {left: right, right: left}
        reads = {left: left_reads, right: True}
        shutdown = {left: False, right: False}
        while not self._stop.is_set() and time.monotonic() < self._deadline:
            for source in (left, right):
                destination = peer[source]
                if not reads[source] and not buffers[destination] and not shutdown[destination]:
                    try:
                        with self._effect_fence:
                            destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    except NetworkBrokerRefused as exc:
                        raise BrowserProxyRefused(
                            "network_proxy_request_cancelled",
                        ) from exc
                    shutdown[destination] = True
            if not any(reads.values()) and not any(buffers.values()):
                return
            read_list = [
                source for source in (left, right)
                if reads[source] and len(buffers[peer[source]]) < _MAX_PROXY_BUFFER_BYTES
            ]
            write_list = [destination for destination in (left, right) if buffers[destination]]
            readable, writable, exceptional = select.select(
                read_list, write_list, (left, right), 0.05,
            )
            if exceptional:
                raise BrowserProxyRefused("network_proxy_relay_failed")
            for source in readable:
                try:
                    block = source.recv(
                        _MAX_PROXY_BUFFER_BYTES - len(buffers[peer[source]]),
                    )
                except BlockingIOError:
                    continue
                if block:
                    buffers[peer[source]].extend(block)
                else:
                    reads[source] = False
            for destination in writable:
                try:
                    with self._effect_fence:
                        written = destination.send(buffers[destination])
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise BrowserProxyRefused("network_proxy_relay_failed")
                del buffers[destination][:written]
        raise BrowserProxyRefused("network_proxy_request_cancelled")

    def _serve(self, client: socket.socket) -> None:
        self._authenticate(client)
        first = self._read_exact(client, 1)
        if first == b"\x05":
            self._serve_socks(client)
            return
        header, remainder = self._read_header(client, first)
        request = _parse_request(header, remainder)
        upstream = self._dial(request.method, request.host, request.port)
        try:
            if request.connect:
                self._send(
                    client,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                )
                self._relay(client, upstream)
                return
            self._send(upstream, request.forwarded_head)
            self._copy_body(
                client, upstream, request.initial_body, request.body_length,
            )
            if request.upgrade:
                self._relay(client, upstream)
            else:
                self._relay(client, upstream, left_reads=False)
        finally:
            self._close_tracked(upstream)

    def stop(self) -> None:
        deadline = time.monotonic() + 2.0
        self._local_stop.set()
        self._authentication = None
        for cleanup in (self._close_registration, self._close_listener):
            try:
                cleanup()
            except NetworkBrokerRefused as exc:
                self._fatal = self._fatal or str(exc)
        accept = self._accept_thread
        if accept is not None and accept is not threading.current_thread():
            accept.join(timeout=max(0.0, deadline - time.monotonic()))
            if accept.is_alive():
                self._fatal = "network_proxy_accept_settlement_failed"
        # The accept loop is fenced and joined before snapshots so it cannot
        # add a client after the drain set was captured.
        while True:
            with self._lock:
                sockets = tuple(self._sockets)
                threads = tuple(
                    thread for thread in self._threads
                    if thread is not threading.current_thread()
                )
            for handle in sockets:
                try:
                    self._close_tracked(handle)
                except NetworkBrokerRefused as exc:
                    self._fatal = self._fatal or str(exc)
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
            with self._lock:
                remaining_sockets = len(self._sockets)
                remaining_threads = tuple(
                    thread for thread in self._threads if thread.is_alive()
                )
            if not remaining_sockets and not remaining_threads:
                break
            if time.monotonic() >= deadline:
                self._fatal = "network_proxy_client_settlement_failed"
                break

    def summary(self) -> dict:
        with self._lock:
            records = [record.to_dict() for record in self._records]
            dropped = self._dropped
            active_sockets = len(self._sockets)
            active_threads = sum(thread.is_alive() for thread in self._threads)
            open_plans = len(self._open_plans)
        accept_alive = self._accept_thread is not None and self._accept_thread.is_alive()
        return {
            "schema_version": "quarry.browser-proxy-summary.v1",
            "request_id": self._policy.request_id,
            "records": records,
            "dropped_records": dropped,
            "open_plans": open_plans,
            "fatal": self._fatal,
            "active_sockets": active_sockets,
            "active_threads": active_threads + int(accept_alive),
            "complete": (
                self._fatal is None and self._listener is None
                and self._registration is None and dropped == 0
                and open_plans == 0
                and active_sockets == 0 and active_threads == 0
                and not accept_alive
            ),
        }


__all__ = ("BrowserProxyRefused", "PinnedBrowserProxy")
