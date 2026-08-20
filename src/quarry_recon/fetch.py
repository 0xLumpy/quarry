"""Shared direct-HTTP choke point for recon fetches to a target.

One place enforces the guards that tool flags give nuclei/httpx/ffuf on every hand-rolled fetch:
http_rl pacing, a bounded read, and per-hop redirect scope enforcement. Redirects are followed
manually with the no-follow opener so each hop's host is guarded before contact — a hop leaving scope
or hitting the scan box (loopback/metadata/own-iface) is never requested, while a private/internal
answer is recorded as intel and contacted by default. All fetches are unauthenticated and non-mutating.
"""
from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import ipaddress
import json
import os
import errno
import re
import secrets as _secrets
import select
import socket
import stat
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import contract, netguard, normalize, privfs, store

UA = "Mozilla/5.0"
DEFAULT_MAX_BODY = 2 * 1024 * 1024      # 2 MB default cap
DEFAULT_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})   # actual navigations (304 is not a redirect)
_SENSITIVE_HEADERS = ("authorization", "cookie", "proxy-authorization")
_AUTHORITY_HEADERS = frozenset({
    "host", ":authority", "proxy-authorization", "proxy-connection",
})
_HTTP_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_MAX_NATIVE_SEND_CHUNK = 64 * 1024


def _preferred_fault(primary, faults):
    """Keep an exact cancellation ahead of every ordinary cleanup fault."""
    if primary is not None and not isinstance(primary, Exception):
        return primary
    cancellation = next(
        (fault for fault in faults if not isinstance(fault, Exception)), None,
    )
    return cancellation or primary or (faults[0] if faults else None)


class _ResponseCleanupState:
    """Local response-exit classification independent of exception mutability."""

    __slots__ = ("outcome",)

    def __init__(self):
        self.outcome = None


@contextlib.contextmanager
def _response_lifetime(response, cleanup_state=None):
    """Close one response while preserving the operation's preferred fault."""
    if cleanup_state is not None:
        cleanup_state.outcome = None
    primary = None
    try:
        yield
    except BaseException as exc:
        primary = exc
    close_faults = []
    if response is not None:
        transport = getattr(response, "_quarry_network_transport", None)
        if transport is not None:
            try:
                transport.release()
            except BaseException as exc:
                close_faults.append(exc)
        try:
            response.close()
        except BaseException as exc:
            close_faults.append(exc)
    preferred = _preferred_fault(primary, close_faults)
    if preferred is not None:
        if cleanup_state is not None:
            cleanup_state.outcome = (
                preferred, primary is None, tuple(close_faults),
            )
        raise preferred


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):     # never follow — return None so the 30x is handed back
        return None


def _http_only_opener(http_handler, https_handler):
    """Build an opener with no FTP/file/data handlers and no ambient proxy."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler({}), urllib.request.UnknownHandler(),
        http_handler, urllib.request.HTTPDefaultErrorHandler(),
        _NoRedirect(), https_handler, urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


_NO_REDIRECT_OPENER = _http_only_opener(
    urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(),
)
import ssl as _ssl  # noqa: E402


class _PinnedTransport:
    """Literal-address connector retaining the URL host for HTTP Host and TLS SNI."""

    def __init__(self, approved, *, peer_authority=None, on_attempt=None,
                 effect_fence=None):
        self.approved = tuple(approved)
        self.peer_authority = peer_authority
        self.on_attempt = on_attempt
        self.effect_fence = effect_fence
        self.selected_peer = None
        self._connections = set()

    def _track(self, connection):
        if self.effect_fence is not None:
            self.effect_fence.track_socket(connection)
        self._connections.add(connection)

    def _untrack(self, connection):
        self._connections.discard(connection)
        if self.effect_fence is not None:
            self.effect_fence.untrack_socket(connection)

    def _close_tracked(self, connection):
        if self.effect_fence is None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        else:
            self.effect_fence.close_tracked_socket(connection)
        self._connections.discard(connection)

    def _replace_tracked(self, old, new):
        if self.effect_fence is not None:
            try:
                self.effect_fence.replace_tracked_socket(old, new)
            except BaseException:
                # The fence may have been signalled after wrap_socket detached
                # ``old`` but before this transfer.  Its replacement helper
                # closes ``new`` in that case; do not retain either dead Python
                # object as transport state.
                self._connections.discard(old)
                self._connections.discard(new)
                raise
        elif old not in self._connections:
            try:
                new.close()
            except OSError:
                pass
            raise RuntimeError("native TLS socket transfer lacked authority")
        self._connections.discard(old)
        self._connections.add(new)

    def release(self):
        for connection in tuple(self._connections):
            self._close_tracked(connection)

    def create_connection(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                          source_address=None, *args, **kwargs):
        _host, port = address
        last = None
        for value in self.approved:
            connection = None
            planned = False
            settled = False
            try:
                if self.on_attempt is not None:
                    self.on_attempt(
                        "planned", value,
                        "literal TCP peer admitted before connect",
                    )
                    planned = True
                if self.peer_authority is not None:
                    decision = self.peer_authority(
                        value, int(port), socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    )
                    if not decision.allowed:
                        raise RuntimeError("literal peer lost network authority")
                # `value` is already a canonical literal.  No name reaches this
                # call, so there is no second resolver decision to rebind.
                address = ipaddress.ip_address(value)
                family = socket.AF_INET if address.version == 4 else socket.AF_INET6
                connection = socket.socket(
                    family, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                )
                self._track(connection)
                timeout_value = (
                    socket.getdefaulttimeout()
                    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout
                )
                if timeout_value is None:
                    timeout_value = 60.0
                if (type(timeout_value) not in {int, float}
                        or not 0 < timeout_value <= 60):
                    raise ValueError("native TCP timeout is outside its bound")
                deadline = time.monotonic() + float(timeout_value)
                connection.setblocking(False)
                if source_address is not None:
                    if self.effect_fence is None:
                        connection.bind(source_address)
                    else:
                        with self.effect_fence:
                            connection.bind(source_address)
                endpoint = ((value, port) if family == socket.AF_INET
                            else (value, port, 0, 0))
                if self.effect_fence is None:
                    error = connection.connect_ex(endpoint)
                else:
                    with self.effect_fence:
                        error = connection.connect_ex(endpoint)
                if error not in {
                        0, errno.EISCONN, errno.EINPROGRESS,
                        errno.EALREADY, errno.EWOULDBLOCK,
                    }:
                    raise OSError(error, "literal peer connect failed")
                while error not in {0, errno.EISCONN}:
                    if ((self.effect_fence is not None
                         and self.effect_fence.is_set())
                            or time.monotonic() >= deadline):
                        raise TimeoutError("literal peer connect deadline expired")
                    _readable, writable, exceptional = select.select(
                        (), (connection,), (connection,),
                        min(0.05, deadline - time.monotonic()),
                    )
                    if not writable and not exceptional:
                        continue
                    error = connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_ERROR,
                    )
                    if error:
                        raise OSError(error, "literal peer connect failed")
                peer = netguard.canonical_ip_set((connection.getpeername()[0],))
                if len(peer) != 1 or peer[0] not in self.approved:
                    raise OSError("connected peer was not in the approved address set")
                if self.peer_authority is not None:
                    decision = self.peer_authority(
                        peer[0], int(port), socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    )
                    if not decision.allowed:
                        raise RuntimeError("connected peer lost network authority")
                if self.on_attempt is not None:
                    settled = True
                    self.on_attempt(
                        "settled", peer[0],
                        "literal TCP peer connected and post-authorized",
                    )
                else:
                    settled = True
                self.selected_peer = peer[0]
                connection.settimeout(float(timeout_value))
                return connection
            except BaseException as exc:
                last = exc
                settlement_fault = None
                if self.on_attempt is not None and planned and not settled:
                    try:
                        self.on_attempt(
                            "settled", value,
                            "literal TCP peer connection did not settle",
                        )
                    except BaseException as fault:
                        settlement_fault = fault
                if connection is not None:
                    self._close_tracked(connection)
                if settlement_fault is not None:
                    if self.effect_fence is not None:
                        self.effect_fence.cancel()
                    if not isinstance(exc, Exception):
                        raise exc
                    raise settlement_fault from exc
                if not isinstance(exc, OSError):
                    if self.effect_fence is not None:
                        self.effect_fence.cancel()
                    raise
        raise OSError("no approved destination peer could be connected") from last

    def wrap_tls(self, connection, context, *, server_hostname):
        """Wrap a pinned peer while retaining cancellation over the live fd."""
        if connection not in self._connections:
            raise RuntimeError("native TLS socket lacked transport authority")
        timeout_value = connection.gettimeout()
        if timeout_value is None:
            timeout_value = 60.0
        if (type(timeout_value) not in {int, float}
                or not 0 < timeout_value <= 60):
            raise ValueError("native TLS timeout is outside its bound")
        deadline = time.monotonic() + float(timeout_value)
        wrapped = None
        try:
            # ``wrap_socket`` detaches ``connection`` even with handshake
            # disabled.  Hold the shared effect fence until the live SSLSocket
            # has replaced that detached shell in its tracked set.
            if self.effect_fence is None:
                wrapped = context.wrap_socket(
                    connection, server_hostname=server_hostname,
                    do_handshake_on_connect=False,
                )
                self._replace_tracked(connection, wrapped)
            else:
                with self.effect_fence:
                    wrapped = context.wrap_socket(
                        connection, server_hostname=server_hostname,
                        do_handshake_on_connect=False,
                    )
                    self._replace_tracked(connection, wrapped)
            wrapped.setblocking(False)
            while True:
                if ((self.effect_fence is not None
                     and self.effect_fence.is_set())
                        or time.monotonic() >= deadline):
                    raise TimeoutError("native TLS handshake deadline expired")
                want_read = want_write = False
                try:
                    if self.effect_fence is None:
                        wrapped.do_handshake()
                    else:
                        with self.effect_fence:
                            wrapped.do_handshake()
                    break
                except _ssl.SSLWantReadError:
                    want_read = True
                except _ssl.SSLWantWriteError:
                    want_write = True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native TLS handshake deadline expired")
                readable, writable, exceptional = select.select(
                    (wrapped,) if want_read else (),
                    (wrapped,) if want_write else (),
                    (wrapped,), min(0.05, remaining),
                )
                if exceptional:
                    raise OSError("native TLS handshake socket failed")
                if not readable and not writable:
                    continue
            if self.effect_fence is None:
                wrapped.settimeout(float(timeout_value))
            else:
                with self.effect_fence:
                    wrapped.settimeout(float(timeout_value))
            return wrapped
        except BaseException:
            target = wrapped if wrapped is not None else connection
            self._close_tracked(target)
            raise

    def send_all(self, connection, body) -> None:
        """Send request bytes as bounded nonblocking effects under the fence.

        ``http.client`` normally calls blocking ``socket.sendall`` for request
        headers and bodies.  Closing that socket from another thread does not
        prove the blocked OFD write has returned.  Small nonblocking writes
        make each peer-visible effect a short fence epoch, while cancellation
        wakes the select loop and prevents any later epoch from entering.
        """
        if self.effect_fence is None:
            connection.sendall(body)
            return
        view = memoryview(body)
        timeout_value = connection.gettimeout()
        if timeout_value is None:
            timeout_value = 60.0
        if (type(timeout_value) not in {int, float}
                or not 0 < timeout_value <= 60):
            raise ValueError("native HTTP send timeout is outside its bound")
        deadline = time.monotonic() + float(timeout_value)
        primary = None
        try:
            with self.effect_fence:
                connection.setblocking(False)
            while view:
                if self.effect_fence.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError("native HTTP send deadline expired")
                want_read = False
                try:
                    with self.effect_fence:
                        written = connection.send(
                            view[:_MAX_NATIVE_SEND_CHUNK],
                        )
                except (_ssl.SSLWantWriteError, BlockingIOError):
                    written = None
                except _ssl.SSLWantReadError:
                    written = None
                    want_read = True
                if written is not None:
                    if written <= 0:
                        raise OSError("native HTTP request send failed")
                    view = view[written:]
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native HTTP send deadline expired")
                readable, writable, exceptional = select.select(
                    (connection,) if want_read else (),
                    () if want_read else (connection,),
                    (connection,), min(0.05, remaining),
                )
                if exceptional:
                    raise OSError("native HTTP request socket failed")
                if not readable and not writable:
                    continue
        except BaseException as exc:
            primary = exc
        finally:
            restore_fault = None
            if not self.effect_fence.is_set():
                try:
                    with self.effect_fence:
                        connection.settimeout(float(timeout_value))
                except BaseException as exc:
                    restore_fault = exc
            if primary is not None:
                raise primary
            if restore_fault is not None:
                raise restore_fault

    def read_into(self, connection, reader, buffer, timeout_value) -> int:
        """Perform one HTTP/TLS file read through short nonblocking epochs."""
        if self.effect_fence is None:
            return reader(buffer)
        deadline = time.monotonic() + float(timeout_value)
        while True:
            if self.effect_fence.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("native HTTP response read deadline expired")
            want_write = False
            try:
                with self.effect_fence:
                    observed = reader(buffer)
            except (_ssl.SSLWantReadError, BlockingIOError):
                observed = None
            except _ssl.SSLWantWriteError:
                observed = None
                want_write = True
            if observed is not None:
                return observed
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("native HTTP response read deadline expired")
            readable, writable, exceptional = select.select(
                () if want_write else (connection,),
                (connection,) if want_write else (),
                (connection,), min(0.05, remaining),
            )
            if exceptional:
                raise OSError("native HTTP response socket failed")
            if not readable and not writable:
                continue


def _pinned_opener(approved, *, insecure=False, peer_authority=None,
                   on_attempt=None, effect_fence=None):
    if insecure is not False:
        raise ValueError("native HTTPS certificate verification cannot be disabled")
    transport = _PinnedTransport(
        approved, peer_authority=peer_authority, on_attempt=on_attempt,
        effect_fence=effect_fence,
    )

    class FencedRaw(io.RawIOBase):
        def __init__(self, live, timeout_value):
            super().__init__()
            self.live = live
            self.timeout_value = timeout_value

        def readable(self):
            return True

        def fileno(self):
            return self.live.fileno()

        def readinto(self, buffer):
            self._checkClosed()
            return transport.read_into(
                self.live, self.live.recv_into, buffer, self.timeout_value,
            )

        def close(self):
            if not self.closed:
                # The response buffer is not a second socket owner.  The
                # tracked transport shuts down and closes ``live`` before the
                # public response lifetime closes this local buffer.
                super().close()

    class FencedSocket:
        """Adapter for every stdlib request/response socket I/O path."""

        def __init__(self, live):
            self.live = live

        def sendall(self, body):
            transport.send_all(self.live, body)

        def makefile(self, mode="r", buffering=None, *args, **kwargs):
            if mode != "rb" or args or kwargs:
                raise ValueError("native HTTP response file mode is unsupported")
            timeout_value = self.live.gettimeout()
            if timeout_value is None:
                timeout_value = 60.0
            if (type(timeout_value) not in {int, float}
                    or not 0 < timeout_value <= 60):
                raise ValueError("native HTTP response timeout is outside its bound")
            if transport.effect_fence is not None:
                with transport.effect_fence:
                    self.live.setblocking(False)
            return io.BufferedReader(
                FencedRaw(self.live, float(timeout_value)),
                buffer_size=(io.DEFAULT_BUFFER_SIZE if buffering in {None, -1}
                             else buffering),
            )

        def close(self):
            # ``HTTPConnection.getresponse`` closes its connection reference
            # before returning a Connection: close response.  The response
            # reader and transport now own the live socket; closing it here
            # would truncate the body or untrack TLS read-side protocol writes.
            return None

        def __getattr__(self, name):
            return getattr(self.live, name)

    class PinnedSendMixin:
        def send(self, data):
            if self.sock is None:
                if self.auto_open:
                    self.connect()
                else:
                    raise http.client.NotConnected()
            live = self.sock
            adapter = FencedSocket(live)
            self.sock = adapter
            try:
                return super().send(data)
            finally:
                if self.sock is adapter:
                    self.sock = live

        def getresponse(self):
            if self.sock is None:
                raise http.client.ResponseNotReady("Idle")
            live = self.sock
            adapter = FencedSocket(live)
            self.sock = adapter
            # Keep the adapter installed: urllib's ``do_open`` explicitly
            # calls ``h.sock.close()`` after getresponse.  That close must use
            # the same fenced shutdown path rather than bypassing transport
            # ownership on the live socket.
            return super().getresponse()

    class PinnedHTTPConnection(PinnedSendMixin, http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = transport.create_connection

    class PinnedHTTPSConnection(PinnedSendMixin, http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = transport.create_connection

        def connect(self):
            # Ambient HTTP CONNECT is not part of this transport; urllib's
            # ProxyHandler is empty, so observing a tunnel request is a caller
            # or stdlib authority mismatch and must fail before TCP contact.
            if self._tunnel_host is not None:
                raise OSError("native HTTPS tunnel authority is unavailable")
            http.client.HTTPConnection.connect(self)
            raw = self.sock
            try:
                self.sock = transport.wrap_tls(
                    raw, self._context, server_hostname=self.host,
                )
            except BaseException:
                self.sock = None
                raise

    context = _ssl.create_default_context()
    class PinnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(PinnedHTTPConnection, req)

    class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(
                PinnedHTTPSConnection, req, context=context,
                check_hostname=True,
            )

    opener = _http_only_opener(
        PinnedHTTPHandler(), PinnedHTTPSHandler(),
    )
    return opener, transport


def _network_scope(ctx):
    from . import network_policy

    return network_policy.scope_for(getattr(ctx, "run", None))


def _explicit_contact(scope, host, *, source_id, block_private):
    """Resolve through the scope's literal DNS authority, never ambient NSS."""
    from . import network_dns
    from .network_broker import BrokerPolicy

    policy_request_id = _secrets.token_hex(16)
    broker_policy = BrokerPolicy.from_json(json.dumps(
        scope.broker_policy(
            request_id=policy_request_id, source_id=source_id,
            tool="native-dns", approved_peers=(),
        ),
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ))
    planned: dict[tuple[str, int], list[str]] = {}

    def on_event(stage, peer, port, decision, reason):
        key = (peer, port)
        if stage == "dns-planned":
            request_id = _secrets.token_hex(16)
            scope.trace_native_planned(
                request_id=request_id, source_id=source_id,
                host=host, answers=(peer,), approved=(peer,), denied=(),
            )
            planned.setdefault(key, []).append(request_id)
            return
        if stage != "dns-settled" or not planned.get(key):
            raise RuntimeError("native DNS settlement lacked its durable plan")
        request_id = planned[key][0]
        scope.trace_native_settled(
            request_id=request_id, source_id=source_id, host=host,
            decision=decision, reason=reason, selected_peer=peer,
        )
        planned[key].pop(0)
        if not planned[key]:
            del planned[key]

    answers, state = network_dns.resolve(
        broker_policy, host, timeout=5.0, on_event=on_event,
        effect_fence=scope.effect_fence,
    )
    if planned:
        raise RuntimeError("native DNS authority retained an unsettled effect")
    if state != "ok":
        return netguard.ContactState(
            state, [], [], answers=answers, approved=(),
        )
    # ``stored_ips`` is the explicit wire result above, so contact_state takes
    # its no-resolution branch and only performs address classification.
    return netguard.contact_state(
        host, stored_ips=answers, block_private=block_private,
        own_ips=scope.own_ips, control_plane_cidrs=scope.control_plane_cidrs,
    )


def _contact(ctx, host, *, port, source_id="native-http"):
    if type(port) is not int or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("native contact port is invalid")
    scope = _network_scope(ctx)
    if scope is not None:
        decision, reason = scope.host_allowed(host, source_id=source_id)
        if decision != "allow":
            request_id = _secrets.token_hex(16)
            scope.trace_native(
                request_id=request_id, source_id=source_id, host=host,
                answers=(), approved=(), denied=(), decision="deny",
                reason=reason,
            )
            return netguard.ContactState(
                "scope_refused", [], [], answers=(), approved=(),
            )
    block_private = netguard._block_private(ctx)
    if scope is None:
        # Compatibility is intentionally limited to the still-unwired backend.
        # Production active work must bind a NetworkPolicyScope before this
        # branch is removed/enforced at runner integration.
        result = netguard.contact_state(host, block_private=block_private)
    else:
        result = _explicit_contact(
            scope, host, source_id=source_id, block_private=block_private,
        )
    if scope is not None and result[0] == "contact":
        denied = []
        for peer in result.approved:
            decision = scope.decide_peer(
                peer, port, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                source_id=source_id,
            )
            if not decision.allowed:
                denied.append(peer)
        # Public-provider rebinding and mixed safe/private answers refuse as a
        # unit; no answer from that resolution is attempted.
        if denied:
            result = netguard.ContactState(
                "scope_refused", denied, result[2], answers=result.answers,
                approved=(),
            )
    if scope is not None and result[0] != "contact":
        request_id = _secrets.token_hex(16)
        scope.trace_native(
            request_id=request_id, source_id=source_id, host=host,
            answers=getattr(result, "answers", ()), approved=(),
            denied=result[1], decision="deny", reason=result[0],
        )
    return result


def _open_contact(ctx, host, contact, req, timeout, *, insecure=False,
                  source_id="native-http"):
    """Persist admission, then open through one revalidated literal peer."""
    _validated_request_authority(req, host)
    if (type(contact) is not netguard.ContactState or contact[0] != "contact"
            or not contact.approved):
        raise PermissionError("native transport has no exact approved peer set")
    approved = contact.approved
    scope = _network_scope(ctx)
    request_id = _secrets.token_hex(16)
    attempt_ids = {}

    def trace_attempt(stage, peer, reason):
        if scope is None:
            return
        if stage == "planned":
            attempt_id = _secrets.token_hex(16)
            scope.trace_native_planned(
                request_id=attempt_id, source_id=source_id, host=host,
                answers=(peer,), approved=(peer,), denied=(),
            )
            attempt_ids[peer] = attempt_id
            return
        attempt_id = attempt_ids.pop(peer, None)
        if attempt_id is None:
            raise RuntimeError("native transport attempt settlement lacked a plan")
        scope.trace_native_settled(
            request_id=attempt_id, source_id=source_id, host=host,
            decision=("allow" if "connected" in reason else "deny"),
            reason=reason, selected_peer=peer,
        )
    opener, transport = _pinned_opener(
        approved, insecure=insecure,
        peer_authority=(
            (lambda peer, port, socket_type, protocol: scope.decide_peer(
                peer, port, socket_type, protocol, source_id=source_id,
            )) if scope is not None else None
        ),
        on_attempt=trace_attempt,
        effect_fence=(scope.effect_fence if scope is not None else None),
    )
    if scope is not None:
        # Build every effect-free TLS/opener object first.  Once this durable
        # plan exists, every later exit is paired by the settlement below.
        scope.trace_native_planned(
            request_id=request_id, source_id=source_id, host=host,
            answers=contact.answers, approved=approved, denied=(),
        )
    response = None
    try:
        status, headers, response = _open_no_follow(req, timeout, opener)
        if transport.selected_peer is None:
            raise OSError("transport did not prove its selected peer")
        if scope is not None:
            scope.trace_native_settled(
                request_id=request_id, source_id=source_id, host=host,
                decision="allow", reason="literal peer connected and verified",
                selected_peer=transport.selected_peer,
            )
        if response is not None:
            try:
                setattr(response, "_quarry_network_transport", transport)
            except BaseException:
                transport.release()
                raise
        else:
            transport.release()
        return status, headers, response
    except BaseException as primary:
        cleanup_faults = []
        try:
            transport.release()
        except BaseException as exc:
            cleanup_faults.append(exc)
        if response is not None:
            try:
                response.close()
            except BaseException as exc:
                cleanup_faults.append(exc)
        if scope is not None:
            try:
                scope.trace_native_settled(
                    request_id=request_id, source_id=source_id, host=host,
                    decision="deny", reason="literal peer connection did not settle",
                    selected_peer=transport.selected_peer,
                )
            except BaseException as trace_fault:
                scope.effect_fence.cancel()
                if not isinstance(primary, Exception):
                    raise primary
                raise trace_fault from primary
        raise _preferred_fault(primary, cleanup_faults)


def _pace(ctx) -> None:
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                    # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)


def _open_no_follow(req, timeout, opener=None):
    """Open `req` without following redirects. Returns (status, headers, response|None).

    A 3xx surfaces as a normal response or an HTTPError depending on handler order — both carry
    status+headers, normalized here. A 4xx/5xx is handed back rather than raised: an HTTPError is an
    open readable response, and a 401/403 'protected-but-present' body is evidence scoped_get keeps.
    Transport errors (URLError/timeout) still propagate — those are not a status."""
    try:
        resp = (opener or _NO_REDIRECT_OPENER).open(req, timeout=timeout)
        return getattr(resp, "status", 200), getattr(resp, "headers", {}) or {}, resp
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            try:
                return e.code, e.headers, None   # redirect surfaced as error: headers only, nothing to read
            finally:
                e.close()                        # HTTPError is itself an open response — release it here
        return e.code, (e.headers or {}), e      # 4xx/5xx: a readable response — hand it back, don't raise


def _validate_opened_response(status, headers, response) -> None:
    """Validate the opener tuple before any body or redirect is trusted."""
    if type(status) is not int or not 100 <= status <= 599:
        raise ValueError(f"HTTP response status is invalid: {status!r}")
    if not callable(getattr(headers, "get", None)):
        raise TypeError("HTTP response headers do not provide a mapping getter")
    if status in _REDIRECT_STATUSES:
        location = headers.get("Location")
        if location is not None and type(location) is not str:
            raise TypeError("HTTP redirect Location is not text")
    elif response is None:
        raise TypeError("non-redirect HTTP response has no readable body object")


def _validated_http_url(url: str):
    """Return a strict absolute HTTP(S) split or refuse before any resolver/I/O."""
    if type(url) is not str or not url or not url.isascii():
        raise ValueError("request URL must be an absolute ASCII HTTP(S) URL")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url):
        raise ValueError("request URL contains unsafe characters")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("request URL is malformed") from exc
    if (parts.scheme not in {"http", "https"} or not parts.netloc or not host
            or parts.username is not None or parts.password is not None
            or "@" in parts.netloc or "\\" in parts.netloc
            or "%" in host or normalize.canon_host_strict(host) is None):
        raise ValueError("request URL must be an absolute HTTP(S) URL without userinfo")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("request URL port is invalid")
    return parts


def _effective_http_port(parts) -> int:
    """Return the exact TCP authority implied by one validated URL split."""
    return parts.port or (443 if parts.scheme == "https" else 80)


def _validated_request_authority(req, expected_host: str):
    """Bind an exact urllib request to the host admitted by the resolver."""
    if type(req) is not urllib.request.Request:
        raise TypeError("native transport requires an exact urllib Request")
    parts = _validated_http_url(req.full_url)
    if (type(expected_host) is not str
            or normalize.canon_host_strict(expected_host) != expected_host
            or parts.hostname != expected_host
            or req.type != parts.scheme
            or req.host != parts.netloc
            or req.has_proxy()):
        raise PermissionError(
            "native request authority does not match its approved host",
        )
    if any(
        type(name) is not str or name.lower() in _AUTHORITY_HEADERS
        for name, _value in tuple(req.header_items())
    ):
        raise PermissionError(
            "native request headers cannot override transport authority",
        )
    return parts


def _preflight_managed_request(
    url, origin_host, *, timeout, data, method, headers, max_redirects,
) -> dict[str, str] | None:
    """Reject malformed managed request inputs before allocating a lease."""
    parts = _validated_http_url(url)
    host = parts.hostname
    if type(method) is not str or _HTTP_TOKEN_RE.fullmatch(method) is None:
        raise ValueError("managed acquisition method must be an HTTP token")
    if data is not None and type(data) is not bytes:
        raise TypeError("managed acquisition request body must be exact bytes or None")
    frozen_headers = None
    if headers is not None:
        if not isinstance(headers, Mapping):
            raise TypeError("managed acquisition headers must be a mapping")
        items = tuple(headers.items())
        frozen_headers = {}
        for item in items:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("managed acquisition header entries must be pairs")
            name, value = item
            if (type(name) is not str
                    or _HTTP_TOKEN_RE.fullmatch(name) is None):
                raise TypeError("managed acquisition header names must be HTTP tokens")
            if name.lower() in _AUTHORITY_HEADERS:
                raise ValueError(
                    "managed acquisition headers cannot override transport authority",
                )
            if type(value) is not str:
                raise TypeError("managed acquisition header values must be text")
            try:
                value.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "managed acquisition header values must be Latin-1 encodable",
                ) from exc
            if any(
                ord(char) < 0x20 and char != "\t" or ord(char) == 0x7f
                for char in value
            ):
                raise ValueError(
                    "managed acquisition header values contain control characters",
                )
            frozen_headers[name] = value
    if origin_host is not None:
        if (type(origin_host) is not str
                or normalize.canon_host_strict(origin_host) is None
                or origin_host != parts.hostname):
            raise ValueError("managed acquisition origin host is invalid")
    if (type(timeout) not in {int, float} or isinstance(timeout, bool)
            or not 0 <= timeout < float("inf")):
        raise ValueError("managed acquisition timeout must be finite and non-negative")
    if type(max_redirects) is not int or max_redirects < 0:
        raise ValueError("managed acquisition redirect count must be a non-negative integer")
    request_headers = {"User-Agent": UA}
    request_headers.update(frozen_headers or {})
    # Construction is effect-free and catches any remaining urllib request
    # shape fault before the durable managed claim exists.  Redirect requests
    # are derived later only from this frozen, validated representation.
    urllib.request.Request(
        url, data=data, method=method, headers=request_headers,
    )
    return frozen_headers


def redirect_location(ctx, url, origin_host=None, *, timeout=20,
                      source_id="native-http"):
    """One scoped, rate-paced request to `url` without following redirects; returns
    (location_header|None, status). For open-redirect probing: read where the app would send us
    without fetching the attacker-controlled target. Resolve-guards the origin as well as the caller's
    name-based scope gate, since redirect/SSRF candidates come from the gf/archive corpus. Returns
    (None, 0) for an origin that resolves to the scan box / metadata (a private origin is contacted) or
    cannot be resolved."""
    _parts = _validated_http_url(url)
    _h = _parts.hostname
    _contact_result = _contact(
        ctx, _h, port=_effective_http_port(_parts), source_id=source_id,
    )
    _st, _deny, _intel = _contact_result
    if _intel:
        netguard.record_internal(ctx, _h, _intel)          # record a private/self lead the lookup found
    if _st != "contact":
        return None, 0
    _pace(ctx)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    status, rhdrs, resp = _open_contact(
        ctx, _h, _contact_result, req, timeout, source_id=source_id,
    )
    try:
        return (rhdrs.get("Location") if rhdrs else None), status
    finally:
        if resp is not None:
            transport = getattr(resp, "_quarry_network_transport", None)
            try:
                if transport is not None:
                    transport.release()
            finally:
                resp.close()


@contextlib.contextmanager
def _walk(ctx, url, origin_host=None, *, timeout=20, data=None, method="GET", headers=None,
          max_redirects=DEFAULT_MAX_REDIRECTS, contact_attempt=None,
          response_cleanup=None, source_id="native-http"):
    """Walk the redirect chain with every guard and yield the terminal hop as `(resp, final, status,
    contacted)`; the response is still open, so the caller decides how the body is consumed. Shared by
    both body policies (bounded read and stream-to-disk) so one copy of the guards serves both.

    `contacted` False means the request was never made (a hop would leave scope or hit the scan box /
    metadata); status is 0, nothing to read. `contacted` True with `resp` None is an empty body — a
    redirect surfaced as an HTTPError (headers only) or the redirect limit was exhausted — never
    confused with off-scope."""
    initial_parts = _validated_http_url(url)
    if origin_host is not None and origin_host != initial_parts.hostname:
        raise ValueError("request origin host does not match its URL authority")
    origin = initial_parts.hostname
    hdrs = {"User-Agent": UA}
    if headers:
        if (not isinstance(headers, Mapping)
                or any(type(name) is not str
                       or name.lower() in _AUTHORITY_HEADERS
                       for name in tuple(headers))):
            raise ValueError("request headers cannot override transport authority")
        hdrs.update(headers)
    current = url
    cur_parts = initial_parts
    status = 0
    for _hop in range(max_redirects + 1):
        # self-attack guard on the origin and every redirect target: never contact the scan box /
        # metadata; record a private/self lead (private space is contacted unless block_private_targets).
        _contact_result = _contact(
            ctx, cur_parts.hostname, port=_effective_http_port(cur_parts),
            source_id=source_id,
        )
        _st, _deny, _intel = _contact_result
        if _intel:
            netguard.record_internal(ctx, cur_parts.hostname, _intel)
        if _st != "contact":
            yield None, current, 0, False
            return
        _pace(ctx)
        req = urllib.request.Request(current, data=data, method=method, headers=hdrs)
        if contact_attempt is not None:
            contact_attempt()
        status, rhdrs, resp = _open_contact(
            ctx, cur_parts.hostname, _contact_result, req, timeout,
            source_id=source_id,
        )
        with _response_lifetime(resp, response_cleanup):
            _validate_opened_response(status, rhdrs, resp)
            if status in _REDIRECT_STATUSES:
                loc = rhdrs.get("Location")
                if not loc:                              # redirect status without a Location — terminal
                    yield resp, current, status, True
                    return
                nxt = urljoin(current, loc)
                nxt_parts = _validated_http_url(nxt)
                nhost = normalize.host_of_url(nxt)
                if nhost != origin and not ctx.scope.active_allowed(nhost):
                    yield None, nxt, status, False       # would leave scope -> don't contact the target
                    return
                if (nxt_parts.hostname, nxt_parts.port, nxt_parts.scheme) != \
                   (cur_parts.hostname, cur_parts.port, cur_parts.scheme):
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() not in _SENSITIVE_HEADERS}
                cur_parts, current = nxt_parts, nxt
                data, method = None, "GET"               # follow non-mutating: never re-POST to a redirect
                continue
            yield resp, current, status, True            # terminal (incl 304)
            return
    yield None, current, status, True                    # redirect limit exceeded — not off-scope; empty body


def scoped_get(ctx, url, origin_host=None, *, max_body=DEFAULT_MAX_BODY, timeout=20,
               data=None, method="GET", headers=None, max_redirects=DEFAULT_MAX_REDIRECTS,
               source_id="native-http"):
    """Fetch `url` with all guards. Returns (data|None, final_url, status):
      - data is None  => the hop was not contacted: a redirect would leave scope, or the host resolves
        to the scan box / metadata (a private answer is contacted + recorded). No body is read.
      - otherwise     => bounded body read (<= max_body+1 bytes; caller drops if len > max_body).
    Sensitive headers are dropped when authority/scheme changes. Redirect-limit exhaustion returns an
    empty body (not None) so a loop is never mistaken for off-scope. Paces to profile.http_rl; caller
    must scope-gate the origin.

    Reads into memory, so it is the wrong tool when the body is evidence to keep: an over-cap response
    comes back as `max_body+1` bytes to drop, losing what was fetched. Use `scoped_get_file` instead."""
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects, source_id=source_id) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        return (resp.read(max_body + 1) if resp else b""), final, status


class Acquisition:
    """What a streamed fetch got; the artifact is on disk either way.

    `complete` False is not empty: `path` (or `partial`) holds the bytes that arrived and `error` says
    why the rest did not. Whether the body gets parsed is the caller's separate question. `contacted`
    and `disposition` distinguish a replayed receipt from a request. `disposition` is one of:

        complete             the body arrived whole, this call
        incomplete           we requested it and the transport or the disk broke, this call
        replayed-incomplete  a prior incomplete acquisition; nothing was requested
        path-collision       the artifact path is already owned by a different request

    `final` and `status` carry the original response line so a replay reports it rather than a synthetic
    zero — several lanes branch on status before completeness."""

    __slots__ = (
        "path", "bytes", "sha256", "complete", "partial", "error",
        "contacted", "disposition", "final", "status", "truncation",
        "_managed_run", "_managed_components", "_managed_body_components",
        "_managed_body_snapshot", "_managed_receipt_snapshot",
        "_managed_discard_certified",
    )

    def __init__(self, path, size, sha256, complete, partial=None, error=None,
                 contacted=True, disposition=None, final=None, status=None, truncation=None,
                 _managed_run=None, _managed_components=None,
                 _managed_body_components=None, _managed_body_snapshot=None,
                 _managed_receipt_snapshot=None,
                 _managed_discard_certified=False):
        self.path, self.bytes, self.sha256 = path, size, sha256
        self.complete, self.partial, self.error = complete, partial, error
        self.contacted = contacted
        self.disposition = disposition or ("complete" if complete else "incomplete")
        self.final, self.status = final, status
        self.truncation = truncation      # a typed `contract.Truncation` distinguishes it from a generic incomplete
        self._managed_run = _managed_run
        self._managed_components = _managed_components
        self._managed_body_components = _managed_body_components
        self._managed_body_snapshot = _managed_body_snapshot
        self._managed_receipt_snapshot = _managed_receipt_snapshot
        self._managed_discard_certified = bool(_managed_discard_certified)


#: the acquisition receipt sits beside the partial artifact and binds it to the request that produced
#: it — existence of a truncated-hash `.part` file is not identity.
_RECEIPT_SUFFIX = ".acq.json"


def acquisition_identity(url, method="GET", data=None, policy=None) -> str:
    """A digest of what makes two acquisitions the same request: URL, method, body, and any policy the
    caller says changes the answer — never the values themselves."""
    h = hashlib.sha256()
    for part in (str(method or "GET").upper(), str(url), str(policy or "")):
        h.update(part.encode("utf-8", "replace")); h.update(b"\x00")
    h.update(hashlib.sha256(data if isinstance(data, bytes) else (data or b"")).digest()
             if data is not None else b"")
    return h.hexdigest()


class AcquisitionRefused(Exception):
    """The acquisition state on disk does not permit a request. Typed (not a bare exception) and carries
    the disposition to report, so a refusal is a result — `scoped_get_file` converts it into an
    `Acquisition` rather than letting the caller's `except` count it as a network attempt."""

    def __init__(self, disposition, message, *, bytes_=0, partial=None, final=None, status=None,
                 digest="", truncation=None):
        super().__init__(message)
        self.disposition, self.bytes, self.partial = disposition, bytes_, partial
        self.final, self.status = final, status
        self.digest = digest             # a verified replay keeps the digest it checked
        self.truncation = truncation     # a replayed truncation carries its typed remainder forward


def _digest_file(path, chunk: int = 1024 * 1024) -> "tuple[int, str]":
    """(size, sha256) of a file, read in fixed-memory chunks."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf); n += len(buf)
    return n, h.hexdigest()


_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _refuse_os(what, path, e):
    """A filesystem error while inspecting ownership is not a network attempt: if we cannot inspect the
    state we do not know whether a request already happened, so we refuse and say contact did not occur."""
    return AcquisitionRefused("ownership-uninspectable",
                              f"cannot inspect {what} at {path} ({e}); the prior acquisition state is "
                              f"unknown, so this is NOT requested")


def _exists(path, follow=False):
    try:
        (path.stat() if follow else path.lstat())
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        raise _refuse_os("acquisition state", path, e) from e


def _read_regular(path, what):
    """Read a file without following a symlink, or refuse — a symlinked receipt could point at an
    external document and replay as our own ownership record."""
    try:
        # O_NOFOLLOW rejects a symlink; O_NONBLOCK keeps a FIFO from blocking the open forever. S_ISREG
        # below rejects both anyway; these flags just ensure we reach that check.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        if getattr(e, "errno", None) in (errno.ELOOP, errno.EMLINK):
            raise AcquisitionRefused("evidence-modified",
                                     f"{what} {path} is a symlink; refusing to follow it") from e
        raise AcquisitionRefused("receipt-unreadable",
                                 f"{what} {path} exists but cannot be read ({e}); refusing to request "
                                 f"again under an unknown prior state") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AcquisitionRefused("evidence-modified",
                                     f"{what} {path} is not a regular file; refusing")
        return os.read(fd, 1024 * 1024).decode("utf-8", "replace")
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    finally:
        os.close(fd)


def _str_field(doc, key, path, *, required=True):
    v = doc.get(key)
    if v is None and not required:
        return ""
    if not isinstance(v, str):
        return None
    return v


def _parse_receipt(raw, path):
    """Validate one already-authenticated acquisition receipt payload."""
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise AcquisitionRefused("receipt-damaged",
                                 f"acquisition receipt {path} is not valid JSON ({e}); a torn receipt "
                                 f"may describe a request already made — refusing") from e
    if not isinstance(doc, dict):
        raise AcquisitionRefused("receipt-damaged", f"acquisition receipt {path} is not an object")
    bad = []
    if not isinstance(doc.get("ident"), str) or not _HEX64.match(doc.get("ident") or ""):
        bad.append("ident (64-hex)")
    if type(doc.get("complete")) is not bool:                      # not `truthy`: the exact type
        bad.append("complete (bool)")
    n = doc.get("bytes")
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        bad.append("bytes (non-negative int)")
    if not isinstance(doc.get("digest"), str) or not _HEX64.match(doc.get("digest") or ""):
        bad.append("digest (64-hex, REQUIRED)")
    # validate every consumed field, not only the integrity four: `final`/`status` are handed straight
    # back to callers, so a malformed one must be caught here, not raised mid-interpretation.
    for key in ("url", "method"):
        if _str_field(doc, key, path) is None:
            bad.append(f"{key} (string)")
    if _str_field(doc, "final", path, required=False) is None:
        bad.append("final (string or absent)")
    if _str_field(doc, "error", path, required=False) is None:
        bad.append("error (string or absent)")
    st = doc.get("status")
    if st is not None and (isinstance(st, bool) or not isinstance(st, int) or not 0 <= st <= 599):
        bad.append("status (HTTP status int or absent)")
    # an incomplete receipt may carry a typed policy truncation: validate its shape so a replay
    # reconstructs it rather than reducing every incomplete to a generic one
    trunc = doc.get("truncation")
    if trunc is not None:
        try:
            contract.Truncation.from_receipt(trunc)
        except ValueError:
            bad.append("truncation ({kind: layer, limit: non-negative int})")
        # a truncation is a policy stop: a whole body cannot also be a truncated one
        if doc.get("complete") is True:
            bad.append("truncation on a complete acquisition (contradictory)")
    if bad:
        raise AcquisitionRefused("receipt-damaged",
                                 f"acquisition receipt {path} is missing or malformed: "
                                 f"{', '.join(bad)}; refusing to act on an unverifiable record")
    return doc


def _read_receipt(path):
    """The receipt as a validated record, or raise.

    "Unreadable" must not collapse into "absent": a torn receipt describes a request that may already
    have been made, so it refuses rather than fetching again. Every integrity field is required and
    typed — an optional digest is not an integrity check, and `complete` must be an actual bool."""
    return _parse_receipt(_read_regular(path, "acquisition receipt"), path)


def _verify_file(path, recorded_bytes, recorded_digest, *, what):
    """The stored evidence must be a regular file of exactly the recorded size and digest. Uses `lstat`
    (never `stat`) so a symlink pointed at matching external bytes is caught, not followed."""
    try:
        st = path.lstat()
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    if not stat.S_ISREG(st.st_mode):
        raise AcquisitionRefused("evidence-modified",
                                 f"{path} is not a regular file; refusing to treat it as {what}")
    try:
        size, sha = _digest_file(path)
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    if size != recorded_bytes or sha != recorded_digest:
        raise AcquisitionRefused("evidence-modified",
                                 f"{path} no longer matches its receipt ({size} bytes/{sha[:16]} vs "
                                 f"{recorded_bytes}/{recorded_digest[:16]}); the stored {what} changed "
                                 f"under us and is NOT re-fetched automatically",
                                 bytes_=size, digest=sha)
    return size, sha


def _reconcile(dest, part, rec_path, ident, url):
    """Decide whether this artifact path may be acquired into, reading all three files as one state.
    Only nothing-exists permits a request; every other combination means a prior acquisition happened
    or cannot be ruled out:

        nothing                  -> acquire
        dest, no receipt         -> orphan-complete     (evidence we cannot prove we own)
        part, no receipt         -> orphan-partial      (a crash, or a receipt that could not be written)
        receipt, other ident     -> path-collision      (this path belongs to a different request)
        receipt(complete), dest  -> replayed-complete   (verified; nothing requested)
        receipt(partial), part   -> replayed-incomplete (verified; nothing requested)
        receipt, file missing    -> evidence-lost
        file changed/symlink     -> evidence-modified
        receipt unreadable/torn  -> receipt-unreadable / receipt-damaged
        state uninspectable      -> ownership-uninspectable

    An operator clears any of these by removing the files; nothing here does it automatically, because
    each is evidence."""
    has_rec, has_part, has_dest = _exists(rec_path), _exists(part), _exists(dest)
    if not (has_rec or has_part or has_dest):
        return None
    if not has_rec:
        if has_part:
            raise AcquisitionRefused("orphan-partial",
                                     f"{part} exists with no acquisition receipt — a crash, or a "
                                     f"receipt that could not be written. Whose bytes these are is "
                                     f"unprovable, so this is NOT re-requested; remove the file to "
                                     f"try again", partial=part)
        raise AcquisitionRefused("orphan-complete",
                                 f"{dest} already holds an artifact with no acquisition receipt. It "
                                 f"cannot be proved to be this request's evidence, and it is NOT "
                                 f"overwritten by a fresh fetch; remove it to try again")
    rec = _read_receipt(rec_path)
    if rec.get("ident") != ident:
        # path owned by a different request (truncated-hash filenames collide); overwriting would mix
        # two URLs' evidence into one file — refuse loudly, never fetch under an ambiguous name.
        raise AcquisitionRefused("path-collision",
                                 f"artifact path {dest} already holds a different acquisition "
                                 f"({rec.get('url')!r}); refusing to overwrite or to fetch under an "
                                 f"ambiguous name")
    recorded, digest = rec["bytes"], rec["digest"]
    final, status = rec.get("final"), rec.get("status")
    # a receipt describes one file; the other being present is unaccounted evidence — refuse.
    if rec["complete"] and has_part:
        raise AcquisitionRefused("ownership-conflict",
                                 f"receipt describes a COMPLETE acquisition, but {part} is also "
                                 f"present; the extra file is unaccounted evidence — refusing until an "
                                 f"operator resolves it", partial=part, final=final, status=status)
    if not rec["complete"] and has_dest:
        raise AcquisitionRefused("ownership-conflict",
                                 f"receipt describes an INCOMPLETE acquisition, but {dest} is also "
                                 f"present; the extra file is unaccounted evidence — refusing until an "
                                 f"operator resolves it", final=final, status=status)
    if rec["complete"]:
        if not has_dest:
            raise AcquisitionRefused("evidence-lost",
                                     f"receipt records a COMPLETE acquisition of {url} but {dest} is "
                                     f"gone; refusing to silently re-fetch what we claim to have",
                                     bytes_=recorded, final=final, status=status)
        size, sha = _verify_file(dest, recorded, digest, what="acquired evidence")
        raise AcquisitionRefused("replayed-complete",
                                 "already acquired WHOLE in this run; not re-requested",
                                 bytes_=size, digest=sha, final=final, status=status)
    if not has_part:
        raise AcquisitionRefused("evidence-lost",
                                 f"receipt records {recorded} byte(s) of {url} but {part} is gone; the "
                                 f"partial evidence cannot be shown and is NOT re-fetched automatically",
                                 bytes_=recorded, final=final, status=status)
    size, sha = _verify_file(part, recorded, digest, what="partial evidence")
    # `_read_receipt` already validated the shape; rebuild the typed remainder so a replay reports the
    # truncation as one rather than a generic incomplete
    trunc = contract.Truncation.from_receipt(rec["truncation"]) if rec.get("truncation") is not None else None
    raise AcquisitionRefused("replayed-incomplete",
                             f"a prior acquisition of this URL was incomplete ({rec.get('error')}); "
                             f"NOT re-requested — remove {rec_path.name} and {part.name} to try again",
                             bytes_=size, digest=sha, partial=part, final=final, status=status,
                             truncation=trunc)


def _publish_receipt(rec_path, doc) -> str:
    """Write the receipt atomically. Returns "" on success or the failure text. The failure is reported
    (not suppressed): a partial with no receipt reconciles as `orphan-partial` and refuses, staying
    fail-closed."""
    tmp = None
    try:
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        # a unique name with O_CREAT|O_EXCL|O_NOFOLLOW cannot be pre-planted or symlink-followed, and the
        # write goes through the descriptor rather than a path resolved a second time.
        tmp = rec_path.with_name(f"{rec_path.name}.{os.getpid()}.{_secrets.token_hex(8)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            with contextlib.suppress(Exception):
                os.close(fd)
            raise
        os.replace(tmp, rec_path)
        return ""
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        with contextlib.suppress(Exception):
            if tmp is not None:
                tmp.unlink()
        return f"; the acquisition RECEIPT could not be written ({e}), so this artifact path is now " \
               f"refused until an operator clears it"


def _managed_root_hint(path: Path) -> Path | None:
    """Return a lexical ``recon/<run>`` ancestor without authenticating it."""
    for candidate in path.parents:
        if candidate.parent.name == "recon" and store.valid_run_id(candidate.name):
            return candidate
    return None


def _recon_namespace_hint(path: Path) -> Path | None:
    """Return any lexical ``recon`` ancestor.

    Legacy I/O needs negative proof that a destination is outside the reserved
    namespace.  That proof cannot depend on the child looking like a valid Run:
    control directories and damaged/untrusted Run names are reserved too.
    """
    for candidate in (path, *path.parents):
        if candidate.name == "recon":
            return candidate
    return None


def _contained_by(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _classify_acquisition_destination(ctx, dest: Path):
    """Classify before consulting caller authority; legacy requires negative proof.

    A lexical or resolved ``recon/<run>`` shape is managed even when its identity
    is damaged.  Such a path never falls through to ambient legacy I/O.
    """
    try:
        lexical = Path(os.path.abspath(os.fspath(dest)))
        resolved = lexical.resolve(strict=False)
    except (TypeError, ValueError, OSError) as exc:
        return "refused", None, None, f"destination identity is uninspectable: {exc}"
    lexical_root = _managed_root_hint(lexical)
    resolved_root = _managed_root_hint(resolved)
    lexical_recon = _recon_namespace_hint(lexical)
    resolved_recon = _recon_namespace_hint(resolved)
    caller_run = getattr(ctx, "run", None)
    under_recon = lexical_recon is not None or resolved_recon is not None
    if type(caller_run) is store.Run:
        try:
            project = Path(os.path.abspath(os.fspath(caller_run.project_dir)))
            recon_lexical = project / "recon"
            recon_resolved = recon_lexical.resolve(strict=False)
        except (TypeError, ValueError, OSError) as exc:
            return "refused", None, None, f"project recon identity is uninspectable: {exc}"
        under_recon = under_recon or (
            _contained_by(lexical, recon_lexical)
            or _contained_by(resolved, recon_resolved)
        )
    if lexical_root is None and resolved_root is None:
        if under_recon:
            return (
                "refused", None, None,
                "destination is inside the reserved recon control namespace",
            )
        return "legacy", None, None, ""
    if lexical != resolved:
        return (
            "refused", None, None,
            "managed destination uses a symlink alias; exact lexical Run authority is required",
        )
    if lexical_root is None:
        return "refused", None, None, "destination resolves into a managed Run through an alias"
    try:
        discovered = store.managed_run_for_artifact(lexical)
    except Exception as exc:
        return "refused", None, None, f"managed destination cannot be authenticated: {exc}"
    if discovered is None:
        return "refused", None, None, "managed-shaped destination has no authentic Run owner"
    discovered_run, components = discovered
    if type(caller_run) is not store.Run:
        return "refused", None, None, "managed destination requires an exact Run owner"
    if (caller_run._authority_key != discovered_run._authority_key
            or caller_run._run_directory_identity
            != discovered_run._run_directory_identity
            or Path(os.path.abspath(os.fspath(caller_run.dir))) != lexical_root):
        return "refused", None, None, "managed destination belongs to a different Run owner"
    return "managed", caller_run, components, ""


def _managed_refusal(message: str, url: str, *, disposition="managed-refused"):
    return (
        Acquisition(
            None, 0, "", False, contacted=False, disposition=disposition,
            error=f"{message}; NOT contacted", final=url, status=0,
        ),
        url,
        0,
    )


def _attach_managed_reconciliation(
    refusal, *, body_components, body_snapshot, receipt_snapshot,
):
    refusal.managed_body_components = body_components
    refusal.managed_body_snapshot = body_snapshot
    refusal.managed_receipt_snapshot = receipt_snapshot
    return refusal


def _managed_reconcile(transaction, components, ident, url, dest, part, rec_path):
    """Reconcile all three acquisition names through the pinned transaction."""
    receipt_components = components[:-1] + (components[-1] + _RECEIPT_SUFFIX,)
    part_components = components[:-1] + (components[-1] + ".part",)
    receipt = transaction.snapshot(receipt_components, content_limit=1024 * 1024)
    partial = transaction.snapshot(part_components)
    complete = transaction.snapshot(components)
    if receipt is None and partial is None and complete is None:
        return None
    if receipt is None:
        if partial is not None:
            raise _attach_managed_reconciliation(
                AcquisitionRefused(
                    "orphan-partial",
                    f"{part} exists with no acquisition receipt; prior contact is unprovable",
                    partial=part,
                ),
                body_components=part_components, body_snapshot=partial,
                receipt_snapshot=None,
            )
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "orphan-complete",
                f"{dest} exists with no acquisition receipt; prior contact is unprovable",
            ),
            body_components=components, body_snapshot=complete,
            receipt_snapshot=None,
        )
    try:
        raw = (receipt.data or b"").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "receipt-damaged",
                f"acquisition receipt {rec_path} is not valid UTF-8: {exc}",
            ),
            body_components=None, body_snapshot=None,
            receipt_snapshot=receipt,
        )
    try:
        doc = _parse_receipt(raw, rec_path)
    except AcquisitionRefused as refusal:
        raise _attach_managed_reconciliation(
            refusal, body_components=None, body_snapshot=None,
            receipt_snapshot=receipt,
        )
    if doc.get("ident") != ident:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "path-collision",
                f"artifact path {dest} belongs to a different acquisition ({doc.get('url')!r})",
            ),
            body_components=None, body_snapshot=None, receipt_snapshot=receipt,
        )
    recorded, digest = doc["bytes"], doc["digest"]
    final, status = doc.get("final"), doc.get("status")
    if doc["complete"] and partial is not None:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "ownership-conflict",
                f"complete receipt for {dest} conflicts with an unaccounted partial",
                partial=part, final=final, status=status,
            ),
            body_components=None, body_snapshot=None, receipt_snapshot=receipt,
        )
    if not doc["complete"] and complete is not None:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "ownership-conflict",
                f"incomplete receipt for {part} conflicts with an unaccounted complete body",
                final=final, status=status,
            ),
            body_components=None, body_snapshot=None, receipt_snapshot=receipt,
        )
    body = complete if doc["complete"] else partial
    body_components = components if doc["complete"] else part_components
    body_path = dest if doc["complete"] else part
    if body is None:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "evidence-lost",
                f"receipt records {recorded} byte(s) but {body_path} is gone",
                bytes_=recorded, final=final, status=status,
            ),
            body_components=body_components, body_snapshot=None,
            receipt_snapshot=receipt,
        )
    if body.size != recorded or body.digest != digest:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "evidence-modified",
                f"{body_path} no longer matches its acquisition receipt",
                bytes_=body.size, digest=body.digest,
                partial=part if not doc["complete"] else None,
                final=final, status=status,
            ),
            body_components=body_components, body_snapshot=body,
            receipt_snapshot=receipt,
        )
    if doc["complete"]:
        raise _attach_managed_reconciliation(
            AcquisitionRefused(
                "replayed-complete", "already acquired WHOLE; not re-requested",
                bytes_=body.size, digest=body.digest, final=final, status=status,
            ),
            body_components=body_components, body_snapshot=body,
            receipt_snapshot=receipt,
        )
    truncation = (
        contract.Truncation.from_receipt(doc["truncation"])
        if doc.get("truncation") is not None else None
    )
    raise _attach_managed_reconciliation(
        AcquisitionRefused(
            "replayed-incomplete",
            f"prior acquisition was incomplete ({doc.get('error')}); not re-requested",
            bytes_=body.size, digest=body.digest, partial=part,
            final=final, status=status, truncation=truncation,
        ),
        body_components=body_components, body_snapshot=body,
        receipt_snapshot=receipt,
    )


def _receipt_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")


def _scoped_get_file_legacy(ctx, url, dest, origin_host=None, *, timeout=20, data=None, method="GET",
                            headers=None, max_redirects=DEFAULT_MAX_REDIRECTS,
                            chunk=1024 * 1024, deadline_s=300.0, policy=None, governor=None,
                            source_id="native-http"):
    """Same guards as `scoped_get`, but the body is streamed to `dest` under `governor`'s disk policy.

    Returns `(Acquisition|None, final_url, status)`; None means the hop was never contacted, as in
    `scoped_get`. An `Acquisition` with `contacted` False is a refusal decided from the state on disk —
    no request was made — and `disposition` says which one.

    The body is not size-capped for its own sake — the request already happened and the bytes already
    crossed the wire — but a `DiskGovernor` bounds free space (and any configured byte ceiling) so a
    hostile infinite body cannot fill the host: at the boundary the partial is KEPT with `complete=False`
    (it reconciles as an incomplete acquisition) and the receipt records the binding layer as the
    durable, reproducible remainder.
    Fixed-memory chunks (`chunk` is what is held in RAM), hashed while streaming, published in one
    `os.replace`; a broken transport keeps the partial too. `deadline_s` bounds time. Nothing retries."""
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")
    rec_path = dest.with_name(dest.name + _RECEIPT_SUFFIX)
    ident = acquisition_identity(url, method, data, policy)
    try:
        _reconcile(dest, part, rec_path, ident, url)
    except AcquisitionRefused as r:
        # a refusal is a result: `contacted` False, so nothing counts it as an attempt on the target.
        return (Acquisition(dest if r.disposition == "replayed-complete" else None,
                            r.bytes, r.digest, r.disposition == "replayed-complete",
                            partial=r.partial, error=str(r), contacted=False,
                            disposition=r.disposition, final=r.final, status=r.status,
                            truncation=getattr(r, "truncation", None)),
                r.final or url, r.status or 0)
    # admit against the byte governor before contacting: an exhausted/tripped or misconfigured budget
    # must not open the request (no spend) and must leave no receipt
    try:
        gov = governor if governor is not None else contract.default_governor()
    except ValueError as e:
        return (Acquisition(None, 0, "", False, contacted=False, disposition="budget-invalid",
                            error=f"acquisition budget misconfigured; NOT contacted: {e}",
                            final=url, status=0), url, 0)
    dest.parent.mkdir(parents=True, exist_ok=True)
    denied = gov.admit(dest.parent)
    if denied is not None:
        return (Acquisition(None, 0, "", False, contacted=False, disposition="budget-exhausted",
                            error=f"acquisition budget exhausted at the {denied} policy; NOT contacted",
                            final=url, status=0), url, 0)
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects, source_id=source_id) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        if resp is None:                       # redirect loop / headers-only 3xx: an empty body, published
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"")
            n, sha = 0, hashlib.sha256(b"").hexdigest()
            note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                               "final": final, "status": status, "bytes": 0,
                                               "digest": sha, "complete": True})
            return (Acquisition(dest, 0, sha, True, final=final, status=status, error=note or None,
                                disposition="complete-unowned" if note else "complete"),
                    final, status)
        try:
            n, sha = contract.stream_to_file(resp, dest, chunk=chunk, deadline_s=deadline_s,
                                             governor=gov)
        except contract.IncompleteAcquisition as e:
            # the arrived bytes stay on disk with a receipt binding them to the request: an acquisition
            # gap, reported as one — never a silent empty result and never an automatic retry.
            written, partial = getattr(e, "bytes_written", 0), getattr(e, "partial", None)
            psha = ""
            if partial is not None and Path(partial).exists():
                written, psha = _digest_file(partial)     # what is on disk, not what we think we wrote
            rec = {"ident": ident, "url": url, "method": method, "final": final, "status": status,
                   "bytes": written, "digest": psha, "complete": False, "error": str(e)}
            # a policy truncation is a typed remainder: the binding layer + bound ride the receipt so a
            # raised bound is reproducible, distinct from a transport break with no configured cause.
            trunc = None
            if isinstance(e, contract.AcquisitionTruncated):
                trunc = contract.Truncation(e.limit_kind, e.limit_bytes)
                rec["truncation"] = trunc.as_receipt()
            note = _publish_receipt(rec_path, rec)
            # transport gap and ownership gap are separate facts: a failed receipt write makes the
            # disposition `-unowned` so the next lifecycle refuses the partial rather than trusting it.
            return (Acquisition(None, written, psha, False, partial=partial, error=str(e) + note,
                                disposition="incomplete-unowned" if note else "incomplete",
                                final=final, status=status, truncation=trunc), final, status)
        # bind the complete acquisition too, or another method/body/policy for the same URL overwrites
        # it. Written after the artifact; a failed write leaves it complete-but-unowned (orphan-complete).
        note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                           "final": final, "status": status, "bytes": n,
                                           "digest": sha, "complete": True})
        return (Acquisition(dest, n, sha, True, final=final, status=status, error=note or None,
                            disposition="complete-unowned" if note else "complete"),
                final, status)


def _managed_acquisition_from_refusal(run, components, dest, refusal, url):
    complete = refusal.disposition == "replayed-complete"
    certified = refusal.disposition in {
        "replayed-complete", "replayed-incomplete",
    }
    body_components = getattr(refusal, "managed_body_components", None)
    body_snapshot = getattr(refusal, "managed_body_snapshot", None)
    receipt_snapshot = getattr(refusal, "managed_receipt_snapshot", None)
    return Acquisition(
        dest if complete else None,
        refusal.bytes,
        refusal.digest,
        complete,
        partial=refusal.partial,
        error=str(refusal),
        contacted=False,
        disposition=refusal.disposition,
        final=refusal.final,
        status=refusal.status,
        truncation=getattr(refusal, "truncation", None),
        _managed_run=run,
        _managed_components=components,
        _managed_body_components=body_components if certified else None,
        _managed_body_snapshot=body_snapshot if certified else None,
        _managed_receipt_snapshot=receipt_snapshot if certified else None,
        _managed_discard_certified=certified,
    )


def _managed_facts(
    *, complete, disposition, path, partial, size, digest, final, status,
    truncation=None, errors=(), body_components=None, body_snapshot=None,
    receipt_snapshot=None, contacted=True,
):
    return {
        "complete": complete,
        "disposition": disposition,
        "path": path,
        "partial": partial,
        "bytes": size,
        "digest": digest,
        "final": final,
        "status": status,
        "truncation": truncation,
        "errors": list(errors),
        "body_components": body_components,
        "body_snapshot": body_snapshot,
        "receipt_snapshot": receipt_snapshot,
        "contacted": contacted,
    }


def _cas_committed(fault) -> bool:
    return getattr(fault, "state", "") in {"committed", "committed_with_fault"}


def _cas_uncertain(fault) -> bool:
    return getattr(fault, "state", "") == "uncertain"


def _publication_fault_text(fault) -> str:
    """Include the typed CAS outcome and its concrete namespace fault."""
    details = [str(fault)]
    for name in ("action_error", "reconciliation_error", "__cause__"):
        nested = getattr(fault, name, None)
        if (isinstance(nested, BaseException) and nested is not fault
                and str(nested) not in details):
            details.append(str(nested))
    return ": ".join(detail for detail in details if detail)


def _scoped_get_file_managed(
    ctx, run, components, url, dest, origin_host, *, timeout, data, method,
    headers, max_redirects, chunk, deadline_s, policy, governor, source_id,
):
    """One authority-first managed acquisition; construct its result after settlement."""
    part = dest.with_name(dest.name + ".part")
    rec_path = dest.with_name(dest.name + _RECEIPT_SUFFIX)
    part_components = components[:-1] + (components[-1] + ".part",)
    receipt_components = components[:-1] + (components[-1] + _RECEIPT_SUFFIX,)
    ident = acquisition_identity(url, method, data, policy)
    facts = None
    refusal = None
    transaction = None
    contacted = False
    deferred: list[BaseException] = []
    settlement_fault = None
    settlement_diagnostic = None
    response_cleanup = _ResponseCleanupState()

    try:
        with run.managed_acquisition_claim(*components) as transaction:
            try:
                _managed_reconcile(
                    transaction, components, ident, url, dest, part, rec_path,
                )
            except AcquisitionRefused as existing:
                refusal = existing
            if refusal is not None:
                body_snapshot = getattr(
                    refusal, "managed_body_snapshot", None,
                )
                receipt_snapshot = getattr(
                    refusal, "managed_receipt_snapshot", None,
                )
                if body_snapshot is not None and receipt_snapshot is not None:
                    absent_components = (
                        part_components
                        if tuple(body_snapshot.components) == tuple(components)
                        else components
                    )
                    transaction.certify_pair(
                        body_snapshot, receipt_snapshot,
                        absent_components=absent_components,
                    )
                else:
                    transaction.settle_precontact()
            if refusal is None:
                try:
                    denied = governor.admit(dest.parent)
                except Exception as exc:
                    facts = _managed_facts(
                        complete=False, disposition="budget-invalid", path=None,
                        partial=None, size=0, digest="", final=url, status=0,
                        contacted=False,
                        errors=(f"acquisition budget cannot be inspected; NOT contacted: {exc}",),
                    )
                else:
                    if denied is not None:
                        facts = _managed_facts(
                            complete=False, disposition="budget-exhausted", path=None,
                            partial=None, size=0, digest="", final=url, status=0,
                            contacted=False,
                            errors=(f"acquisition budget exhausted at {denied}; NOT contacted",),
                        )
                if facts is not None and not facts.get("contacted"):
                    transaction.settle_precontact()
                if facts is None:
                    try:
                        with _walk(
                            ctx, url, origin_host, timeout=timeout, data=data,
                            method=method, headers=headers,
                            max_redirects=max_redirects,
                            source_id=source_id,
                            contact_attempt=transaction.mark_contact_attempted,
                            response_cleanup=response_cleanup,
                        ) as (response, final, status, did_contact):
                            if not did_contact:
                                if transaction.contact_attempted:
                                    contacted = True
                                    facts = _managed_facts(
                                        complete=False,
                                        disposition="managed-uncertain",
                                        path=None, partial=None, size=0,
                                        digest="", final=final, status=status,
                                        errors=(
                                            "a contacted redirect chain ended at an uncontacted hop; "
                                            "the provider outcome is retained as uncertain",
                                        ),
                                    )
                                else:
                                    facts = {
                                        "not_contacted": True,
                                        "final": final,
                                        "status": status,
                                    }
                                    transaction.settle_precontact()
                            else:
                                contacted = True
                                source = response if response is not None else io.BytesIO(b"")
                                writer = transaction.open_writer()
                                stream_fault = None
                                try:
                                    size, digest = contract.stream_to_fd(
                                        source, writer, budget_path=dest.parent,
                                        chunk=chunk, deadline_s=deadline_s,
                                        governor=governor,
                                    )
                                except BaseException as exc:
                                    stream_fault = exc
                                    size = getattr(exc, "bytes_written", 0)
                                    digest = getattr(exc, "sha256", "")
                                    if type(size) is not int or size < 0:
                                        size = 0
                                    if type(digest) is not str:
                                        digest = ""
                                if (stream_fault is not None
                                        and not isinstance(stream_fault, Exception)):
                                    deferred.append(stream_fault)
                                whole = stream_fault is None
                                target_components = components if whole else part_components
                                target_path = dest if whole else part
                                truncation = None
                                if isinstance(stream_fault, contract.AcquisitionTruncated):
                                    truncation = contract.Truncation(
                                        stream_fault.limit_kind,
                                        stream_fault.limit_bytes,
                                    )
                                body_faults = []
                                try:
                                    published = transaction.publish_body_if_absent(
                                        target_components,
                                    )
                                except store.ManagedAcquisitionRefused:
                                    raise
                                except BaseException as exc:
                                    body_faults.append(exc)
                                    if not isinstance(exc, Exception):
                                        deferred.append(exc)
                                    if _cas_committed(exc):
                                        published = True
                                    elif _cas_uncertain(exc):
                                        # The public transaction owns the same
                                        # staged body across an uncertain CAS.
                                        # One bounded replay either terminalizes
                                        # that exact publication or preserves its
                                        # durable crash marker.
                                        try:
                                            published = (
                                                transaction.publish_body_if_absent(
                                                    target_components,
                                                )
                                            )
                                        except store.ManagedAcquisitionRefused:
                                            raise
                                        except BaseException as replay_exc:
                                            body_faults.append(replay_exc)
                                            if not isinstance(replay_exc, Exception):
                                                deferred.append(replay_exc)
                                            if _cas_committed(replay_exc):
                                                published = True
                                            else:
                                                published = None
                                                facts = _managed_facts(
                                                    complete=False,
                                                    disposition="publication-uncertain",
                                                    path=None, partial=None, size=size,
                                                    digest=digest, final=final,
                                                    status=status,
                                                    truncation=truncation,
                                                    errors=tuple(
                                                        "body publication uncertain: "
                                                        f"{_publication_fault_text(fault)}"
                                                        for fault in body_faults
                                                    ),
                                                )
                                    else:
                                        published = None
                                        facts = _managed_facts(
                                            complete=False,
                                            disposition="publication-failed",
                                            path=None, partial=None, size=size,
                                            digest=digest, final=final, status=status,
                                            truncation=truncation,
                                            errors=(f"body publication failed: {exc}",),
                                        )
                                if published is False:
                                    transaction.retain_uncertain(
                                        "managed body destination appeared after contact",
                                    )
                                    facts = _managed_facts(
                                        complete=False,
                                        disposition="publication-collision",
                                        path=None, partial=None, size=size,
                                        digest=digest, final=final, status=status,
                                        truncation=truncation,
                                        errors=(
                                            "the destination appeared after reconciliation and was not overwritten",
                                        ),
                                    )
                                elif published is True:
                                    body_snapshot = transaction.snapshot(target_components)
                                    if body_snapshot is None:
                                        transaction.retain_uncertain(
                                            "published body disappeared after contact",
                                        )
                                        facts = _managed_facts(
                                            complete=False,
                                            disposition="publication-uncertain",
                                            path=None, partial=None, size=size,
                                            digest=digest, final=final, status=status,
                                            truncation=truncation,
                                            errors=("published body disappeared before reconciliation",),
                                        )
                                    elif (digest and (
                                        body_snapshot.size != size
                                        or body_snapshot.digest != digest
                                    )):
                                        transaction.retain_uncertain(
                                            "published body changed after contact",
                                        )
                                        facts = _managed_facts(
                                            complete=False,
                                            disposition="publication-uncertain",
                                            path=None, partial=None,
                                            size=body_snapshot.size,
                                            digest=body_snapshot.digest,
                                            final=final, status=status,
                                            truncation=truncation,
                                            errors=("published body changed before reconciliation",),
                                        )
                                    else:
                                        size, digest = body_snapshot.size, body_snapshot.digest
                                        stream_note = "" if stream_fault is None else str(stream_fault)
                                        receipt_doc = {
                                            "ident": ident,
                                            "url": url,
                                            "method": method,
                                            "final": final,
                                            "status": status,
                                            "bytes": size,
                                            "digest": digest,
                                            "complete": whole,
                                        }
                                        if stream_note:
                                            receipt_doc["error"] = stream_note
                                        if truncation is not None:
                                            receipt_doc["truncation"] = truncation.as_receipt()
                                        encoded_receipt = _receipt_bytes(receipt_doc)
                                        receipt_faults = []
                                        receipt_uncertain = False
                                        try:
                                            receipt_published = (
                                                transaction.publish_companion_if_absent(
                                                    receipt_components, encoded_receipt,
                                                )
                                            )
                                        except store.ManagedAcquisitionRefused:
                                            raise
                                        except BaseException as exc:
                                            receipt_faults.append(exc)
                                            if not isinstance(exc, Exception):
                                                deferred.append(exc)
                                            if _cas_committed(exc):
                                                receipt_published = True
                                            elif _cas_uncertain(exc):
                                                # Companion publication freezes
                                                # these exact bytes and reuses its
                                                # private stage for this one replay.
                                                try:
                                                    receipt_published = (
                                                        transaction
                                                        .publish_companion_if_absent(
                                                            receipt_components,
                                                            encoded_receipt,
                                                        )
                                                    )
                                                except store.ManagedAcquisitionRefused:
                                                    raise
                                                except BaseException as replay_exc:
                                                    receipt_faults.append(replay_exc)
                                                    if not isinstance(
                                                        replay_exc, Exception,
                                                    ):
                                                        deferred.append(replay_exc)
                                                    if _cas_committed(replay_exc):
                                                        receipt_published = True
                                                    else:
                                                        receipt_published = False
                                                        receipt_uncertain = True
                                            else:
                                                receipt_published = False
                                        receipt_snapshot = None
                                        receipt_owned = False
                                        if receipt_published:
                                            receipt_snapshot = transaction.snapshot(
                                                receipt_components,
                                                content_limit=1024 * 1024,
                                            )
                                            receipt_owned = (
                                                receipt_snapshot is not None
                                                and receipt_snapshot.data == encoded_receipt
                                            )
                                        errors = []
                                        if stream_fault is not None:
                                            errors.append(stream_note)
                                        for body_fault in body_faults:
                                            errors.append(
                                                "body publication reported after commit: "
                                                f"{_publication_fault_text(body_fault)}",
                                            )
                                        for receipt_fault in receipt_faults:
                                            errors.append(
                                                "receipt publication fault: "
                                                f"{_publication_fault_text(receipt_fault)}",
                                            )
                                        if receipt_uncertain:
                                            errors.append(
                                                "receipt publication remained uncertain after replay",
                                            )
                                        if not receipt_owned:
                                            errors.append(
                                                "the acquisition receipt was not owned; the body snapshot is not a "
                                                "current readable artifact and this path will refuse replay",
                                            )
                                        if receipt_uncertain:
                                            transaction.retain_uncertain(
                                                "receipt publication remained uncertain",
                                            )
                                            disposition = "receipt-uncertain"
                                        else:
                                            disposition = (
                                                "complete" if whole and receipt_owned
                                                else "incomplete" if not whole and receipt_owned
                                                else "complete-unowned" if whole
                                                else "incomplete-unowned"
                                            )
                                        if not receipt_owned:
                                            transaction.retain_uncertain(
                                                "acquisition receipt was not owned after contact",
                                            )
                                        facts = _managed_facts(
                                            complete=(
                                                whole and receipt_owned
                                                and not receipt_uncertain
                                            ),
                                            disposition=disposition,
                                            path=(
                                                dest if whole and receipt_owned
                                                and not receipt_uncertain else None
                                            ),
                                            partial=(
                                                part if not whole and receipt_owned
                                                and not receipt_uncertain else None
                                            ),
                                            size=size, digest=digest,
                                            final=final, status=status,
                                            truncation=truncation, errors=errors,
                                            body_components=target_components,
                                            body_snapshot=body_snapshot,
                                            receipt_snapshot=(
                                                receipt_snapshot if receipt_owned else None
                                            ),
                                        )
                                        if receipt_owned:
                                            absent_components = (
                                                part_components if whole else components
                                            )
                                            transaction.certify_pair(
                                                body_snapshot, receipt_snapshot,
                                                absent_components=absent_components,
                                            )
                    except BaseException as exc:
                        close_outcome = response_cleanup.outcome
                        close_only = bool(
                            close_outcome is not None
                            and close_outcome[0] is exc
                            and close_outcome[1]
                        )
                        if facts is not None and contacted and close_only:
                            if not isinstance(exc, Exception):
                                deferred.append(exc)
                            else:
                                facts.setdefault("errors", []).append(
                                    f"response close fault: {exc}",
                                )
                        elif transaction.contact_attempted:
                            contacted = True
                            prior = facts if isinstance(facts, dict) else {}
                            if not isinstance(exc, Exception):
                                deferred.append(exc)
                            facts = _managed_facts(
                                complete=False,
                                disposition="managed-uncertain",
                                path=None, partial=None,
                                size=prior.get("bytes", 0),
                                digest=prior.get("digest", ""),
                                final=prior.get("final", url),
                                status=prior.get("status", 0),
                                truncation=prior.get("truncation"),
                                errors=tuple(prior.get("errors", ())) + (
                                    "managed acquisition did not obtain a current terminal "
                                    f"certificate ({type(exc).__name__}: {exc})",
                                ),
                            )
                        else:
                            deferred.append(exc)
    except BaseException as exc:
        settlement_fault = exc

    # An exact cancellation recorded inside the operation always outranks a
    # later ordinary settlement/refusal result.  Dispatch it before any branch
    # below can return a managed diagnostic.
    preferred = _preferred_fault(None, deferred)
    if preferred is not None and not isinstance(preferred, Exception):
        raise preferred

    if settlement_fault is not None:
        if not isinstance(settlement_fault, Exception):
            deferred.append(settlement_fault)
        elif (transaction is not None
              and transaction.settlement_state == "released"
              and (facts is not None or refusal is not None)):
            reported = (
                "transaction settlement reported after terminal release: "
                f"{settlement_fault}"
            )
            if facts is not None and "errors" in facts:
                facts.setdefault("errors", []).append(reported)
            elif refusal is not None:
                settlement_diagnostic = reported
        elif (transaction is not None
              and transaction.settlement_state == "retained-uncertain"
              and facts is not None and contacted):
            retained_error = (
                "transaction settlement retained crash evidence: "
                f"{settlement_fault}"
            )
            if (facts.get("complete") or facts.get("path") is not None
                    or facts.get("partial") is not None):
                facts = _managed_facts(
                    complete=False, disposition="managed-uncertain",
                    path=None, partial=None,
                    size=facts.get("bytes", 0),
                    digest=facts.get("digest", ""),
                    final=facts.get("final", url),
                    status=facts.get("status", 0),
                    truncation=facts.get("truncation"),
                    errors=tuple(facts.get("errors", ())) + (
                        retained_error,
                    ),
                )
            else:
                facts.setdefault("errors", []).append(retained_error)
        elif (facts is not None
              and facts.get("disposition") in {
                  "publication-uncertain", "publication-failed",
                  "receipt-uncertain",
              }):
            facts.setdefault("errors", []).append(
                f"transaction settlement retained crash evidence: {settlement_fault}",
            )
        elif (transaction is not None
              and transaction.settlement_state == "retained-uncertain"
              and not contacted):
            return _managed_refusal(
                "managed acquisition state could not be certified and its "
                f"durable lease was retained: {settlement_fault}",
                url, disposition="managed-authority-refused",
            )
        elif refusal is None and not contacted and facts is None:
            return _managed_refusal(
                f"managed acquisition authority refused: {settlement_fault}", url,
                disposition="managed-authority-refused",
            )
        else:
            deferred.append(settlement_fault)

    preferred = _preferred_fault(None, deferred)
    if preferred is not None:
        raise preferred
    if refusal is not None:
        acquisition = _managed_acquisition_from_refusal(
            run, components, dest, refusal, url,
        )
        if settlement_diagnostic:
            acquisition.error = (
                f"{acquisition.error}; {settlement_diagnostic}"
            )
        return acquisition, refusal.final or url, refusal.status or 0
    if facts is not None and facts.get("not_contacted"):
        return None, facts["final"], facts["status"]
    if facts is None:
        return _managed_refusal(
            "managed acquisition did not reach a reconciled terminal fact", url,
            disposition="managed-uncertain",
        )
    error = "; ".join(item for item in facts["errors"] if item) or None
    acquisition = Acquisition(
        facts["path"], facts["bytes"], facts["digest"], facts["complete"],
        partial=facts["partial"], error=error,
        contacted=facts["contacted"], disposition=facts["disposition"],
        final=facts["final"], status=facts["status"],
        truncation=facts["truncation"],
        _managed_run=run, _managed_components=components,
        _managed_body_components=facts["body_components"],
        _managed_body_snapshot=facts["body_snapshot"],
        _managed_receipt_snapshot=facts["receipt_snapshot"],
        _managed_discard_certified=(
            transaction is not None
            and transaction.settlement_state == "released"
            and facts["body_snapshot"] is not None
            and facts["receipt_snapshot"] is not None
        ),
    )
    return acquisition, facts["final"], facts["status"]


def scoped_get_file(ctx, url, dest, origin_host=None, *, timeout=20, data=None, method="GET",
                    headers=None, max_redirects=DEFAULT_MAX_REDIRECTS,
                    chunk=1024 * 1024, deadline_s=300.0, policy=None, governor=None,
                    source_id="native-http"):
    """Stream one guarded response through managed authority or proven legacy I/O."""
    dest = Path(dest)
    classification, run, components, reason = _classify_acquisition_destination(ctx, dest)
    if classification == "legacy":
        return _scoped_get_file_legacy(
            ctx, url, dest, origin_host, timeout=timeout, data=data,
            method=method, headers=headers, max_redirects=max_redirects,
            chunk=chunk, deadline_s=deadline_s, policy=policy,
            governor=governor, source_id=source_id,
        )
    if classification == "refused":
        return _managed_refusal(reason, url)
    headers = _preflight_managed_request(
        url, origin_host, timeout=timeout, data=data, method=method,
        headers=headers, max_redirects=max_redirects,
    )
    managed_governor = contract.preflight_stream_to_fd(
        chunk=chunk, deadline_s=deadline_s, governor=governor,
    )
    return _scoped_get_file_managed(
        ctx, run, components, url, dest, origin_host,
        timeout=timeout, data=data, method=method, headers=headers,
        max_redirects=max_redirects, chunk=chunk, deadline_s=deadline_s,
        policy=policy, governor=managed_governor, source_id=source_id,
    )


def discard_acquisition(ctx, acquisition):
    """Conditionally discard only the exact managed body/receipt snapshots."""
    if not isinstance(acquisition, Acquisition) or acquisition._managed_run is None:
        return None
    if not acquisition._managed_discard_certified:
        raise AcquisitionRefused(
            "managed-discard-refused",
            "managed acquisition discard requires a certified owned body/receipt pair",
        )
    run = getattr(ctx, "run", None)
    if run is not acquisition._managed_run or type(run) is not store.Run:
        raise AcquisitionRefused(
            "managed-owner-refused",
            "managed acquisition discard requires its exact Run owner",
        )
    components = acquisition._managed_components
    body_components = acquisition._managed_body_components
    receipt_components = components[:-1] + (components[-1] + _RECEIPT_SUFFIX,)
    body_components = body_components or components
    ledger = None
    primary = None
    try:
        with run.managed_acquisition_discard_claim(*components) as transaction:
            ledger = transaction.discard_pair(
                body_components, acquisition._managed_body_snapshot,
                receipt_components, acquisition._managed_receipt_snapshot,
            )
    except BaseException as exc:
        primary = exc
        ledger = getattr(exc, "managed_discard", ledger)
    if primary is not None:
        if ledger is not None:
            try:
                primary.managed_discard = ledger
            except BaseException:
                pass
        raise primary
    return {"body": ledger.body, "receipt": ledger.receipt}


def scoped_headers(ctx, url, *, timeout=20, max_redirects=DEFAULT_MAX_REDIRECTS, max_body=512 * 1024,
                   insecure=False, source_id="native-http"):
    """Guarded header+body fetch: resolve- + scope-guard every hop, follow only in-scope redirects,
    return (headers|None, body, final_url, status). headers is None when a hop would leave scope / hit
    the scan box (never contacted) or on a swallowed transport failure (URLError/TLS/timeout), so one
    bad request never aborts the caller's phase. A bounded body is read (for <meta http-equiv> CSP).
    ``insecure`` is retained only as a compatibility argument and any true value is refused before
    resolution/contact; every accepted HTTPS response preserves hostname and certificate checks."""
    if insecure is not False:
        raise ValueError("native HTTPS certificate verification cannot be disabled")
    initial_parts = _validated_http_url(url)
    origin = normalize.host_of_url(url)
    current = url
    cur_parts = initial_parts
    status = 0
    for _hop in range(max_redirects + 1):
        _contact_result = _contact(
            ctx, cur_parts.hostname, port=_effective_http_port(cur_parts),
            source_id=source_id,
        )
        _st, _deny, _intel = _contact_result
        if _intel:
            netguard.record_internal(ctx, cur_parts.hostname, _intel)
        if _st != "contact":
            return None, b"", current, 0                  # scan box/metadata/unresolved -> not contacted
        _pace(ctx)
        req = urllib.request.Request(current, headers={"User-Agent": UA}, method="GET")
        try:
            status, rhdrs, resp = _open_contact(
                ctx, cur_parts.hostname, _contact_result, req, timeout,
                insecure=insecure, source_id=source_id,
            )
        except (urllib.error.URLError, OSError):
            return None, b"", current, 0                  # transport failure -> swallow, caller continues
        try:
            if status in _REDIRECT_STATUSES:
                loc = rhdrs.get("Location") if rhdrs else None
                if not loc:
                    return rhdrs, b"", current, status
                nxt = urljoin(current, loc)
                nxt_parts = _validated_http_url(nxt)
                if normalize.host_of_url(nxt) != origin and not ctx.scope.active_allowed(normalize.host_of_url(nxt)):
                    return None, b"", nxt, status         # redirect would leave scope -> stop
                cur_parts, current = nxt_parts, nxt
                continue
            body = resp.read(max_body) if resp else b""
            return rhdrs, body, current, status
        finally:
            if resp is not None:
                transport = getattr(resp, "_quarry_network_transport", None)
                try:
                    if transport is not None:
                        transport.release()
                finally:
                    resp.close()
    return None, b"", current, status
