"""Bounded literal-resolver DNS for the runner-owned browser proxy."""
from __future__ import annotations

import ipaddress
import errno
import os
import select
import socket
import struct
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


class NetworkDNSRefused(NetworkBrokerRefused):
    """The explicit resolver exchange was malformed or unauthorised."""


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


__all__ = ("NetworkDNSRefused", "resolve")
