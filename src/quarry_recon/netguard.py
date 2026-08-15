"""Self-attack guard. `record`: a host resolving private/self is a review(internal-resolution) finding.
`deny`: contact refused only for the scan box itself (loopback, link-local, cloud metadata, unspecified,
own-interface addrs); private space is contacted unless block_private_targets. Hosts fresh-resolve at the
tool boundary (bounded, uncached); a public->metadata rebind between resolve and tool is a residual risk."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import multiprocessing as _mp
import os
import re
import socket
import threading
import time
from collections.abc import Mapping
from collections import deque
from multiprocessing import connection as _mpc
from types import MappingProxyType
from typing import NamedTuple

_NEG_ERRNOS = {getattr(socket, n) for n in ("EAI_NONAME", "EAI_NODATA")
               if getattr(socket, n, None) is not None}

# Loopback / link-local / unspecified — always the scan box, never a target.
_SELF_NETS = tuple(ipaddress.ip_network(c) for c in
                   ("127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "0.0.0.0/32", "::1/128", "::/128"))
# Cloud instance-metadata endpoints — our own credentials sit behind these.
_METADATA_NETS = tuple(ipaddress.ip_network(c) for c in
                       ("169.254.169.254/32", "169.254.170.2/32", "100.100.100.200/32", "fd00:ec2::254/128"))
# Contacted unless block_private_targets; also the trigger for recording internal-resolution intel.
_PRIVATE_NETS = tuple(ipaddress.ip_network(c) for c in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))


def _own_ips() -> frozenset[str]:
    """The scan box's own interface addresses. Best-effort; computed once at import."""
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:
        pass
    for fam, dst in ((socket.AF_INET, ("8.8.8.8", 80)), (socket.AF_INET6, ("2001:4860:4860::8888", 80))):
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.connect(dst)
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return frozenset(ips)


_OWN_IPS = _own_ips()


def _norm(ip: str):
    """Parse, unwrapping an IPv4-mapped IPv6 (::ffff:127.0.0.1 -> 127.0.0.1). None if unparseable."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def is_self_attack_ip(ip: str) -> bool:
    """True for a destination that is the scan box itself: loopback, link-local, metadata, own interface.
    Never contactable under any mode; an unparseable address is also true, to fail closed."""
    a = _norm(ip)
    if a is None:
        return True
    if ip in _OWN_IPS or str(a) in _OWN_IPS:
        return True
    return any(a in n for n in _SELF_NETS) or any(a in n for n in _METADATA_NETS)


def is_private_ip(ip: str) -> bool:
    """True for private space — contacted by default, blocked only under block_private_targets."""
    a = _norm(ip)
    return a is not None and any(a in n for n in _PRIVATE_NETS)


def is_contactable_ip(ip: str, *, block_private: bool = False) -> bool:
    """Contactable unless it's a self-attack destination (always) or private-under-block_private."""
    if is_self_attack_ip(ip):
        return False
    if block_private and is_private_ip(ip):
        return False
    return True


def intel_ips(ips) -> list[str]:
    """The answers worth recording as internal-resolution intel — any non-public one. Independent of
    the contact decision."""
    return sorted({ip for ip in ips if ip and (is_self_attack_ip(ip) or is_private_ip(ip))})


def _mapped_cidr(net) -> str:
    """The IPv4-mapped IPv6 form of a v4 network: 100.100.100.200/32 -> ::ffff:100.100.100.200/128."""
    return f"::ffff:{net.network_address}/{96 + net.prefixlen}"


def self_deny_list() -> str:
    """Comma-joined CIDR deny list of self, metadata and own-interface ranges, each v4 range also in its
    IPv4-mapped form so a tool whose deny parser does not normalize `::ffff:…` still refuses it. Private
    space is deliberately absent — it is contacted."""
    nets = _SELF_NETS + _METADATA_NETS
    parts = {str(n) for n in nets}
    parts |= {_mapped_cidr(n) for n in nets if n.version == 4}
    for ip in _OWN_IPS:
        if ":" in ip:
            parts.add(f"{ip}/128")
        else:
            parts.add(f"{ip}/32")
            parts.add(f"::ffff:{ip}/128")
    return ",".join(sorted(parts))


def _getaddrinfo(host: str) -> list[str]:
    return sorted({i[4][0] for i in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


# fork is unsafe only from a multithreaded process: single-threaded callers fork, multithreaded use forkserver.
# `_STUB` injects a test resolver as a picklable arg passed to each worker (no monkeypatch inheritance).
_MP = _mp.get_context("forkserver")   # for Value/Event/etc.; picklable to a forkserver child and fork-inherited
_STUB = None                     # None=real; {"mode":"hang"} | {"map":{host:[ips]}} | {"gaierror":errno}
_MAX_WORKERS = 16                # max outstanding queries in flight at once
_KILL_GRACE = 0.5                # SIGTERM -> SIGKILL window for a stuck resolver worker
_WORKER_NAME = "netguard-resolver"
_DEFAULT_TIMEOUT = 5.0           # every query has a finite per-worker deadline

_RESOLUTION_LANE = "netguard.resolve"
_RESOLUTION_REMAINDER_SCHEMA = "quarry.resolver-remainder.v1"
_WORKER_CHANNEL_FAILURE = object()
_RESOLUTION_CAUSES = frozenset({
    "unreached", "indeterminate", "worker-invalid-result", "late",
    "worker-failure", "cancelled", "corpus-deadline", "query-timeout",
    "unsupported-corpus-size",
})
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class _FrozenIPs(tuple):
    """An immutable tuple with list-compatible equality for the legacy API."""

    def __eq__(self, other):
        if isinstance(other, (list, tuple)):
            return tuple(self) == tuple(other)
        return NotImplemented

    __hash__ = tuple.__hash__


def _freeze_resolution_value(value):
    """Copy one JSON-like remainder value into a deeply read-only shape."""
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("resolver remainder mappings require exact string keys")
        return MappingProxyType({
            key: _freeze_resolution_value(item) for key, item in value.items()
        })
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_resolution_value(item) for item in value)
    raise TypeError(
        f"resolver remainder detail cannot snapshot mutable {type(value).__name__}",
    )


def _thaw_resolution_value(value):
    """Return a detached record value; mutating it cannot alter the snapshot."""
    if isinstance(value, Mapping):
        return {key: _thaw_resolution_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_resolution_value(item) for item in value]
    return value


class ResolutionRemainder(NamedTuple):
    """Deep immutable value snapshot of a resolver's mutable ``Remainder``."""

    lane: str
    unit: str
    measure: str
    model: str
    now: int
    cooldown: int
    terminal: Mapping
    detail: Mapping

    @classmethod
    def snapshot(cls, remainder) -> "ResolutionRemainder":
        from .remainder import Remainder

        if type(remainder) is not Remainder:
            raise TypeError("resolution batch requires an exact Remainder value")
        remainder.validate()
        return cls(
            lane=remainder.lane,
            unit=remainder.unit,
            measure=remainder.measure,
            model=remainder.model,
            now=remainder.now,
            cooldown=remainder.cooldown,
            terminal=_freeze_resolution_value(remainder.terminal),
            detail=_freeze_resolution_value(remainder.detail),
        )

    @property
    def retriable(self) -> int:
        return (self.now + self.cooldown) if self.model == "project_progress" else 0

    def validate(self) -> None:
        """Retain the mutable value object's validation-compatible API."""
        from .remainder import Remainder

        Remainder(
            lane=self.lane,
            unit=self.unit,
            measure=self.measure,
            model=self.model,
            now=self.now,
            cooldown=self.cooldown,
            terminal=dict(self.terminal),
            detail=_thaw_resolution_value(self.detail),
        ).validate()

    def as_record(self) -> dict:
        from .remainder import TERMINAL_CAUSES

        return {
            "lane": self.lane,
            "unit": self.unit,
            "measure": self.measure,
            "model": self.model,
            "retriable": {"now": self.now, "cooldown": self.cooldown},
            "terminal": {
                cause: self.terminal.get(cause, 0) for cause in TERMINAL_CAUSES
            },
            "detail": _thaw_resolution_value(self.detail),
        }


class ResolutionBatch(Mapping):
    """A sealed result map plus truthful resolver work/resource accounting.

    This is deliberately a ``Mapping``, not a ``dict`` subtype: calling a base
    ``dict`` mutator cannot bypass its seal. Nested address collections and
    metrics are immutable too, so neither a late worker nor a caller can turn a
    timed-out/uncertified name into a clean result after the deadline.
    """

    __slots__ = ("_rows", "unresolved_hosts", "remainder", "metrics", "sealed", "_frozen")

    def __init__(self, rows, *, unresolved_hosts, remainder, metrics):
        normalized = {
            host: (_FrozenIPs(answer[0]), answer[1])
            for host, answer in dict(rows).items()
        }
        object.__setattr__(self, "_rows", MappingProxyType(normalized))
        object.__setattr__(self, "unresolved_hosts", tuple(unresolved_hosts))
        object.__setattr__(self, "remainder", ResolutionRemainder.snapshot(remainder))
        object.__setattr__(self, "metrics", MappingProxyType(dict(metrics)))
        object.__setattr__(self, "sealed", True)
        object.__setattr__(self, "_frozen", True)

    def __getitem__(self, key):
        return self._rows[key]

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

    def __setitem__(self, key, value):
        raise TypeError("a published resolution batch is sealed")

    def __delitem__(self, key):
        raise TypeError("a published resolution batch is sealed")

    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise TypeError("a published resolution batch is sealed")
        object.__setattr__(self, name, value)


def _valid_resolver_host(host) -> bool:
    """The closed ASCII DNS/IP grammar accepted for resolver work identity."""
    from . import resource_contract

    if type(host) is not str or not host or "\0" in host:
        return False
    try:
        encoded = host.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(encoded) > resource_contract.MAX_RESOLVER_HOST_BYTES:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    dns = host[:-1] if host.endswith(".") else host
    if not dns or len(dns.encode("ascii")) > 253:
        return False
    return all(_HOST_LABEL.fullmatch(label) is not None for label in dns.split("."))


class ResolverCorpusRefused(ValueError):
    """The caller supplied more hosts than the published finite batch envelope."""

    def __init__(self, message: str, batch: ResolutionBatch):
        super().__init__(message)
        self.resolution_batch = batch


def _resolver_remainder(unresolved, *, payload_digest: str | None,
                        terminal_cause: str | None = None,
                        terminal_count: int | None = None):
    from .remainder import Remainder

    count = len(unresolved) if terminal_count is None else terminal_count
    if (type(count) is not int or count < 0
            or (payload_digest is not None and count != len(unresolved))):
        raise ValueError("resolver remainder count does not match its exact payload")
    retained = payload_digest is not None
    detail = {
        "payload_retained": retained,
        "replayable": retained or count == 0,
        "payload_digest": payload_digest,
        "reason": ("the resolver obligation is known zero" if count == 0 else
                   "exact unresolved hosts are retained for replay" if retained else
                   "no durable resolver remainder payload was retained"),
    }
    terminal = {}
    now = count if retained else 0
    if count and not retained:
        terminal[terminal_cause or "machinery"] = count
    result = Remainder(
        lane=_RESOLUTION_LANE,
        unit=f"{_RESOLUTION_LANE}:hosts",
        measure="hosts",
        model="project_progress",
        now=now,
        terminal=terminal,
        detail=detail,
    )
    result.validate()
    return result


def _resolver_input_refusal(*, observed_lower_bound: int):
    """One terminal corpus obligation when an exact host tail is unknowable.

    The first ``MAX_RESOLVER_HOSTS + 1`` hosts are an exact payload only when
    the iterator then proves exhaustion. Seeing a further sentinel proves the
    accepted input is too large or unbounded, but does not prove its host count.
    Record one terminal *corpus*, not a fabricated exact host remainder.
    """
    from .remainder import LANE_MODEL, Remainder

    result = Remainder(
        lane=_RESOLUTION_LANE,
        unit=f"{_RESOLUTION_LANE}:corpus",
        measure="corpora",
        model=LANE_MODEL[_RESOLUTION_LANE],
        terminal={"unschedulable": 1},
        detail={
            "payload_retained": False,
            "replayable": False,
            "payload_digest": None,
            "reason": "input-too-large-or-unbounded",
            "exact_host_count": False,
            "observed_hosts_lower_bound": observed_lower_bound,
        },
    )
    result.validate()
    return result


def _persist_resolution_remainder(path, unresolved) -> str:
    """Persist the exact unresolved host/cause payload and return its sha256 identity."""
    from . import resource_contract

    if any(not _valid_resolver_host(host) or cause not in _RESOLUTION_CAUSES
           for host, cause in unresolved):
        raise ValueError("resolver remainder producer supplied an invalid work identity/cause")
    document = {
        "schema_version": _RESOLUTION_REMAINDER_SCHEMA,
        "lane": _RESOLUTION_LANE,
        "measure": "hosts",
        "count": len(unresolved),
        "work": [{"host": host, "cause": cause} for host, cause in unresolved],
    }
    body = resource_contract.canonical_bytes(document)
    if len(body) > resource_contract.MAX_RESOLVER_REMAINDER_BYTES:
        raise ValueError("resolver remainder exceeds its published byte envelope")
    resource_contract.atomic_private_write(path, body)
    return "sha256:" + hashlib.sha256(body).hexdigest()


def read_resolution_remainder(path) -> dict:
    """Read one exact resolver work record, rejecting damage rather than dropping hosts."""
    from . import resource_contract

    try:
        raw = resource_contract.read_private_file(
            path, maximum=resource_contract.MAX_RESOLVER_REMAINDER_BYTES,
        )
        if not raw.endswith(b"\n") or resource_contract.canonical_bytes(json.loads(raw)) != raw:
            raise ValueError("resolver remainder is not canonical JSON")
        document = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"resolver remainder is unreadable: {exc}") from exc
    if (not isinstance(document, dict)
            or set(document) != {"schema_version", "lane", "measure", "count", "work"}
            or document["schema_version"] != _RESOLUTION_REMAINDER_SCHEMA
            or document["lane"] != _RESOLUTION_LANE
            or document["measure"] != "hosts"
            or type(document["count"]) is not int or document["count"] < 0
            or document["count"] > resource_contract.MAX_RESOLVER_HOSTS + 1
            or not isinstance(document["work"], list)
            or document["count"] != len(document["work"])):
        raise ValueError("resolver remainder shape is invalid")
    seen = set()
    for index, item in enumerate(document["work"]):
        if (not isinstance(item, dict) or set(item) != {"host", "cause"}
                or not _valid_resolver_host(item["host"])
                or item["cause"] not in _RESOLUTION_CAUSES
                or item["host"] in seen):
            raise ValueError(f"resolver remainder work item {index} is invalid")
        seen.add(item["host"])
    return document


def _spawn_context():
    return _mp.get_context("forkserver") if threading.active_count() > 1 else _mp.get_context("fork")


def _do_resolve(host, stub) -> tuple[list[str], str]:
    """Per-host lookup + classification inside a worker: the injected stub, else real getaddrinfo."""
    if stub is not None:
        if stub.get("mode") == "hang":
            while True:
                time.sleep(1)
        if stub.get("mode") == "crash":
            os._exit(17)  # test/fault-injection worker: parent must reclaim and account for it
        if stub.get("mode") == "slow":        # answers after the deadline: the late reply must be discarded
            time.sleep(stub.get("delay", 2.0))
            return ["9.9.9.9"], "ok"
        gate = stub.get("gate")               # (counter, event): hold the worker in its slot to observe the cap
        if gate is not None:
            counter, event = gate
            with counter.get_lock():
                counter.value += 1
            event.wait()
            with counter.get_lock():
                counter.value -= 1
            return ["1.2.3.4"], "ok"
        if "gaierror" in stub:
            return [], ("nxdomain" if stub["gaierror"] in _NEG_ERRNOS else "indeterminate")
        if "all" in stub:                     # same answer for every host
            return (sorted(stub["all"]), "ok") if stub["all"] else ([], "nxdomain")
        states = stub.get("states")           # exact per-host (ips, state); a miss uses `miss` (default indeterminate)
        if states is not None:
            v = states.get(host)
            if v is not None:
                return list(v[0]), v[1]
            miss = stub.get("miss") or ([], "indeterminate")
            return list(miss[0]), miss[1]
        m = stub.get("map") or {}             # per-host ips (else `default`); presence => ok, absence => nxdomain
        ips = m.get(host, stub.get("default"))
        return (sorted(ips), "ok") if ips else ([], "nxdomain")
    try:
        ips = _getaddrinfo(host)
        return ips, ("ok" if ips else "nxdomain")
    except socket.gaierror as e:
        return [], ("nxdomain" if e.errno in _NEG_ERRNOS else "indeterminate")
    except Exception:
        return [], "indeterminate"


def _resolve_child(conn, host, stub) -> None:
    """Write one newline-delimited bounded result without a blocking frame reader.

    ``multiprocessing.Connection.recv`` blocks after seeing only a partial frame
    header/body. The parent instead drains this raw pipe in nonblocking mode and
    accepts a result only after the complete newline-delimited JSON payload is in
    memory before the corpus deadline.
    """
    try:
        answer = _do_resolve(host, stub)
    except Exception:
        answer = ([], "indeterminate")
    try:
        from . import resource_contract

        payload = json.dumps(
            {"ips": answer[0], "state": answer[1]},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii") + b"\n"
        if len(payload) > resource_contract.MAX_RESOLVER_RESULT_BYTES:
            payload = b'{}\n'
        view = memoryview(payload)
        while view:
            written = os.write(conn.fileno(), view)
            if written <= 0:
                break
            view = view[written:]
    except Exception:
        pass
    finally:
        conn.close()


def _drain_resolution_result(reader, buffer: bytearray):
    """Nonblockingly drain a raw worker pipe -> (complete, decoded result)."""
    from . import resource_contract

    eof = False
    while True:
        try:
            remaining = resource_contract.MAX_RESOLVER_RESULT_BYTES - len(buffer)
            chunk = os.read(reader.fileno(), min(64 * 1024, max(1, remaining + 1)))
        except BlockingIOError:
            break
        except InterruptedError:
            continue
        if not chunk:
            eof = True
            break
        buffer.extend(chunk)
        if len(buffer) > resource_contract.MAX_RESOLVER_RESULT_BYTES:
            return True, None
        if b"\n" in chunk:
            break
    newline = buffer.find(b"\n")
    if newline < 0:
        return (True, _WORKER_CHANNEL_FAILURE) if eof else (False, None)
    if newline != len(buffer) - 1:
        return True, None
    try:
        document = json.loads(bytes(buffer[:newline]))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True, None
    if not isinstance(document, dict) or set(document) != {"ips", "state"}:
        return True, None
    return True, (document["ips"], document["state"])


def _preferred_cleanup_fault(faults):
    return (next((fault for fault in faults if not isinstance(fault, Exception)), None)
            or (faults[0] if faults else None))


def _reclaim_all(processes) -> list[BaseException]:
    """Kill/reap every owned worker while deferring repeated cancellation.

    A KeyboardInterrupt/SystemExit at terminate, kill, is_alive or join is a
    primary result, not permission to orphan the rest of the process set.  Every
    operation is retried until the process is observed dead; collected faults are
    returned only after all children have been reaped.
    """
    owned = [proc for proc in processes if getattr(proc, "pid", None) is not None]
    faults: list[BaseException] = []

    def call(proc, name, *args):
        try:
            return getattr(proc, name)(*args)
        except BaseException as exc:
            faults.append(exc)
            return None

    grace = time.monotonic() + _KILL_GRACE
    pending = list(owned)
    while pending and time.monotonic() < grace:
        next_pending = []
        for proc in pending:
            alive = call(proc, "is_alive")
            if alive is False:
                call(proc, "join", 0)
                continue
            if alive is not False:
                call(proc, "terminate")
                call(proc, "join", min(0.02, max(0.0, grace - time.monotonic())))
            alive = call(proc, "is_alive")
            if alive is not False:
                next_pending.append(proc)
        pending = next_pending

    # One shared hard-kill phase. Cancellation is still deferred and retried;
    # os.kill is a fallback when a patched Process.kill repeatedly raises.
    hard_deadline = time.monotonic() + max(2.0, _KILL_GRACE * 4)
    while pending:
        next_pending = []
        for proc in pending:
            alive = call(proc, "is_alive")
            if alive is False:
                call(proc, "join", 0)
                continue
            call(proc, "kill")
            call(proc, "join", 0.02)
            alive = call(proc, "is_alive")
            if alive is not False:
                if time.monotonic() >= hard_deadline:
                    try:
                        os.kill(proc.pid, 9)
                    except ProcessLookupError:
                        pass
                    except BaseException as exc:
                        faults.append(exc)
                    call(proc, "join", 0.05)
                alive = call(proc, "is_alive")
                if alive is not False and time.monotonic() >= hard_deadline:
                    try:
                        if proc.exitcode is not None:
                            call(proc, "join", 0)
                            alive = False
                    except BaseException as exc:
                        faults.append(exc)
            if alive is not False:
                next_pending.append(proc)
        pending = next_pending
    return faults


def _reclaim(proc) -> list[BaseException]:
    return _reclaim_all([proc])


def active_worker_count() -> int:
    """Live resolver worker processes (by name) — the stuck-worker gate; back to baseline after every batch."""
    return sum(1 for c in _mp.active_children() if c.name == _WORKER_NAME)


def _resolve_batch(hosts, *, timeout: float, max_outstanding: int, budget_s: float = 30.0,
                   remainder_path=None) -> ResolutionBatch:
    """Resolve one corpus under a single deadline and a bounded worker/queue set.

    Every host starts as unresolved.  Only an on-time reply mutates that private map;
    workers are reclaimed together before a sealed ``ResolutionBatch`` is published.
    A supplied remainder path receives the exact unresolved host/cause payload.  If
    it is absent or unwritable the count is explicitly terminal machinery, never a
    fabricated replay queue.
    """
    if type(max_outstanding) is not int or not 1 <= max_outstanding <= _MAX_WORKERS:
        raise ValueError(f"max_outstanding must be an exact integer in 1..{_MAX_WORKERS}")
    if (isinstance(budget_s, bool) or not isinstance(budget_s, (int, float))
            or budget_s < 0 or not math.isfinite(budget_s)):
        raise ValueError("resolver corpus budget must be finite and non-negative")
    out: dict = {h: ([], "indeterminate") for h in hosts}
    causes: dict = {h: "unreached" for h in hosts}
    if not hosts:
        remainder = _resolver_remainder((), payload_digest=None)
        return ResolutionBatch(out, unresolved_hosts=(), remainder=remainder,
                               metrics={"input_hosts": 0, "attempted_hosts": 0,
                                        "resolved_hosts": 0, "unresolved_hosts": 0,
                                        "worker_processes": 0, "outstanding_queue": 0,
                                        "corpus_deadline_ms": 0, "elapsed_ms": 0,
                                        "deadline_expired": False})
    to = timeout if (type(timeout) in {int, float} and not isinstance(timeout, bool)
                     and timeout > 0) else _DEFAULT_TIMEOUT
    stub = _STUB                              # snapshot; passed to every worker as an arg
    ctx = _spawn_context()                    # fork (single-threaded) or forkserver (multithreaded)
    pending = deque(hosts)
    inflight: dict = {}                       # reader -> (proc, host, kill_at, bytes)
    owned: set = set()
    attempted = 0
    peak_workers = 0
    peak_outstanding = 0
    start = time.monotonic()
    stop_at = start + budget_s
    deadline_expired = False
    primary = None
    cleanup_faults: list[BaseException] = []
    try:
        while pending or inflight:
            now = time.monotonic()
            if stop_at is not None and now >= stop_at:
                deadline_expired = True
                break
            while (pending and len(inflight) < max_outstanding
                   and (stop_at is None or time.monotonic() < stop_at)):
                host = pending.popleft()
                reader = writer = proc = None
                try:
                    reader, writer = ctx.Pipe(False)
                    os.set_blocking(reader.fileno(), False)
                    proc = ctx.Process(
                        target=_resolve_child, args=(writer, host, stub),
                        daemon=True, name=_WORKER_NAME,
                    )
                    proc.start()              # a post-fork start failure remains owned and reclaimed
                    owned.add(proc)
                    attempted += 1
                    causes[host] = "inflight"
                    inflight[reader] = (
                        proc, host, time.monotonic() + to, bytearray(),
                    )
                    peak_workers = max(peak_workers, len(owned))
                    peak_outstanding = max(peak_outstanding, len(inflight))
                except BaseException as start_fault:
                    faults = _reclaim(proc) if proc is not None else []
                    for connection in (writer, reader):
                        if connection is None:
                            continue
                        try:
                            connection.close()
                        except BaseException as exc:
                            faults.append(exc)
                    if faults:
                        try:
                            start_fault.resolver_cleanup_errors = tuple(faults)
                        except BaseException:
                            pass
                    raise start_fault
                try:
                    writer.close()
                except BaseException as close_fault:
                    faults = _reclaim(proc)
                    owned.discard(proc)
                    inflight.pop(reader, None)
                    causes[host] = "cancelled"
                    try:
                        reader.close()
                    except BaseException as exc:
                        faults.append(exc)
                    if faults:
                        try:
                            close_fault.resolver_cleanup_errors = tuple(faults)
                        except BaseException:
                            pass
                    raise close_fault
            if not inflight:
                break
            wake_at = min(kill_at for _proc, _host, kill_at, _buffer in inflight.values())
            if stop_at is not None:
                wake_at = min(wake_at, stop_at)
            ready = _mpc.wait(list(inflight), timeout=max(0.0, wake_at - time.monotonic()))
            for reader in ready:
                proc, host, kill_at, buffer = inflight[reader]
                worker_primary = None
                try:
                    complete, answer = _drain_resolution_result(reader, buffer)
                    if not complete:
                        continue
                    inflight.pop(reader)
                    received_at = time.monotonic()
                    usable = (
                        isinstance(answer, tuple) and len(answer) == 2
                        and isinstance(answer[0], list)
                        and all(type(ip) is str and ip
                                and _norm(ip) is not None for ip in answer[0])
                        and answer[1] in {"ok", "nxdomain", "indeterminate"}
                    )
                    if (usable and received_at < kill_at
                            and (stop_at is None or received_at < stop_at)):
                        out[host] = (list(answer[0]), answer[1])
                        causes[host] = ("resolved" if answer[1] != "indeterminate"
                                        else "indeterminate")
                    elif answer is _WORKER_CHANNEL_FAILURE:
                        causes[host] = "worker-failure"
                    elif not usable:
                        causes[host] = "worker-invalid-result"
                    else:
                        causes[host] = "late"
                except Exception:
                    inflight.pop(reader, None)
                    causes[host] = "worker-failure"
                except BaseException as exc:
                    inflight.pop(reader, None)
                    worker_primary = exc
                local_faults = []
                try:
                    reader.close()
                except BaseException as exc:
                    local_faults.append(exc)
                local_faults.extend(_reclaim(proc))
                owned.discard(proc)
                if worker_primary is not None:
                    if local_faults:
                        try:
                            worker_primary.resolver_cleanup_errors = tuple(local_faults)
                        except BaseException:
                            pass
                    raise worker_primary
                cleanup_fault = _preferred_cleanup_fault(local_faults)
                if cleanup_fault is not None:
                    try:
                        cleanup_fault.resolver_cleanup_errors = tuple(local_faults)
                    except BaseException:
                        pass
                    raise cleanup_fault
            now = time.monotonic()
            if stop_at is not None and now >= stop_at:
                deadline_expired = True
                break
            for reader, (proc, host, kill_at, _buffer) in list(inflight.items()):
                if now >= kill_at:
                    inflight.pop(reader)
                    causes[host] = "query-timeout"
                    local_faults = []
                    try:
                        reader.close()
                    except BaseException as exc:
                        local_faults.append(exc)
                    local_faults.extend(_reclaim(proc))
                    owned.discard(proc)
                    cleanup_fault = _preferred_cleanup_fault(local_faults)
                    if cleanup_fault is not None:
                        try:
                            cleanup_fault.resolver_cleanup_errors = tuple(local_faults)
                        except BaseException:
                            pass
                        raise cleanup_fault
    except BaseException as exc:
        primary = exc
    finally:
        for reader, (_proc, host, _kill_at, _buffer) in list(inflight.items()):
            try:
                reader.close()
            except BaseException as exc:
                cleanup_faults.append(exc)
            if causes[host] == "inflight":
                causes[host] = "corpus-deadline" if deadline_expired else "cancelled"
        cleanup_faults.extend(_reclaim_all(owned))
        inflight.clear()
        owned.clear()
    cleanup_primary = _preferred_cleanup_fault(cleanup_faults)
    if primary is None:
        primary = cleanup_primary
    elif (isinstance(primary, Exception) and cleanup_primary is not None
          and not isinstance(cleanup_primary, Exception)):
        try:
            cleanup_primary.resolver_operation_error = primary
            cleanup_primary.resolver_cleanup_errors = tuple(cleanup_faults)
        except BaseException:
            pass
        primary = cleanup_primary
    elif cleanup_faults:
        try:
            primary.resolver_cleanup_errors = tuple(cleanup_faults)
        except BaseException:
            pass

    elapsed_ms = max(0, int(math.ceil((time.monotonic() - start) * 1000)))
    unresolved = [(host, causes[host]) for host, answer in out.items()
                  if answer[1] == "indeterminate"]
    payload_digest = None
    persistence_fault = None
    persistence_cancellation = None
    if unresolved and remainder_path is not None:
        try:
            payload_digest = _persist_resolution_remainder(remainder_path, unresolved)
        except BaseException as exc:
            committed = getattr(exc, "resource_publication_committed", False)
            committed_digest = getattr(exc, "resource_payload_digest", None)
            if committed and isinstance(committed_digest, str):
                payload_digest = committed_digest
            else:
                persistence_fault = f"{type(exc).__name__}: {exc}"
            if not isinstance(exc, Exception):
                persistence_cancellation = exc
    remainder = _resolver_remainder(unresolved, payload_digest=payload_digest)
    if persistence_fault:
        remainder.detail["persistence_fault"] = persistence_fault
    batch = ResolutionBatch(
        out,
        unresolved_hosts=[host for host, _cause in unresolved],
        remainder=remainder,
        metrics={
            "input_hosts": len(out),
            "attempted_hosts": attempted,
            "resolved_hosts": len(out) - len(unresolved),
            "unresolved_hosts": len(unresolved),
            "worker_processes": peak_workers,
            "outstanding_queue": peak_outstanding,
            "corpus_deadline_ms": int(budget_s * 1000) if budget_s > 0 else 0,
            "elapsed_ms": elapsed_ms,
            "deadline_expired": deadline_expired,
        },
    )
    if persistence_cancellation is not None:
        if primary is None or isinstance(primary, Exception):
            if primary is not None:
                try:
                    persistence_cancellation.resolver_operation_error = primary
                except BaseException:
                    pass
            primary = persistence_cancellation
        else:
            try:
                primary.resolver_persistence_errors = (persistence_cancellation,)
            except BaseException:
                pass
    if primary is not None:
        try:
            primary.resolution_batch = batch
        except BaseException:
            pass
        raise primary
    return batch


def resolve(host: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Bounded A+AAAA resolution -> (ips, state) in 'ok' / 'nxdomain' / 'indeterminate'. A hang is killed and
    reported indeterminate. No caching."""
    if not host:
        return [], "indeterminate"
    deadline = timeout if (type(timeout) in {int, float} and not isinstance(timeout, bool)
                           and timeout > 0 and math.isfinite(timeout)) else _DEFAULT_TIMEOUT
    ips, state = _resolve_batch(
        [host], timeout=deadline, max_outstanding=1, budget_s=deadline,
    )[host]
    return list(ips), state


def resolve_many(hosts, *, timeout: float = 5.0, corpus_deadline_s: float | None = None,
                 max_outstanding: int | None = None, remainder_path=None) -> ResolutionBatch:
    """Resolve one finite corpus with bounded processes, queue, deadline and remainder.

    ``corpus_deadline_s`` defaults to the published v0.3.x support deadline.
    Exact unresolved hosts are replayable only when ``remainder_path`` commits;
    otherwise the returned remainder classifies them as terminal machinery.
    """
    from . import resource_contract

    if isinstance(hosts, (str, bytes, bytearray)):
        raise TypeError("resolver corpus must be a finite sized collection of host strings")
    try:
        raw_count = len(hosts)
    except (TypeError, OverflowError) as exc:
        # An unsized iterator can be infinite or fail halfway through intake.
        # Refuse before accepting any work: otherwise neither a durable exact
        # remainder nor a truthful terminal count can be produced.
        raise TypeError(
            "resolver corpus must be a finite sized collection of host strings",
        ) from exc
    # Retain at most the exact overflow payload (MAX+1), then perform one more
    # bounded ``next``. Exhaustion makes the retained identity exact. A MAX+2
    # sentinel instead proves only a lower bound: the tail may be larger or
    # infinite, so it is terminal corpus input and never a replayable host list.
    retained_limit = resource_contract.MAX_RESOLVER_HOSTS + 1
    sentinel_limit = retained_limit + 1
    materialized = []
    iterator = iter(hosts)
    exhausted = False
    has_unretained_tail = False
    for index in range(sentinel_limit):
        try:
            host = next(iterator)
        except StopIteration:
            exhausted = True
            break
        if index == retained_limit:
            has_unretained_tail = True
            break
        if not _valid_resolver_host(host):
            raise ValueError(
                f"resolver corpus item {index} is not a host inside the published byte envelope/grammar",
            )
        materialized.append(host)
    if has_unretained_tail:
        remainder = _resolver_input_refusal(observed_lower_bound=sentinel_limit)
        batch = ResolutionBatch(
            {}, unresolved_hosts=(), remainder=remainder,
            metrics={"input_hosts": None, "input_count_exact": False,
                     "observed_input_hosts_lower_bound": sentinel_limit,
                     "attempted_hosts": 0, "resolved_hosts": 0,
                     "unresolved_hosts": None,
                     "worker_processes": 0, "outstanding_queue": 0,
                     "corpus_deadline_ms": 0, "elapsed_ms": 0,
                     "deadline_expired": False},
        )
        raise ResolverCorpusRefused(
            f"resolver corpus has at least {sentinel_limit} entries; supported maximum is "
            f"{resource_contract.MAX_RESOLVER_HOSTS}; input is too large or unbounded "
            "and no exact tail was accepted",
            batch,
        )
    if not exhausted:  # pragma: no cover - the loop exits only by exhaustion or sentinel
        raise AssertionError("bounded resolver intake has no terminal state")
    if raw_count != len(materialized):
        raise ValueError(
            "resolver corpus length contract is inconsistent with its bounded iteration",
        )
    uniq = []
    seen = set()
    for host in materialized:
        if host not in seen:
            seen.add(host)
            uniq.append(host)
    if not uniq:
        return _resolve_batch([], timeout=timeout, max_outstanding=1, budget_s=0,
                              remainder_path=remainder_path)
    if len(materialized) > resource_contract.MAX_RESOLVER_HOSTS:
        unresolved = [(host, "unsupported-corpus-size") for host in uniq]
        payload_digest = None
        persistence_cancellation = None
        if remainder_path is not None:
            try:
                payload_digest = _persist_resolution_remainder(remainder_path, unresolved)
            except BaseException as exc:
                committed = getattr(exc, "resource_publication_committed", False)
                committed_digest = getattr(exc, "resource_payload_digest", None)
                if committed and isinstance(committed_digest, str):
                    payload_digest = committed_digest
                if not isinstance(exc, Exception):
                    persistence_cancellation = exc
        remainder = _resolver_remainder(
            unresolved, payload_digest=payload_digest, terminal_cause="unschedulable",
        )
        batch = ResolutionBatch(
            {host: ([], "indeterminate") for host in uniq},
            unresolved_hosts=uniq, remainder=remainder,
            metrics={"input_hosts": len(uniq), "attempted_hosts": 0,
                     "resolved_hosts": 0, "unresolved_hosts": len(uniq),
                     "worker_processes": 0, "outstanding_queue": 0,
                     "corpus_deadline_ms": 0, "elapsed_ms": 0,
                     "deadline_expired": False},
        )
        if persistence_cancellation is not None:
            try:
                persistence_cancellation.resolution_batch = batch
            except BaseException:
                pass
            raise persistence_cancellation
        raise ResolverCorpusRefused(
            f"resolver corpus has {len(uniq)} hosts; supported maximum is "
            f"{resource_contract.MAX_RESOLVER_HOSTS}", batch,
        )
    deadline = (resource_contract.MAX_RESOLVER_CORPUS_DEADLINE_SECONDS
                if corpus_deadline_s is None else corpus_deadline_s)
    workers = min(_MAX_WORKERS, len(uniq)) if max_outstanding is None else max_outstanding
    return _resolve_batch(
        uniq, timeout=timeout, max_outstanding=workers, budget_s=deadline,
        remainder_path=remainder_path,
    )


def contact_state(host, stored_ips=None, *, block_private=False, timeout=5.0):
    """(state, deny_ips, intel) for a native fetch (scoped_get). state is 'contact' | 'self' |
    'private_blocked' | 'nxdomain' | 'indeterminate'; deny_ips says why contact was refused; intel is the
    answers worth recording. Stored non-contactable answers decide without a live lookup, but a host that
    fails to resolve live is never authorized by stored data."""
    stored = [ip for ip in (stored_ips or []) if ip]
    ips, state = (stored, "ok") if stored else resolve(host, timeout=timeout)
    if not stored and state != "ok":
        return state, [], []
    all_ips = set(ips) | set(stored)
    intel = intel_ips(all_ips)
    if any(is_self_attack_ip(ip) for ip in all_ips):
        return "self", [ip for ip in all_ips if is_self_attack_ip(ip)], intel
    if block_private and any(is_private_ip(ip) for ip in all_ips):
        return "private_blocked", [ip for ip in all_ips if is_private_ip(ip)], intel
    return "contact", [], intel


def _block_private(ctx) -> bool:
    return bool(getattr(getattr(ctx, "profile", None), "block_private_targets", False))


def _stored_map(ctx, hosts) -> dict[str, list[str]]:
    want = set(hosts)
    out: dict[str, set] = {}
    for r in ctx.run.read("resolved"):
        h = r.get("host")
        if h in want:
            out.setdefault(h, set()).update(r.get("a") or [])
            out.setdefault(h, set()).update(r.get("aaaa") or [])
    for d in ctx.run.read("dns_record"):
        if d.get("host") in want and d.get("type") in ("a", "aaaa") and d.get("value"):
            out.setdefault(d["host"], set()).add(d["value"])
    return {h: sorted(v) for h, v in out.items()}


def record_internal(ctx, host, ips):
    """Record an internal-resolving host as a review finding, independent of the contact decision."""
    ctx.run.add("review", {"id": f"internal-resolution:{host}", "klass": "internal-resolution",
                "value": host, "host": host, "ips": list(ips),
                "note": f"{host} resolves to internal/private IP(s) {', '.join(ips)} — internal-exposure lead "
                        "(DNS record = intel; reachable service is tested unless it's a scan-box/metadata hit)",
                "sources": ["netguard"]})


def guard_hosts(ctx, hosts, *, phase: str = "", record: bool = True, allow_dangling: bool = False) -> list[str]:
    """Filter a tool's target hosts. Every host is fresh-resolved in one bounded batch, so the contact
    decision uses the current answer; intel is the union of stored and current answers. Records every host
    with a private or self answer, withholds one whose current answer is a scan-box/metadata destination
    (or private space under block_private_targets), drops an authoritative nxdomain unless `allow_dangling`
    (takeover's signal), and passes an indeterminate host through."""
    block_private = _block_private(ctx)
    smap = _stored_map(ctx, hosts)
    uniq = [h for h in dict.fromkeys(hosts) if h]
    live = resolve_many(uniq)
    safe, recorded, withheld = [], 0, 0
    for h in uniq:
        cur_ips, state = live.get(h, ([], "indeterminate"))
        intel = intel_ips(set(cur_ips) | set(smap.get(h, [])))
        if intel and record:
            record_internal(ctx, h, intel)
            recorded += 1
        if state == "ok":
            if any(not is_contactable_ip(ip, block_private=block_private) for ip in cur_ips):
                withheld += 1
                continue
            safe.append(h)
        elif state == "nxdomain":
            if allow_dangling:                           # kept only for takeover's signal
                safe.append(h)
        else:                                            # indeterminate
            safe.append(h)
    if record and (recorded or withheld):
        ctx.run.notes.append(f"{phase}: netguard recorded {recorded} internal-resolution lead(s); "
                             f"withheld {withheld} scan-box/metadata (or blocked-private) host(s) from contact")
    return safe


def guard_urls(ctx, urls, *, phase: str = "", record: bool = True) -> list[str]:
    from . import normalize
    by_host: dict[str, list[str]] = {}
    for u in urls:
        by_host.setdefault(normalize.host_of_url(u), []).append(u)
    safe = set(guard_hosts(ctx, [h for h in by_host if h], phase=phase, record=record))
    return [u for h, us in by_host.items() for u in us if h in safe]
