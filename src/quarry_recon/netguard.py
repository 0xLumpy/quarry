"""Self-attack guard. `record`: a host resolving private/self is a review(internal-resolution) finding.
`deny`: contact refused only for the scan box itself (loopback, link-local, cloud metadata, unspecified,
own-interface addrs); private space is contacted unless block_private_targets. Hosts fresh-resolve at the
tool boundary (bounded, uncached); a public->metadata rebind between resolve and tool is a residual risk."""
from __future__ import annotations

import ipaddress
import multiprocessing as _mp
import socket
import threading
import time
from multiprocessing import connection as _mpc

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


def _spawn_context():
    return _mp.get_context("forkserver") if threading.active_count() > 1 else _mp.get_context("fork")


def _do_resolve(host, stub) -> tuple[list[str], str]:
    """Per-host lookup + classification inside a worker: the injected stub, else real getaddrinfo."""
    if stub is not None:
        if stub.get("mode") == "hang":
            while True:
                time.sleep(1)
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
    try:
        conn.send(_do_resolve(host, stub))
    except Exception:
        conn.send(([], "indeterminate"))
    finally:
        conn.close()


def _reclaim(proc) -> None:
    if getattr(proc, "pid", None) is None:
        return                                # never started (start raised before fork) — nothing to reclaim
    if proc.is_alive():
        proc.terminate()
        proc.join(_KILL_GRACE)
    if proc.is_alive():
        proc.kill()
    proc.join()


def active_worker_count() -> int:
    """Live resolver worker processes (by name) — the stuck-worker gate; back to baseline after every batch."""
    return sum(1 for c in _mp.active_children() if c.name == _WORKER_NAME)


def _resolve_batch(hosts, *, timeout: float, max_outstanding: int, budget_s: float = 0.0) -> dict:
    """Resolve `hosts` in <= `max_outstanding` killable workers; a query killed at `timeout` or unreached by a
    positive `budget_s` stays ([], 'indeterminate')."""
    out: dict = {h: ([], "indeterminate") for h in hosts}
    if not hosts:
        return out
    to = timeout if isinstance(timeout, (int, float)) and timeout > 0 else _DEFAULT_TIMEOUT
    stub = _STUB                              # snapshot the injected resolver; passed to every worker as an arg
    ctx = _spawn_context()                    # fork (single-threaded) or forkserver (multithreaded)
    pending = list(hosts)
    inflight: dict = {}                       # recv-conn -> (proc, host, kill_at)
    stop_at = time.monotonic() + budget_s if budget_s > 0 else None
    try:
        while pending or inflight:
            while pending and len(inflight) < max_outstanding and (stop_at is None or time.monotonic() < stop_at):
                h = pending.pop(0)
                r, w = ctx.Pipe(False)
                proc = ctx.Process(target=_resolve_child, args=(w, h, stub), daemon=True, name=_WORKER_NAME)
                try:
                    proc.start()              # inside the guard: a start() that forks then raises is reclaimed
                    inflight[r] = (proc, h, time.monotonic() + to)    # finite deadline; never None
                except BaseException:
                    _reclaim(proc)
                    raise
                w.close()
            if not inflight:
                break                         # budget spent; unreached hosts keep the indeterminate default
            wait_s = max(0.0, min(k for _, _, k in inflight.values()) - time.monotonic())
            for r in _mpc.wait(list(inflight), timeout=wait_s):
                proc, h, kill_at = inflight.pop(r)
                try:
                    ans = r.recv()
                    out[h] = ans if time.monotonic() < kill_at else ([], "indeterminate")   # discard a late answer
                except Exception:
                    out[h] = ([], "indeterminate")
                finally:
                    r.close()
                    _reclaim(proc)            # always reclaim, even if recv raised — never orphan a worker
            now = time.monotonic()
            for r, (proc, h, kill_at) in list(inflight.items()):
                if now >= kill_at:
                    inflight.pop(r)
                    r.close()                 # discard any answer the killed worker is mid-write
                    _reclaim(proc)
        return out
    finally:
        for r, (proc, _h, _k) in inflight.items():
            r.close()
            _reclaim(proc)


def resolve(host: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Bounded A+AAAA resolution -> (ips, state) in 'ok' / 'nxdomain' / 'indeterminate'. A hang is killed and
    reported indeterminate. No caching."""
    if not host:
        return [], "indeterminate"
    return _resolve_batch([host], timeout=timeout, max_outstanding=1)[host]


def resolve_many(hosts, *, timeout: float = 5.0) -> dict:
    """Resolve many hosts with bounded outstanding workers -> {host: (ips, state)}. A worker that does not
    finish is killed and reclaimed, so a large failing corpus leaves no live worker."""
    uniq = [h for h in dict.fromkeys(hosts) if h]
    if not uniq:
        return {}
    return _resolve_batch(uniq, timeout=timeout, max_outstanding=min(_MAX_WORKERS, len(uniq)))


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
