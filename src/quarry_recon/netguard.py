"""Self-attack guard. Contact is the default, and the guard does two independent things:

  record   a resolved host whose answers include a private or self address becomes a
           review(internal-resolution) finding, whether or not we go on to contact it;
  deny     contact is refused only for destinations that are the scan box itself — loopback,
           link-local, cloud metadata endpoints, the unspecified address, own interface addresses.

Private space (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) is contacted unless the profile sets
block_private_targets. guard_hosts/guard_urls fresh-resolve every outbound host at the tool boundary and
decide on the current answer; resolution is bounded and never cached, and a host that fails to resolve is
passed through rather than suppressed. httpx additionally receives self_deny_list() as its own `-deny`;
nuclei/dalfox/arjun have no connect-time IP deny, so a host that rebinds public -> metadata between our
resolve and the tool's is a residual risk.
"""
from __future__ import annotations

import ipaddress
import socket
import threading

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


def resolve(host: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Bounded A+AAAA resolution -> (ips, state), state one of 'ok' / 'nxdomain' / 'indeterminate'.
    A hang is abandoned and reported indeterminate. No caching."""
    if not host:
        return [], "indeterminate"
    box: dict = {}

    def _work():
        try:
            box["ips"] = _getaddrinfo(host)
        except socket.gaierror as e:
            box["errno"] = e.errno
        except Exception:
            box["errno"] = None

    t = threading.Thread(target=_work, name=f"netguard-dns-{host[:32]}", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return [], "indeterminate"
    if "ips" in box:
        return box["ips"], ("ok" if box["ips"] else "nxdomain")
    return [], ("nxdomain" if box.get("errno") in _NEG_ERRNOS else "indeterminate")


_MAX_WORKERS = 16


def resolve_many(hosts, *, timeout: float = 5.0) -> dict:
    """Resolve many hosts with bounded concurrency -> {host: (ips, state)}. Workers are daemons, so they
    never block shutdown; a host that did not finish stays ([], 'indeterminate')."""
    import queue
    uniq = [h for h in dict.fromkeys(hosts) if h]
    out: dict = {h: ([], "indeterminate") for h in uniq}
    if not uniq:
        return out
    q: queue.Queue = queue.Queue()
    for h in uniq:
        q.put(h)

    def _worker():
        while True:
            try:
                h = q.get_nowait()
            except queue.Empty:
                return
            out[h] = resolve(h, timeout=timeout)

    workers = [threading.Thread(target=_worker, name="netguard-dns-batch", daemon=True)
               for _ in range(min(_MAX_WORKERS, len(uniq)))]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout * 2 + 5)
    return out


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
