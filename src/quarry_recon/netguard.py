"""Self-attack guard — CONTACT-BY-DEFAULT (Lumpy 2026-07-17). Quarry is an OFFENSIVE recon tool: a public
name resolving to a private IP is a LEAD, not the end of the investigation. So this module does TWO
INDEPENDENT things and never lets one depend on the other:

  1. RECORD (always): any resolved host whose answers include a private/self address is stored as a
     review(internal-resolution) finding — the DNS record IS intel. This happens whether or not we contact.

  2. DENY CONTACT (narrow): the ONLY destinations we refuse to contact are the ones that attack the SCAN BOX
     itself and are never the target — loopback, link-local, cloud METADATA endpoints (AWS v4/v6, Alibaba,
     GCP/Azure via 169.254.169.254), the unspecified address, and the scan box's OWN interface IPs. Reaching
     these leaks Quarry's own credentials / hits its own services.

Private space (RFC1918 / CGNAT / ULA) is CONTACTED BY DEFAULT — from an internal engagement it IS the target,
and even externally the right move is to reach the service and let evidence (Host/SNI, cert, fingerprint)
decide ownership. An operator who wants the conservative VPS-external posture sets MODES.BLOCK_PRIVATE_TARGETS.

Resolution used here is bounded (a daemon thread joined with a timeout) and never cached (the OS resolver
caches per real DNS TTL). guard_hosts/guard_urls FRESH-resolve every outbound host right at the tool boundary
and decide on the CURRENT answer. A transient-unresolvable host is passed through, not suppressed; for httpx
we ALSO pass self_deny_list() as its own `-deny` (a real connect-time IP deny). nuclei/dalfox/arjun have NO
connect-time IP deny, so a host that REBINDS public->metadata in the gap between our resolve and the tool's
is an inherent (exotic) residual — the fresh pre-resolve is the guard.
"""
from __future__ import annotations

import ipaddress
import socket
import threading

_NEG_ERRNOS = {getattr(socket, n) for n in ("EAI_NONAME", "EAI_NODATA")
               if getattr(socket, n, None) is not None}

# Loopback / link-local / unspecified — reaching these is always the scan box, never a target.
_SELF_NETS = tuple(ipaddress.ip_network(c) for c in
                   ("127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "0.0.0.0/32", "::1/128", "::/128"))
# Cloud instance-metadata endpoints (own credentials): AWS v4/link-local + ECS, AWS IPv6 IMDS, Alibaba.
_METADATA_NETS = tuple(ipaddress.ip_network(c) for c in
                       ("169.254.169.254/32", "169.254.170.2/32", "100.100.100.200/32", "fd00:ec2::254/128"))
# Contacted BY DEFAULT — only blocked when MODES.BLOCK_PRIVATE_TARGETS. Also the RECORD-as-intel trigger.
_PRIVATE_NETS = tuple(ipaddress.ip_network(c) for c in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))


def _own_ips() -> frozenset[str]:
    """The scan box's own interface addresses — reaching them is a self-hit. Best-effort, computed once."""
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
    """Parse; unwrap an IPv4-mapped IPv6 (::ffff:127.0.0.1 -> 127.0.0.1) so a mapped self/metadata address
    can't slip past the CIDR checks. None if unparseable."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def is_self_attack_ip(ip: str) -> bool:
    """True for a destination that attacks the SCAN BOX itself (loopback/link-local/metadata/own iface).
    ALWAYS denied contact — no mode makes these contactable. Unparseable -> True (fail closed on contact)."""
    a = _norm(ip)
    if a is None:
        return True
    if ip in _OWN_IPS or str(a) in _OWN_IPS:
        return True
    return any(a in n for n in _SELF_NETS) or any(a in n for n in _METADATA_NETS)


def is_private_ip(ip: str) -> bool:
    """True for RFC1918 / CGNAT / ULA (contacted by default; blocked only under BLOCK_PRIVATE_TARGETS)."""
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
    """The subset worth RECORDING as internal-resolution intel: private OR self/metadata (i.e. any
    non-public answer). Independent of the contact decision."""
    return sorted({ip for ip in ips if ip and (is_self_attack_ip(ip) or is_private_ip(ip))})


def _mapped_cidr(net) -> str:
    """The IPv4-mapped IPv6 form of a v4 network: 100.100.100.200/32 -> ::ffff:100.100.100.200/128."""
    return f"::ffff:{net.network_address}/{96 + net.prefixlen}"


def self_deny_list() -> str:
    """Comma-joined CIDR deny list of SELF/METADATA/own-iface ranges + the IPv4-MAPPED form of EVERY v4 range
    (so a tool whose deny parser doesn't normalize ::ffff:… still refuses it — full parity with
    is_self_attack_ip's _norm() unwrap). SELF-only: private space is deliberately NOT here (it's contacted)."""
    nets = _SELF_NETS + _METADATA_NETS
    parts = {str(n) for n in nets}
    parts |= {_mapped_cidr(n) for n in nets if n.version == 4}          # mapped forms (incl Alibaba metadata)
    for ip in _OWN_IPS:
        if ":" in ip:
            parts.add(f"{ip}/128")
        else:
            parts.add(f"{ip}/32")
            parts.add(f"::ffff:{ip}/128")                              # mapped own IPv4
    return ",".join(sorted(parts))


def _getaddrinfo(host: str) -> list[str]:
    return sorted({i[4][0] for i in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def resolve(host: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Bounded A+AAAA resolution -> (ips, state): 'ok' / 'nxdomain' / 'indeterminate'. Daemon-thread join;
    a hang is abandoned + reported 'indeterminate'. No caching."""
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
    """Resolve many hosts with BOUNDED concurrency -> {host: (ips, state)}. Daemon workers (never block
    shutdown); simple fixed cap (no elaborate deadline). A host not finished is ('indeterminate')."""
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
    """(state, deny_ips, intel) for a NATIVE fetch (scoped_get). state: 'contact' | 'self' (self-attack,
    never) | 'private_blocked' | 'nxdomain' | 'indeterminate'. deny_ips = why not contacted; intel = ips
    worth recording. Stored non-contactable answers decide without a live lookup; a live-failed host is
    never authorized by stored data (returns nxdomain/indeterminate)."""
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
    """RECORD an internal-resolving host as a finding (unconditional — never depends on whether we contact
    it). The DNS record is the lead; Quarry may still test the reachable service to validate ownership."""
    ctx.run.add("review", {"id": f"internal-resolution:{host}", "klass": "internal-resolution",
                "value": host, "host": host, "ips": list(ips),
                "note": f"{host} resolves to internal/private IP(s) {', '.join(ips)} — internal-exposure lead "
                        "(DNS record = intel; reachable service is tested unless it's a scan-box/metadata hit)",
                "sources": ["netguard"]})


def guard_hosts(ctx, hosts, *, phase: str = "", record: bool = True, allow_dangling: bool = False) -> list[str]:
    """Filter a tool's target hosts, CONTACT-BY-DEFAULT. Every host is FRESH-resolved in one bounded batch
    (stored DNS can be stale — a host stored public may point to metadata NOW), so the CONTACT decision uses
    the CURRENT answer; intel is the UNION of stored + current. RECORDS every host with a private/self answer
    as intel (independent of whether we contact it). WITHHOLDS a host whose CURRENT answer is a self-attack
    destination (loopback/metadata/own-iface), or private space under BLOCK_PRIVATE_TARGETS. An authoritative
    NXDOMAIN is dropped UNLESS `allow_dangling` (takeover's signal — meaningful, not a no-op); a transient
    'indeterminate' host is passed through (not suppressed)."""
    block_private = _block_private(ctx)
    smap = _stored_map(ctx, hosts)
    uniq = [h for h in dict.fromkeys(hosts) if h]
    # FRESH-resolve EVERY host at the tool boundary (audit): stored DNS can be stale / incomplete (a host
    # stored public may resolve to metadata NOW), so the CONTACT decision uses the CURRENT answer. Intel is
    # the UNION of stored + current (record a private/self address seen in either). Bounded parallel batch.
    live = resolve_many(uniq)
    safe, recorded, withheld = [], 0, 0
    for h in uniq:
        cur_ips, state = live.get(h, ([], "indeterminate"))
        intel = intel_ips(set(cur_ips) | set(smap.get(h, [])))
        if intel and record:
            record_internal(ctx, h, intel)               # record the lead whether or not we contact it
            recorded += 1
        if state == "ok":
            if any(not is_contactable_ip(ip, block_private=block_private) for ip in cur_ips):
                withheld += 1                            # CURRENT answer is self-attack / blocked-private
                continue
            safe.append(h)
        elif state == "nxdomain":
            if allow_dangling:                           # authoritative-dead: kept ONLY for takeover's signal
                safe.append(h)
        else:                                            # indeterminate (transient) -> pass through, do not suppress
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
