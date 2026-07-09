"""Phase: Origin-IP correlation (A2) — de-fronting candidates for CDN/WAF-fronted hosts.

A CDN/WAF in front of a host hides its true origin IP. The origin (if reachable directly) is where
the app actually runs — no WAF in the way — so it is the real attack surface for the later attack
layer. This phase does NOT bypass anything and sends NO packets: it CORRELATES evidence already
collected (httpx `-cdn`/`-favicon`, tlsx certs) to PROPOSE candidate origin IPs, emitted as `review`
items tagged verify-ownership. Two channels:

  - favicon-hash twin: a non-CDN live host serving the SAME favicon hash as a CDN-fronted host is very
    likely the same application on its origin IP — the CDN just fronts it. (Range-validatable.)
  - cert twin / SAN: a non-CDN host presenting the SAME TLS cert (sha1) as the CDN host, or a host
    named in the CDN host's cert SANs that we already see direct, is a candidate origin. (Real-world;
    a CDN usually terminates TLS with its OWN cert, so the sha1 twin mostly fires off-CDN.)

Map-only (design §3): candidates are review items — NEVER added to scope or any scan target. A CDN
anycast IP must never be port-scanned, and an unconfirmed origin is a lead, not a target. Naabu stays
CIDR-gated to human scope; this phase feeds nothing into it.
"""
from __future__ import annotations

from ..runner import skipped


def _emit(ctx, cdn_host: str, ip: str, channel: str, matched_host: str, sources) -> bool:
    # matched_host = the non-CDN host that produced this IP (the grey twin / SAN host) — the
    # evidence trail a human needs to verify the lead by hand. Map-only: still just a review item.
    return ctx.run.add("review", {
        "id": f"origin-ip:{cdn_host}->{ip}:{channel}",
        "klass": "origin-ip", "value": f"{cdn_host} -> {ip} (matches {matched_host})",
        "host": cdn_host, "origin_ip": ip, "channel": channel, "matched_host": matched_host,
        "note": f"candidate origin IP for CDN-fronted {cdn_host} (via {channel}, matches non-CDN "
                f"{matched_host}) — verify ownership before use",
        "sources": sources or ["origin-correlation"]})


def run(ctx) -> None:
    if ctx.scope.passive_only:
        ctx.run.record("origin", skipped("origin", "passive-only mode"))
        return
    live = ctx.run.read("live")
    cdn_hosts = [l for l in live if l.get("cdn")]
    if not cdn_hosts:
        ctx.run.record("origin", skipped("origin", "no CDN-fronted hosts — nothing to de-front"))
        return

    # non-CDN live hosts with real IPs = potential origins ("grey twins")
    origins = [l for l in live if not l.get("cdn") and l.get("a")]
    live_ips = {l.get("host"): (l.get("a") or []) for l in origins}

    # favicon channel: favicon-hash -> [(host, ips)]
    fav_map: dict = {}
    for l in origins:
        f = l.get("favicon")
        if f not in (None, ""):
            fav_map.setdefault(str(f), []).append((l.get("host"), l.get("a") or []))

    # cert channel: sha1 -> [(non-CDN host, ips)], joined cert-store -> live IPs; + per-host cert lookup
    certs = ctx.run.read("certificate")
    sha1_map: dict = {}
    cert_by_host: dict = {}
    for c in certs:
        h = c.get("host")
        cert_by_host.setdefault(h, c)
        if c.get("sha1") and h in live_ips:
            sha1_map.setdefault(c["sha1"], []).append((h, live_ips[h]))

    found = 0
    seen: set = set()

    def _add(cdn_host, matched_host, ips, channel, sources):
        nonlocal found
        for ip in ips:
            key = (cdn_host, ip, channel)
            if key in seen:
                continue
            seen.add(key)
            if _emit(ctx, cdn_host, ip, channel, matched_host, sources):
                found += 1

    for cdn in cdn_hosts:
        ch = cdn.get("host")
        src = cdn.get("sources")

        # favicon twin — a non-CDN host with the identical favicon hash
        f = cdn.get("favicon")
        if f not in (None, ""):
            for oh, ips in fav_map.get(str(f), []):
                if oh != ch:
                    _add(ch, oh, ips, "favicon", src)

        cc = cert_by_host.get(ch)
        if cc:
            # cert twin — same TLS cert (sha1) served on a non-CDN host
            if cc.get("sha1"):
                for oh, ips in sha1_map.get(cc["sha1"], []):
                    if oh != ch:
                        _add(ch, oh, ips, "cert-sha1", src)
            # cert SAN names a host we already see direct (non-CDN)
            for san in (cc.get("san") or []):
                if san != ch and san in live_ips:
                    _add(ch, san, live_ips[san], "cert-san", src)

    ctx.echo(f"  origin: {len(cdn_hosts)} CDN-fronted host(s); "
             f"+{found} candidate origin IP(s) (verify-ownership, map-only)")
