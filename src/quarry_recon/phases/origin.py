"""Origin-IP correlation (A2): propose candidate origin IPs for CDN/WAF-fronted hosts. Sends no
packets — correlates already-collected evidence (httpx `-cdn`/`-favicon`, tlsx certs) into `review`
items tagged verify-ownership. Map-only: candidates are never added to scope or any scan target.

Two channels:
  - favicon twin: a CDN-detector-negative live host serving the same favicon hash as a CDN-fronted host.
  - cert twin / SAN: a detector-negative host presenting the same TLS cert (sha1) as the CDN host, or a host
    named in the CDN host's cert SANs that we already see direct.

A CDN usually terminates TLS with its own cert, so the cert-sha1 twin mostly fires off-CDN; the
favicon-hash twin is the range-validatable channel.
"""
from __future__ import annotations

from .. import events, normalize
from ..runner import skipped


def _emit(ctx, cdn_host: str, ip: str, channel: str, matched_host: str, sources) -> bool:
    # matched_host = the detector-negative host that produced this IP — evidence for manual verification.
    return ctx.run.add("review", {
        "id": f"origin-ip:{cdn_host}->{ip}:{channel}",
        "klass": "origin-ip", "value": f"{cdn_host} -> {ip} (matches {matched_host})",
        "host": cdn_host, "origin_ip": ip, "channel": channel, "matched_host": matched_host,
        "note": f"candidate origin IP for CDN-fronted {cdn_host} (via {channel}, matches "
                f"CDN-detector-negative "
                f"{matched_host}) — verify ownership before use",
        "sources": sources or ["origin-correlation"]})


def run(ctx) -> None:
    if ctx.scope.passive_only:
        ctx.run.record("origin", skipped("origin", "passive-only mode"))
        return
    live = ctx.run.read("live")
    cdn_hosts = [l for l in live if normalize.cdn_state(l) == "detected"]
    unknown = [l for l in live if normalize.cdn_state(l) == "unknown"]
    if unknown:
        events.coverage_partial(
            "origin.correlation", kind=events.COVERAGE_UNKNOWN, measure="cdn_classification",
            unit="cdn_classification",
            reason=f"{len(unknown)} live service(s) have unknown CDN classification; no origin inference",
        )
    if not cdn_hosts:
        ctx.run.record("origin", skipped("origin", "no CDN-fronted hosts — nothing to de-front"))
        return

    # Detector-negative live hosts with real IPs are only correlation candidates ("grey twins").
    origins = [l for l in live if normalize.cdn_state(l) == "not_detected" and l.get("a")]
    live_ips = {l.get("host"): (l.get("a") or []) for l in origins}

    # favicon channel: favicon-hash -> [(host, ips)]
    fav_map: dict = {}
    for l in origins:
        f = l.get("favicon")
        if f not in (None, ""):
            fav_map.setdefault(str(f), []).append((l.get("host"), l.get("a") or []))

    # cert channel: sha1 -> [(detector-negative host, ips)], joined cert-store -> live IPs
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

        # favicon twin — a detector-negative host with the identical favicon hash
        f = cdn.get("favicon")
        if f not in (None, ""):
            for oh, ips in fav_map.get(str(f), []):
                if oh != ch:
                    _add(ch, oh, ips, "favicon", src)

        cc = cert_by_host.get(ch)
        if cc:
            # cert twin — same TLS cert (sha1) served on a detector-negative host
            if cc.get("sha1"):
                for oh, ips in sha1_map.get(cc["sha1"], []):
                    if oh != ch:
                        _add(ch, oh, ips, "cert-sha1", src)
            # cert SAN names a host the CDN detector marked negative
            for san in (cc.get("san") or []):
                if san != ch and san in live_ips:
                    _add(ch, san, live_ips[san], "cert-san", src)

    ctx.echo(f"  origin: {len(cdn_hosts)} CDN-fronted host(s); "
             f"+{found} candidate origin IP(s) (verify-ownership, map-only)")
