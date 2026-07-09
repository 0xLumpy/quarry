"""Phase 2: Horizontal discovery.

Surfaces MORE in-scope hostnames on owned IP space + cert data. We do NOT pivot to
new apex roots automatically (scope stays fixed); ASN findings are recorded as
candidates for human review (design Q7). Methodology: ASN->cert chain,
kaeferjaeger SNI dataset, tlsx SAN harvest, reverse DNS.
"""
from __future__ import annotations

import urllib.request

from .. import normalize
from ..runner import Status, have, run as exec_tool, skipped


# Per-provider download cap. The kaeferjaeger SNI files are hundreds of MB each (~885 MB for amazon) —
# reading one in full (r.read()) pulled the whole thing into RAM before truncation, a latent OOM. Cap the
# READ at the source so RAM is bounded regardless of file size.
#   NOTE the cap means we only see the FIRST 5 MB of an IP-sorted 885 MB file — a tiny, non-representative
#   slice, so kaeferjaeger's practical name coverage here is low. Full coverage would need streaming the
#   whole ~4 GB (5 providers) and grepping line-by-line — heavy for a name channel that overlaps
#   subfinder + CT. Kept as bounded best-effort; the reconftw diff decides if it earns its keep.
# 403 FIX (2026-07-09): the earlier "403s the VPS egress" read was WRONG — kaeferjaeger.gay anti-bots the
# default `Python-urllib` User-Agent (verified: browser UA → 200, urllib UA → 403). Send a browser UA.
_KJ_CAP = 5_000_000
_KJ_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _kaeferjaeger(ctx) -> tuple[int, int]:
    """Passive: grep cloud-provider SNI cert dataset for in-scope hosts. Bounded read (see _KJ_CAP).
    Returns (added, blocked) — per-provider errors go QUIETLY to run notes (manifest/run.log), never
    the console: kaeferjaeger.gay 403s some VPS egress on every provider, and 5 error lines + a `+0`
    per run is pure noise. The caller emits at most ONE concise line."""
    added = 0
    raw_all = []
    blocked = 0
    for prov in ("amazon", "google", "microsoft", "oracle", "digitalocean"):
        url = f"https://kaeferjaeger.gay/sni-ip-ranges/{prov}/ipv4_merged_sni.txt"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _KJ_UA})   # urllib UA is 403'd (anti-bot)
            with urllib.request.urlopen(req, timeout=120) as r:
                raw_all.append(r.read(_KJ_CAP).decode("utf-8", "replace"))   # bounded — never the full file
        except Exception as e:  # network optional — quiet, it's best-effort
            blocked += 1
            ctx.run.notes.append(f"kaeferjaeger {prov}: {e}")
    if not raw_all:
        return 0, blocked
    blob = "\n".join(raw_all)
    raw_path = ctx.run.raw_path("horizontal", "kaeferjaeger", "sni.txt")
    raw_path.write_text(blob[:_KJ_CAP])
    # cert lines contain many hostnames; extract scope matches
    import re
    for m in re.findall(r"[a-z0-9_.-]+\.[a-z]{2,}", blob, re.IGNORECASE):
        h = m.lower().rstrip(".")
        if ctx.scope.in_scope(h):
            if ctx.run.add("subdomain", {"host": h, "sources": ["kaeferjaeger"],
                                         "raw_ref": str(raw_path)}):
                added += 1
    return added, 0


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    # kaeferjaeger is passive OSINT — always allowed (even passive-only mode). ONE concise line max:
    # hits if any, else a single "blocked" note (not 5 × 403), else silent.
    n, blocked = _kaeferjaeger(ctx)
    if n:
        ctx.echo(f"  kaeferjaeger: +{n} in-scope hosts")
    elif blocked:
        ctx.echo(f"  kaeferjaeger: source unavailable ({blocked} provider(s) failed) — skipped")

    # csprecon: related domains from Content-Security-Policy headers (light HTTP; active)
    if not scope.passive_only and have("csprecon"):
        roots_f = ctx.write_list("roots.txt", prof.apex_domains)
        csp = ctx.run.raw_path("horizontal", "csprecon", "csp.txt")
        r = exec_tool("csprecon", ["csprecon", "-l", str(roots_f), "-s"],
                      raw_path=csp, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            added = 0
            for ent in normalize.hosts(r.raw_path.read_text(), "csprecon", str(csp)):
                if scope.in_scope(ent["host"]) and ctx.run.add("subdomain", ent):
                    added += 1
            ctx.echo(f"  csprecon: +{added} in-scope hosts from CSP")

    # cloud-asset candidates: S3/GCS bucket enum from apex/org (non-mutating detect, verify-ownership).
    # ABOVE the CIDR early-return — it's apex/org-derived and must run for domain-only profiles too.
    if not scope.passive_only:
        from .. import cloud
        nc = cloud.discover(ctx)
        if nc:
            ctx.echo(f"  cloud: +{nc} bucket candidate(s) — VERIFY OWNERSHIP")

    if not prof.cidr:
        ctx.echo("  no CIDR in profile — skipping ASN/range/tls-SAN/revdns steps")
        ctx.run.notes.append("horizontal: CIDR empty, IP-based steps skipped")
        return

    cidr_file = ctx.write_list("cidr.txt", prof.cidr)

    # expand CIDR -> IPs
    ips_path = ctx.run.raw_path("horizontal", "mapcidr", "ips.txt")
    r = exec_tool("mapcidr", ["mapcidr", "-cidr", ",".join(prof.cidr), "-silent"],
            raw_path=ips_path, timeout=120)
    ctx.run.record("horizontal", r)
    ips_file = ips_path if r.ok else cidr_file

    # tls SAN harvest on the ranges -> in-scope hostnames
    if scope.passive_only:
        ctx.run.record("horizontal", skipped("tlsx", "passive-only mode"))
    else:
        tls_raw = ctx.run.raw_path("horizontal", "tlsx", "san.txt")
        r = exec_tool("tlsx", ["tlsx", "-l", str(ips_file), "-san", "-cn", "-silent",
                         "-p", "443,8443,4443", "-resp-only"], raw_path=tls_raw, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            added = 0
            for ent in normalize.hosts(r.raw_path.read_text(), "tlsx-san", str(tls_raw)):
                if scope.in_scope(ent["host"]) and ctx.run.add("subdomain", ent):
                    added += 1
            ctx.echo(f"  tlsx SAN: +{added} in-scope hosts")

    # reverse DNS (PTR) on range IPs
    if not scope.passive_only:
        ptr_raw = ctx.run.raw_path("horizontal", "dnsx", "ptr.txt")
        r = exec_tool("dnsx", ["dnsx", "-l", str(ips_file), "-ptr", "-resp-only", "-silent"],
                raw_path=ptr_raw, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            for ent in normalize.hosts(r.raw_path.read_text(), "revdns", str(ptr_raw)):
                if scope.in_scope(ent["host"]):
                    ctx.run.add("subdomain", ent)

    # Caduceus: live ASN/CIDR -> TLS cert scan -> real hostnames behind CDN
    # (surfaces hosts behind Akamai/Cloudflare that DNS enum misses). Needs active mode + CIDR.
    if not scope.passive_only and have("caduceus"):
        cad = ctx.run.raw_path("horizontal", "caduceus", "certs.json")
        r = exec_tool("caduceus", ["caduceus", "-i", str(cidr_file),
                                   "-p", "443,8443,4443", "-j"], raw_path=cad, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            import json as _json
            added = 0
            raw_text = r.raw_path.read_text()
            try:
                parsed = _json.loads(raw_text)
                records = parsed if isinstance(parsed, list) else [parsed]
            except _json.JSONDecodeError:
                records = []
                for line in raw_text.splitlines():
                    try:
                        records.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        continue
            for obj in records:
                if not isinstance(obj, dict):
                    continue
                domains = obj.get("domains") or obj.get("domain") or obj.get("names") or []
                if isinstance(domains, str):
                    domains = [domains]
                for d in domains:
                    h = str(d).lower().rstrip(".")
                    if scope.in_scope(h) and ctx.run.add("subdomain",
                            {"host": h, "sources": ["caduceus"], "raw_ref": str(cad)}):
                        added += 1
            if not records:
                try:
                    # Last-resort extraction keeps the run useful if Caduceus changes shape.
                    for h in set(__import__("re").findall(r"[a-z0-9_.-]+\.[a-z]{2,}", raw_text, __import__("re").I)):
                        h = h.lower().rstrip(".")
                        if scope.in_scope(h) and ctx.run.add("subdomain",
                                {"host": h, "sources": ["caduceus"], "raw_ref": str(cad)}):
                            added += 1
                except Exception:
                    pass
            ctx.echo(f"  caduceus: +{added} in-scope hosts from certs")
    elif not scope.passive_only:
        ctx.run.record("horizontal", skipped("caduceus", "not installed (optional) — quarry install --only caduceus"))

    # asnmap: context only, never block (hard timeout in runner)
    asn_seeds = prof.asn
    if asn_seeds:
        asn_raw = ctx.run.raw_path("horizontal", "asnmap", "ranges.txt")
        r = exec_tool("asnmap", ["asnmap", "-silent"], stdin_data="\n".join(asn_seeds),
                raw_path=asn_raw, timeout=60)
        ctx.run.record("horizontal", r)
