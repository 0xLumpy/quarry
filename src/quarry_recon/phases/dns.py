"""DNS-record enrichment phase (after vertical, before probe).

puredns stays the brute/validation path; this phase does NOT re-discover hosts. It runs ONE dnsx
pass over the known in-scope resolved set to pull the full useful record layer — A/AAAA/CNAME/MX/
NS/TXT/SOA/CAA + per-host ASN/CDN — as first-class `dns_record` entities with provenance. Placed
early so the DNS context (IPv6, org/DNS-provider, per-host ASN) feeds review/digest + human
decisions from probe onward, instead of being buried at the end of the run.

Overlap is justified as CONTEXT, not duplication: puredns = does-it-resolve; dnsx-enrich = what
records it has. asnmap (horizontal) expands a profile ASN/CIDR into scope; dnsx `-asn` tags each
resolved host with the ASN it sits in — complementary.

Late-discovered hosts (crawl/CSP, found after this phase) don't get DNS metadata this run — that's
a deferred "dns incremental catch-up" refinement. Wildcard-record filtering + TXT intelligence are
separate follow-ups.
"""
from __future__ import annotations

from .. import normalize
from ..runner import have, run as exec_tool, skipped

_RECORD_FLAGS = ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-caa", "-asn", "-cdn"]


def run(ctx) -> None:
    scope = ctx.scope
    if not have("dnsx"):
        ctx.run.record("dns", skipped("dnsx", "dnsx not installed"))
        return
    # RESOLVED hosts only. A no-A / dangling-CNAME host (known as `subdomain` but never resolved)
    # is intentionally NOT enriched here — dns_record is a resolved-asset metadata layer; the
    # CNAME/takeover signal for no-A hosts stays in vertical + enrich.
    hosts = sorted(h for h in set(ctx.run.values("resolved"))
                   if h and scope.in_scope(h) and not scope.is_oos(h))
    if not hosts:
        ctx.run.record("dns", skipped("dnsx", "no in-scope resolved hosts to enrich"))
        return

    hf = ctx.write_list("dns_enrich_hosts.txt", hosts)
    out = ctx.run.raw_path("dns", "dnsx", "records.jsonl")
    cmd = ["dnsx", "-l", str(hf), *_RECORD_FLAGS, "-json", "-silent"]
    if ctx.profile.dns_rate:                        # honor RATELIMIT.DNS (dnsx -rl = req/s)
        cmd += ["-rl", str(ctx.profile.dns_rate)]
    r = exec_tool("dnsx", cmd, raw_path=out, timeout=ctx.http_timeout)
    ctx.run.record("dns", r)

    n = types = 0
    seen_types: set[str] = set()
    if r.raw_path and r.raw_path.exists():
        for e in normalize.dnsx_records(r.raw_path.read_text(), "dnsx-enrich", str(out)):
            if scope.in_scope(e["host"]) and not scope.is_oos(e["host"]):
                if ctx.run.add("dns_record", e):
                    n += 1
                    seen_types.add(e["type"])
    types = len(seen_types)
    ctx.echo(f"  dns-enrich: +{n} record(s) ({types} type(s)) over {len(hosts)} host(s)")
