"""Enrich phase — catch-up over hosts discovered AFTER vertical + probe.

CSP siblings (found in probe via httpx -irh) and link-only needles (found in crawl) become
known *after* the vertical resolve/CNAME pass and the probe pass have already run. Without a
catch-up they stay un-resolved, un-probed, and — critically — never get subdomain-takeover
analysis (a dangling-CNAME host first seen via a crawl link would otherwise be invisible to
the takeover check). This phase resolves them, runs the CNAME/takeover signal, and probes the
ones that resolve, so late-discovered hosts get the same treatment as vertical-discovered ones.
"""
from __future__ import annotations

import json as _json

from .. import normalize
from ..runner import have, run as exec_tool, skipped


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    resolved = set(ctx.run.values("resolved"))
    # hosts known (subdomain) but never resolved → the crawl/CSP-discovered ones
    new = sorted(h for h in set(ctx.run.values("subdomain"))
                 if h and h not in resolved and scope.in_scope(h) and not scope.is_oos(h))
    if not new:
        ctx.run.record("enrich", skipped("enrich", "no late-discovered hosts to enrich"))
        return
    ctx.echo(f"  enriching {len(new)} late-discovered host(s) (crawl/CSP)")
    targets = ctx.write_list("enrich_hosts.txt", new)

    # 1. resolve (A) — pull the late hosts into `resolved`
    if have("dnsx"):
        res = ctx.run.raw_path("enrich", "dnsx", "resolved.txt")
        r = exec_tool("dnsx", ["dnsx", "-l", str(targets), "-a", "-resp", "-json", "-silent"],
                      raw_path=res, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.raw_path:
            for e in normalize.dnsx_resolved(r.raw_path.read_text(), "dnsx", str(res)):
                if scope.in_scope(e["host"]) and not scope.is_oos(e["host"]):
                    ctx.run.add("resolved", e)
        resolved = set(ctx.run.values("resolved"))

    # 2. CNAME / takeover over the late hosts (same signal as vertical's CNAME collection) —
    # a host with a CNAME but no A of its own = takeover candidate.
    if prof.takeover and have("dnsx"):
        cn = ctx.run.raw_path("enrich", "dnsx", "cnames.jsonl")
        r = exec_tool("dnsx", ["dnsx", "-l", str(targets), "-cname", "-json", "-silent"],
                      raw_path=cn, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.raw_path:
            ntk = 0
            for line in r.raw_path.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                host = o.get("host")
                dangling = host not in resolved
                for c in (o.get("cname") or []):
                    ctx.run.add("review", {"id": f"cname:{host}->{c}", "klass": "cname",
                                           "value": f"{host} -> {c}", "host": host,
                                           "cname": c, "takeover_candidate": dangling,
                                           "sources": ["dnsx"]})
                    if dangling:
                        ntk += 1
            if ntk:
                ctx.echo(f"  enrich: +{ntk} dangling CNAME → takeover candidate")

    # 3. probe the newly-resolved hosts (live + tech), so link/CSP-only hosts get fingerprinted
    new_set = set(new)
    new_resolved = sorted(h for h in resolved if h in new_set)
    if not scope.passive_only and have("httpx") and new_resolved:
        hf = ctx.write_list("enrich_probe.txt", new_resolved)
        hx = ctx.run.raw_path("enrich", "httpx", "httpx.jsonl")
        cmd = ["httpx", "-l", str(hf), "-json", "-silent",
               "-ports", ",".join(str(p) for p in prof.ports),
               "-td", "-title", "-sc", "-cl", "-web-server", "-ip", "-cname", "-irh",
               "-follow-redirects", "-no-fallback", "-random-agent", "-t", "15"]
        if prof.http_rl:
            cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("httpx", cmd, raw_path=hx, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.raw_path:
            n = 0
            for e in normalize.httpx_json(r.raw_path.read_text(), "httpx", str(hx)):
                if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                    if ctx.run.add("live", e):
                        n += 1
                        for tech in e.get("tech") or []:
                            ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                                 "url": e["url"], "sources": ["httpx"]})
            ctx.echo(f"  enrich: +{n} live (late-discovered)")
