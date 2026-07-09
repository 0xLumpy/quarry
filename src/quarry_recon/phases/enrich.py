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
from .. import settings
from ..runner import (have, nuclei_timeout, reclassify_from_files, run as exec_tool,
                      scaled_timeout, skipped)


def _a1d_recursive_brute(ctx) -> set[str]:
    """A1d — recursion: feed the target-specific wordlist mined during the crawl back into the brute.

    "Teach Quarry how the target functions." The crawl phase (which runs AFTER vertical) mines the
    target's own naming vocabulary via xnLinkFinder over waymore/JS. Here — the first phase after
    crawl — we harvest that vocabulary and re-brute with it: apexes (puredns) + any wildcard zones
    vertical discovered (the A1 HTTP-differentiator, with the target words folded in). Bounded: the
    target wordlist is capped and deduped against the base dictionary, so this can't explode the
    brute. Returns the set of hosts discovered so run() can force them into the enrich catch-up set."""
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        return set()
    from .vertical import _target_wordlist, _wildcard_differentiate, _resolvers, _wordlist
    base_wl = _wordlist(ctx)
    base_words = {w.strip().lower() for w in base_wl.read_text().splitlines()
                  if w.strip() and not w.startswith("#")} if base_wl else set()
    twords = _target_wordlist(ctx, base_words)
    if not twords:
        ctx.run.record("enrich", skipped("a1d", "no target-specific words mined from crawl"))
        return set()
    twl = ctx.write_list("a1d_target_words.txt", twords)
    ctx.echo(f"  A1d: {len(twords)} target-specific word(s) mined from crawl → recursive re-brute")
    discovered: set[str] = set()

    # apex brute with the target wordlist (same puredns invocation as vertical's brute)
    if have("puredns"):
        resolvers, trusted = _resolvers(ctx)
        for d in prof.apex_domains:
            cmd = ["puredns", "bruteforce", str(twl), d, "--resolvers-trusted", str(trusted), "-q"]
            if resolvers:
                cmd += ["-r", str(resolvers)]
            if prof.dns_rate:
                cmd += ["--rate-limit", str(prof.dns_rate)]
            br = ctx.run.raw_path("enrich", "puredns", f"a1d-brute-{d}.txt")
            r = exec_tool("puredns", cmd, raw_path=br, timeout=ctx.http_timeout)
            ctx.run.record("enrich", r)
            if r.raw_path:
                for e in normalize.hosts(r.raw_path.read_text(), "target-wordlist", str(br)):
                    if scope.in_scope(e["host"]) and not scope.is_oos(e["host"]):
                        ctx.run.add("subdomain", e)
                        discovered.add(e["host"])

    # wildcard-zone differ with the target words folded in (zones persisted by vertical)
    zones = set(ctx.run.values("wildcard_zone"))
    if zones:
        discovered.update(_wildcard_differentiate(ctx, zones, extra_words=twords, phase="enrich",
                                                  label="wildcard-a1d", source="wildcard-http-a1d"))
    if discovered:
        ctx.echo(f"  A1d: +{len(discovered)} host(s) via target-specific recursive re-brute")
    return discovered


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    # A1d recursion FIRST — its discoveries then flow through the resolve/probe/takeover pass below.
    a1d_hosts = _a1d_recursive_brute(ctx)
    resolved = set(ctx.run.values("resolved"))
    # hosts known (subdomain) but never resolved → the crawl/CSP-discovered ones.
    # A1d's wildcard-differentiator adds its hits to `resolved` too (it needs its own httpx pass),
    # which would exclude them from this catch-up — force them back in so they still get the full
    # enrich treatment (dns-record, CNAME/takeover, rich httpx fingerprint, screenshots/WAF/smap).
    new = sorted({h for h in set(ctx.run.values("subdomain"))
                  if h and h not in resolved and scope.in_scope(h) and not scope.is_oos(h)}
                 | {h for h in a1d_hosts if scope.in_scope(h) and not scope.is_oos(h)})
    if not new:
        ctx.run.record("enrich", skipped("enrich", "no late-discovered hosts to enrich"))
        return
    ctx.echo(f"  enriching {len(new)} late-discovered host(s) "
             f"({'crawl/CSP/A1d' if a1d_hosts else 'crawl/CSP'})")
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
        # -a so dangling = has CNAME but no A in THIS result (enrich itself can add a no-A host
        # to `resolved` with a:[], so resolved-set membership is not a reliable dangling signal).
        r = exec_tool("dnsx", ["dnsx", "-l", str(targets), "-cname", "-a", "-json", "-silent"],
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
                dangling = not o.get("a")          # has a CNAME (loop below) but no A record
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

    # DNS-record catch-up: late hosts (crawl/CSP) resolved here missed the `dns` phase, so run the
    # same wildcard-filtered dnsx enrichment over just these (deferred "dns incremental catch-up").
    if new_resolved and have("dnsx"):
        from . import dns as _dns
        nd = _dns.enrich_hosts(ctx, new_resolved, "enrich")
        if nd:
            ctx.echo(f"  dns-enrich (late): +{nd} record(s) over {len(new_resolved)} host(s)")

    if not scope.passive_only and have("httpx") and new_resolved:
        hf = ctx.write_list("enrich_probe.txt", new_resolved)
        hx = ctx.run.raw_path("enrich", "httpx", "httpx.jsonl")
        # methodology flag set MUST match probe.py — without -cdn (and -favicon/-asn/-location/
        # -probe-all-ips) httpx omits CDN data and normalize defaults cdn=False, misclassifying
        # late hosts as origin/no-WAF in the digest.
        cmd = ["httpx", "-l", str(hf), "-json", "-silent",
               "-ports", ",".join(str(p) for p in prof.ports),
               "-td", "-title", "-sc", "-cl", "-favicon", "-cdn", "-web-server",
               "-asn", "-location", "-ip", "-cname", "-irh",
               "-follow-redirects", "-no-fallback", "-probe-all-ips", "-random-agent",
               "-t", str(settings.workers("httpx", 15))]     # H2: core-scaled concurrency
        if prof.http_rl:
            cmd += ["-rl", str(prof.http_rl)]
        # late hosts (A1d re-brute / crawl / CSP) can be large → scale like the probe httpx (port-weighted)
        r = exec_tool("httpx", cmd, raw_path=hx,
                      timeout=scaled_timeout(len(new_resolved), ctx.http_timeout,
                                             per_unit=max(6, len(prof.ports) // 12)))
        ctx.run.record("enrich", r)
        new_live: list[str] = []
        if r.raw_path:
            for e in normalize.httpx_json(r.raw_path.read_text(), "httpx", str(hx)):
                if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                    if ctx.run.add("live", e):
                        new_live.append(e["url"])
                        for tech in e.get("tech") or []:
                            ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                                 "url": e["url"], "sources": ["httpx"]})
            ctx.echo(f"  enrich: +{len(new_live)} live (late-discovered)")

        # ── fingerprint the late hosts the same way probe does (probe ran before they existed) ──
        if new_live:
            if have("nuclei"):                          # WAF fingerprint
                wi = ctx.write_list("enrich_waf.txt", new_live)
                wo = ctx.run.raw_path("enrich", "nuclei", "waf.jsonl")
                wcmd = ["nuclei", "-l", str(wi), "-tags", "waf", "-jsonl", "-o", str(wo)]
                if prof.http_rl:
                    wcmd += ["-rl", str(prof.http_rl)]
                ctx.run.record("enrich", exec_tool(
                    "nuclei", wcmd, timeout=nuclei_timeout(len(new_live), ctx.http_timeout)))
                if wo.exists():
                    for line in wo.read_text().splitlines():
                        try:
                            o = _json.loads(line)
                        except _json.JSONDecodeError:
                            continue
                        ex = o.get("extracted-results") or []
                        name = (ex[0] if ex else None) or o.get("matcher-name") or "unknown"
                        host = o.get("matched-at", o.get("host", ""))
                        ctx.run.add("tech", {"id": f"{host}|waf:{name}", "tech": f"WAF:{name}",
                                             "url": host, "sources": ["nuclei-waf"]})

            if prof.screenshots and have("gowitness"):  # screenshots
                lf = ctx.write_list("enrich_live.txt", new_live)
                shot_dir = ctx.run.dir / "raw" / "enrich" / "gowitness"
                shot_dir.mkdir(parents=True, exist_ok=True)
                gr = exec_tool("gowitness",
                    ["gowitness", "scan", "file", "-f", str(lf),
                     "--screenshot-path", str(shot_dir), "--write-jsonl",
                     "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                    timeout=ctx.http_timeout)
                # same file-output reclassification as probe (BLOCKED-on-empty-stdout is a mislabel)
                shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
                reclassify_from_files(gr, shots, "screenshot")
                ctx.run.record("enrich", gr)
                for ext in ("*.jpeg", "*.png"):
                    for img in shot_dir.glob(ext):
                        ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

            if have("smap"):                            # passive (Shodan) ports — raw, like probe
                si = ctx.write_list("enrich_smap.txt",
                                    [normalize.host_of_url(u) for u in new_live])
                sm = ctx.run.raw_path("enrich", "smap", "smap.txt")
                ctx.run.record("enrich", exec_tool("smap", ["smap", "-iL", str(si)],
                                                   raw_path=sm, timeout=600))
