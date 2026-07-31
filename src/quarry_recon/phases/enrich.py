"""Enrich phase — catch-up over hosts discovered AFTER vertical + probe.

CSP siblings (found in probe via httpx -irh) and link-only needles (found in crawl) become
known *after* the vertical resolve/CNAME pass and the probe pass have already run. Without a
catch-up they stay un-resolved, un-probed, and — critically — never get subdomain-takeover
analysis (a dangling-CNAME host first seen via a crawl link would otherwise be invisible to
the takeover check). This phase resolves them, runs the CNAME/takeover signal, and probes the
ones that resolve, so late-discovered hosts get the same treatment as vertical-discovered ones.
"""
from __future__ import annotations

from pathlib import Path

import json as _json

from .. import normalize
from .. import settings
from ..runner import (RunResult, Status, fresh_artifact_dir, have, nuclei_timeout, reclassify_from_files,
                      run as exec_tool, scaled_timeout, skipped)


def _a1d_base_words(ctx, wordlist_fn, loss: dict) -> set:
    """The configured BASE dictionary, read inside A1d's loss boundary.

    review-B-audit-12#2: this read sat outside every boundary — a permission or decoding failure escaped
    `_a1d_recursive_brute`, recorded no A1d result at all and took the rest of the enrich phase with it.
    The base list is only used to DEDUP mined words against, so failing to read it does not stop A1d; it
    makes the run re-brute dictionary words, which is a loss worth reporting, not a reason to abort."""
    try:
        base_wl = wordlist_fn(ctx)
    except Exception as ex:
        loss["base_error"] = f"the base wordlist could not be located ({type(ex).__name__})"
        return set()
    if not base_wl:
        return set()
    try:
        raw = Path(base_wl).read_bytes()
    except OSError as ex:
        loss["base_error"] = f"the base wordlist could not be read ({type(ex).__name__})"
        return set()
    out, dropped = set(), 0
    for chunk in raw.splitlines():
        try:
            w = chunk.decode("utf-8")
        except UnicodeDecodeError:
            dropped += 1                       # a line we cannot decode cannot exclude anything
            continue
        w = w.strip().lower()
        if w and not w.startswith("#"):
            out.add(w)
    if dropped:
        loss["base_dropped_lines"] = dropped
    return out


def _a1d_loss_why(loss: dict, produced: int) -> str:
    """One accurate sentence for everything A1d lost, or "" when nothing was lost.

    review-B-audit-12#1: "every mined wordlist artifact was unreadable" was asserted whenever ANY file was
    unreadable, so one unreadable file beside a readable-but-empty one produced a false claim. What the
    readable files yielded is stated, not assumed."""
    files, unreadable = loss.get("files", 0), loss.get("unreadable_files", 0)
    parts = []
    if unreadable:
        parts.append(f"ALL {files} mined wordlist artifact(s) unreadable" if unreadable == files and files
                     else (f"{unreadable}/{files} mined wordlist artifact(s) unreadable — the readable "
                           f"{files - unreadable} yielded {produced} usable word(s)"))
    if loss.get("dropped_lines"):
        parts.append(f"{loss['dropped_lines']} mined line(s) not valid UTF-8 and dropped")
    if loss.get("base_error"):
        parts.append(f"{loss['base_error']} — mined words were NOT deduped against it")
    if loss.get("base_dropped_lines"):
        parts.append(f"{loss['base_dropped_lines']} base wordlist line(s) not valid UTF-8")
    return "; ".join(parts)


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
    wl_loss: dict = {}
    base_words = _a1d_base_words(ctx, _wordlist, wl_loss)
    twords = _target_wordlist(ctx, base_words, loss=wl_loss)
    # review-B-audit-12#1: ONE attempt, ONE outcome. Two independent branches used to record a PARTIAL and
    # then a FAILED/SKIPPED for the same attempt, and the FAILED claimed "every artifact was unreadable"
    # even when a readable one had simply yielded nothing. The verdict is chosen once, from what was
    # PRODUCED and what was LOST.
    lost = _a1d_loss_why(wl_loss, len(twords))
    if not twords:
        # review-B-audit-13#2: the base list exists only to DEDUP mined words against. With nothing mined,
        # dedup had no work to do, so a base-only failure is not A1d damage — a genuine no-input SKIP must
        # survive it. Damage to the MINED input is a different fact and still fails.
        mined_damage = _a1d_loss_why({k: v for k, v in wl_loss.items() if not k.startswith("base_")}, 0)
        if mined_damage:
            why = (f"A1d has NO vocabulary and the mined input was DAMAGED ({mined_damage}) — not proof "
                   f"the target had none")
            ctx.run.record("enrich", RunResult("a1d", ["a1d"], Status.FAILED, None, 0.0, None, 0, note=why))
            ctx.echo(f"  A1d: {why}")
        else:
            ctx.run.record("enrich", skipped("a1d", "no target-specific words mined from crawl"))
        return set()
    twl = ctx.write_list("a1d_target_words.txt", twords)
    ctx.echo(f"  A1d: {len(twords)} target-specific word(s) mined from crawl → recursive re-brute")
    discovered: set[str] = set()

    # apex brute with the target wordlist (same puredns invocation as vertical's brute)
    submitted_apexes = 0
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
            submitted_apexes += 1
    else:
        # review-B-audit-13#1: this branch was silently skipped, so eligible A1d work simply vanished —
        # the run showed a mined wordlist and no brute, and nothing said why. A missing REQUIRED tool is
        # already a coverage gap in the manifest; the note carries how much work went unsubmitted.
        ctx.run.record("enrich", skipped("puredns", f"not installed — {len(prof.apex_domains)} A1d apex "
                                                    f"brute(s) unsubmitted"))

    # wildcard-zone differ with the target words folded in (zones persisted by vertical)
    zones = set(ctx.run.values("wildcard_zone"))
    wc: dict = {}
    if zones:
        discovered.update(_wildcard_differentiate(ctx, zones, extra_words=twords, phase="enrich",
                                                  label="wildcard-a1d", source="wildcard-http-a1d",
                                                  source_id="enrich.wildcard_a1d", stats=wc))
    # ── ONE A1d outcome, chosen AFTER the work (review-B-audit-13#1): the earlier note claimed "the
    #    brute ran with less vocabulary" before anything had run — including when it never ran at all.
    unsubmitted = max(0, len(prof.apex_domains) - submitted_apexes)
    # review-B-audit-14: "there were wildcard zones" is not "the wildcard pass ran" — passive mode, a
    # missing httpx, no wordlist, the self-contact guard and the zone cap all leave zones UNSUBMITTED.
    # The differentiator now says what it actually probed, and both facts are reported.
    wc_eligible, wc_probed = wc.get("eligible_zones", 0), wc.get("probed_zones", 0)
    wc_unsubmitted = max(0, wc_eligible - wc_probed)
    parts = ([lost] if lost else []) + ([f"puredns is not installed — {unsubmitted} apex brute(s) "
                                         f"unsubmitted"] if unsubmitted else [])
    if wc_unsubmitted:
        parts.append(f"{wc_unsubmitted}/{wc_eligible} wildcard zone(s) not differentiated"
                     + (f" ({wc['blocked_reason']})" if wc.get("blocked_reason") else ""))
    # review-B-audit-16#2: vocabulary the wildcard pass could not use is A1d's loss too, and it was only
    # ever looked at when zones went unsubmitted — so a probed run with a damaged wordlist read clean.
    _v = wc.get("vocabulary") or {}
    _vlost = _v.get("undecodable", 0) + _v.get("rejected", 0)
    if _v.get("unreadable"):
        parts.append("the wildcard wordlist is present and UNREADABLE — only the mined vocabulary was used")
    if _vlost:
        parts.append(f"{_vlost} wildcard vocabulary word(s) unusable ({_v.get('undecodable', 0)} not valid "
                     f"UTF-8, {_v.get('rejected', 0)} not a single DNS label)")
    if _v.get("withheld"):
        parts.append(f"{_v['withheld']} usable wildcard word(s) withheld by the word cap")
    if parts:
        ran = bool(submitted_apexes or wc_probed)
        why = (f"A1d ran with less than its eligible work ({'; '.join(parts)})" if ran else
               f"A1d did NOT run ({'; '.join(parts)})")
        ctx.run.record("enrich", RunResult("a1d", ["a1d"], Status.PARTIAL if ran else Status.FAILED,
                                           None, 0.0, None, 0, note=why))
        ctx.echo(f"  A1d: {why}")
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
        # v0.3.5: share probe's fingerprint path — SYN web-port prefilter → httpx on open ports only,
        # same fallback discipline. Late A1d/crawl/CSP hosts don't fall back to the slow direct behavior.
        from .probe import fingerprint_hosts
        new_live: list[str] = []
        for raw_ref, glines in fingerprint_hosts(ctx, new_resolved, "enrich"):   # per-group raw provenance
            for e in normalize.httpx_json("\n".join(glines), "httpx", raw_ref):
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
                shot_dir = fresh_artifact_dir(ctx.run.dir / "raw" / "enrich" / "gowitness")   # FRESH per invocation
                gr = exec_tool("gowitness",
                    ["gowitness", "scan", "file", "-f", str(lf),
                     "--screenshot-path", str(shot_dir), "--write-jsonl",
                     "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                    timeout=ctx.http_timeout)
                # same file-output reclassification as probe — count THIS attempt's dir only (a reused/
                # pre-populated dir must not inflate the count; T1.6 core precondition: fresh artifact)
                shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
                reclassify_from_files(gr, shots, "screenshot")
                ctx.run.record("enrich", gr)
                for ext in ("*.jpeg", "*.png"):
                    for img in shot_dir.glob(ext):
                        ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

            if have("smap"):                            # passive (Shodan) ports — parse like probe (C12)
                sm_targets = [normalize.host_of_url(u) for u in new_live]
                si = ctx.write_list("enrich_smap.txt", sm_targets)
                sm = ctx.run.raw_path("enrich", "smap", "smap.json")
                sm.unlink(missing_ok=True)              # -o file: clear stale before the run
                sr = exec_tool("smap", ["smap", "-iL", str(si), "-oJ", str(sm)], timeout=600)
                # was recorded raw-only — enrich's passive port yield was lost (C12). Parse + reclassify +
                # ingest via the SAME shared helper probe uses (-oJ structured; status reflects yield).
                from .probe import _smap_ingest
                _smap_ingest(ctx, sr, sm, "enrich", sm_targets)
