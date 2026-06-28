"""Content discovery (Phase 11) — candidate-driven, scope-safe ffuf. Default OFF.

Intensity via MODES.CONTENT_DISCOVERY: off | light | balanced | deep (11.1 = off/light/balanced,
flat). Recursion (MODES.CONTENT_RECURSION) is 11.2. Guardrails: skipped in passive mode and when
off; only live, in-scope, active-allowed hosts (origin first, capped); ffuf -ac autocalibration
always (kills wildcard/catch-all floods); http_rl -> ffuf -rate. Map-don't-exploit: results are
url + review candidates, never actions. Full design: notes/PHASE11-DESIGN.md.
"""
from __future__ import annotations

import hashlib
import json as _json
from importlib import resources
from pathlib import Path

from .. import normalize
from ..runner import have, run as exec_tool, skipped

MAX_HOSTS = 25                     # cap candidate hosts so a wide scope can't explode
MAX_RESULTS_PER_HOST = 500         # safety cap if autocalibration misses a wildcard
_NOTABLE = {200, 401, 403}         # statuses worth a review-queue entry


def _wordlist(ctx, tier: str) -> Path | None:
    """Resolve the wordlist for a tier. `light` ships with the package (always available);
    `balanced`/`deep` come from framework-managed lists (install/user-provided)."""
    home = Path.home()
    override = home / ".config" / "quarry" / "wordlists" / "content" / f"{tier}.txt"
    if override.exists():
        return override
    if tier == "light":            # shipped curated list -> materialize to the run workdir
        try:
            data = resources.files("quarry_recon.data").joinpath("content-light.txt").read_text()
        except Exception:
            return None
        p = ctx.tmp("content-light.txt")
        p.write_text(data)
        return p
    for c in (home / "wordlists" / f"{tier}.txt",
              home / "wordlists" / "seclists" / "Discovery" / "Web-Content" /
              ("raft-medium-directories.txt" if tier == "balanced" else "raft-large-directories.txt")):
        if c.exists():
            return c
    return None


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    tier = prof.content_discovery
    if tier == "off" or scope.passive_only:
        ctx.run.record("content", skipped("ffuf", f"content discovery: {tier} / passive — skipped"))
        return
    if not have("ffuf"):
        ctx.run.record("content", skipped("ffuf", "ffuf not installed"))
        return
    wl = _wordlist(ctx, tier)
    if not wl:
        ctx.run.record("content", skipped(
            "ffuf", f"no '{tier}' wordlist (~/.config/quarry/wordlists/content/{tier}.txt)"))
        return

    # candidates: live + in-scope + active-allowed; origin (non-CDN) first; capped
    cand = [l for l in ctx.run.read("live")
            if scope.active_allowed(normalize.host_of_url(l.get("url", "")))]
    cand.sort(key=lambda l: 1 if l.get("cdn") else 0)
    targets = [l["url"] for l in cand[:MAX_HOSTS] if l.get("url")]
    if not targets:
        ctx.run.record("content", skipped("ffuf", "no active-allowed live hosts"))
        return
    ctx.echo(f"  content discovery [{tier}]: {len(targets)} host(s), wordlist {wl.name}")

    notable = 0
    for url in targets:
        host = normalize.host_of_url(url)
        # include a url hash so http/https/:8443 on the same host don't overwrite each other's raw
        out = ctx.run.raw_path("content", "ffuf", f"{host}-{hashlib.md5(url.encode()).hexdigest()[:8]}.json")
        cmd = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", str(wl), "-ac",
               "-mc", "200,204,301,302,307,308,401,403,405", "-of", "json", "-o", str(out), "-s"]
        if prof.http_rl:
            cmd += ["-rate", str(prof.http_rl)]
        ctx.run.record("content", exec_tool("ffuf", cmd, timeout=ctx.http_timeout))
        if not out.exists():
            continue
        try:
            results = (_json.loads(out.read_text() or "{}").get("results") or [])[:MAX_RESULTS_PER_HOST]
        except _json.JSONDecodeError:
            continue
        for res in results:
            u, st = res.get("url"), res.get("status")
            if not u or not scope.in_scope(normalize.host_of_url(u)):
                continue
            ctx.run.add("url", {"url": u, "status": st, "sources": ["ffuf"], "raw_ref": str(out)})
            if st in _NOTABLE:
                ctx.run.add("review", {"id": f"content:{u}", "klass": "content",
                                       "value": f"[{st}] {u}", "host": host,
                                       "sources": ["ffuf"], "raw_ref": str(out)})
                notable += 1
    ctx.echo(f"  content: {notable} notable path(s) (200/401/403)")
