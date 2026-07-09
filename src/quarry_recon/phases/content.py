"""Content discovery (Phase 11) — candidate-driven, scope-safe ffuf. Default OFF.

Intensity via MODES.CONTENT_DISCOVERY: off | light | balanced | deep (11.1 = off/light/balanced,
flat). Recursion (MODES.CONTENT_RECURSION) is 11.2. Guardrails: skipped in passive mode and when
off; only live, in-scope, active-allowed hosts (origin first, capped); ffuf -ac autocalibration
always (kills wildcard/catch-all floods); http_rl -> ffuf -rate. Map-don't-exploit: results are
url + review candidates, never actions.
"""
from __future__ import annotations

import hashlib
import json as _json
from importlib import resources
from pathlib import Path

from .. import normalize, settings
from ..runner import have, run as exec_tool, scaled_timeout, skipped

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


def _configleak_words() -> list[str]:
    """Shipped curated high-signal config/secret/VCS/dangerous-endpoint paths (bare, ffuf FUZZ)."""
    try:
        data = resources.files("quarry_recon.data").joinpath("content-configleak.txt").read_text()
    except Exception:
        return []
    return [w.strip() for w in data.splitlines() if w.strip() and not w.startswith("#")]


def _merged_wordlist(ctx, wl: Path) -> Path:
    """Union the tier wordlist with the always-on config-leak list (dedup, order-preserving), so the
    high-signal secret/config paths are checked on EVERY content run regardless of tier."""
    extra = _configleak_words()
    if not extra:
        return wl
    seen: set[str] = set()
    words: list[str] = []
    for w in extra + wl.read_text().splitlines():        # config-leak first (checked even if capped)
        w = w.strip()
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            words.append(w)
    merged = ctx.tmp("content-fuzz.txt")
    merged.write_text("\n".join(words) + "\n")
    return merged


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
    wl = _merged_wordlist(ctx, wl)                        # +config-leak quick-hunt (always merged)

    # candidates: live + in-scope + active-allowed; origin (non-CDN) first; capped
    cand = [l for l in ctx.run.read("live")
            if scope.active_allowed(normalize.host_of_url(l.get("url", "")))]
    cand.sort(key=lambda l: 1 if l.get("cdn") else 0)
    targets = [l["url"] for l in cand[:MAX_HOSTS] if l.get("url")]
    if not targets:
        ctx.run.record("content", skipped("ffuf", "no active-allowed live hosts"))
        return
    # recursion is a separate knob, allowed on balanced/deep only (light stays a flat sweep)
    recurse = prof.content_recursion if tier in ("balanced", "deep") else 0
    rec = f", recursion depth {recurse}" if recurse else ""
    ctx.echo(f"  content discovery [{tier}]: {len(targets)} host(s), wordlist {wl.name}{rec}")
    if recurse >= 4:
        ctx.echo(f"  ⚠️  recursion depth {recurse} is aggressive — expect a loud / slow scan")

    notable = 0
    # workload-scaled ceiling per host: content brute is the balanced/deep+recursion path, so on a real
    # target it hits the same flat-1800s wall the vhost/probe ffuf did. Scale by wordlist size × recursion
    # depth (recursion multiplies the paths fuzzed). Merged wordlist counted once.
    wl_n = sum(1 for _ in wl.open())
    ct_to = scaled_timeout(wl_n * (recurse + 1), ctx.http_timeout, per_unit=0.4)
    for url in targets:
        host = normalize.host_of_url(url)
        # include a url hash so http/https/:8443 on the same host don't overwrite each other's raw
        out = ctx.run.raw_path("content", "ffuf", f"{host}-{hashlib.md5(url.encode()).hexdigest()[:8]}.json")
        # Redirect policy (DELIBERATE exception to the follow-redirects rule the classify-probes obey):
        # content discovery RECORDS what exists at a path — a path that returns 301/302/307/308 IS a
        # finding (`/admin`→`/login`, `/.git`→redirect: the path exists + where it goes is intel). So we
        # MATCH 3xx (-mc) instead of following (-r): following would classify many distinct paths onto one
        # login/home page → -ac/dedup would then drop them → the "this path exists" signal is lost. -ac
        # autocalibration already neutralises the redirect-everything catch-all. (ISC-16, v0.3.)
        cmd = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", str(wl), "-ac",
               "-t", str(settings.workers("ffuf", 40)),   # H2: core-scaled concurrency
               "-mc", "200,204,301,302,307,308,401,403,405", "-of", "json", "-o", str(out), "-s"]
        if prof.http_rl:
            cmd += ["-rate", str(prof.http_rl)]
        if recurse:                                  # 11.2: balanced/deep only (gated above)
            cmd += ["-recursion", "-recursion-depth", str(recurse)]
        ctx.run.record("content", exec_tool("ffuf", cmd, timeout=ct_to))
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
