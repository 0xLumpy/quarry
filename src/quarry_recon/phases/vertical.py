"""Phase 3: Vertical subdomain discovery.

passive (subfinder -all, all sources) + github-subdomains -> brute (puredns) ->
permutations (alterx/dnsgen) -> trusted-resolver validation. Records source deltas so
a human can spot "one source found many another missed" (methodology day1).
"""
from __future__ import annotations

import json as _json
import os
import re as _re
import shutil
import urllib.request
from pathlib import Path

from .. import events, netguard, normalize, secrets, settings
from ..contract import run_contract
from ..runner import Status, have, reclassify_from_artifact, run as exec_tool, skipped


def _shosubgo_read(path):
    """FAIL-CLOSED read of shosubgo's -o host-per-line file. Returns (hosts, artifact_ok):
      - hosts = validated host provenance dicts to INGEST — valid evidence is NEVER suppressed;
      - artifact_ok = True only when the file decoded as clean UTF-8 AND every non-blank line was a valid
        host. Any malformed line or invalid UTF-8 makes it False, so the caller can mark completion PARTIAL
        (not a clean SUCCESS/EMPTY) while still keeping the valid hosts.
    Returns (None, False) when there is no trustworthy artifact at all (missing / unreadable — OSError)."""
    if not path.exists():
        return None, False
    try:
        raw = path.read_bytes()
    except OSError:
        return None, False
    try:
        text = raw.decode("utf-8")
        artifact_ok = True
    except UnicodeDecodeError:
        text, artifact_ok = raw.decode("utf-8", "replace"), False    # invalid UTF-8 -> not a clean artifact
    hosts = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        parsed = list(normalize.hosts(s, "shosubgo", str(path)))
        if parsed:
            hosts.extend(parsed)                                     # keep the valid host
        else:
            artifact_ok = False                                     # a non-blank NON-host line -> malformed artifact
    return hosts, artifact_ok


def _openintel(ctx, cfg: dict, apex: str, timeout: int = 180) -> set:
    """ADVANCED optional passive source: query a local openintel-subs binary + subs.db for `apex`.
    SILENT when unconfigured (the caller guards on binary+db). When configured it runs THROUGH THE RUNNER
    and its RunResult is recorded, so the manifest can distinguish 'DB had no matches' (EMPTY) from
    timeout / broken binary / corrupt DB / CLI drift (FAILED/TIMED_OUT) — a configured failure must be
    OBSERVABLE, not swallowed (Lumpy 2026-07-12). Console stays quiet; a failure surfaces in the manifest.
    Returns the in-DB host set (empty on any non-clean result — best-effort, never breaks the run)."""
    binary, db = cfg.get("binary"), cfg.get("db")
    exe = shutil.which(binary) or (binary if binary and os.path.isfile(binary)
                                   and os.access(binary, os.X_OK) else None)
    if not exe or not os.path.isfile(db):
        # caller already checked binary+db are SET, so this is 'configured but broken' -> a recordable skip
        ctx.run.record("vertical", skipped("openintel-subs", "configured binary or db not found"))
        return set()
    raw = ctx.run.raw_path("vertical", "openintel", f"{apex}.txt")
    r = exec_tool("openintel-subs", [exe, "query", "-d", apex, "-s", "-b", db],
                  raw_path=raw, timeout=timeout)
    ctx.run.record("vertical", r)                           # observable: empty vs timeout vs broken
    if r.status not in (Status.SUCCESS, Status.EMPTY) or not (r.raw_path and Path(r.raw_path).exists()):
        return set()
    out = Path(r.raw_path).read_text(encoding="utf-8", errors="replace")
    return {h for h in (line.strip().lower().rstrip(".") for line in out.splitlines())
            if h and "." in h}


def _censys(cfg: dict, apex: str, timeout: int = 30) -> set:
    """OPTIONAL Censys Platform API cert search for `apex` → subdomain set. Returns an empty set
    (SILENT) unless both a PAT `token` and `org` id are configured. Defensive parse: extracts every
    hostname under the apex from the raw JSON response, so it survives Platform response-schema drift
    (no dependency on an exact `matched_services[...]` path). Best-effort — failure returns empty."""
    token, org = cfg.get("token"), cfg.get("org")
    if not token or not org:
        return set()
    body = _json.dumps({"query": f"cert.parsed.names: {apex}", "page_size": 100}).encode()
    req = urllib.request.Request(
        "https://api.platform.censys.io/v3/global/search/query", data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "X-Organization-ID": str(org),
                 "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(8 * 1024 * 1024).decode("utf-8", "replace")
    except Exception:
        return set()
    pat = _re.compile(r"[a-z0-9](?:[a-z0-9._-]*)?\." + _re.escape(apex) + r"\b", _re.I)
    return {m.lower().strip(".") for m in pat.findall(raw) if "." in m}


def _crtsh(apex: str, timeout: int = 30) -> set:
    """Direct crt.sh CT-log pull for `%.apex` → set of hostnames (SANs, wildcards stripped).
    Best-effort + no key: complements subfinder's CT sources (coverage) and is a fallback when
    passive is thin (resilience). A failure returns an empty set — never breaks the run."""
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(8 * 1024 * 1024)          # bounded read
        rows = _json.loads(data.decode("utf-8", "replace"))
    except Exception:
        return set()
    hosts = set()
    for row in rows if isinstance(rows, list) else []:
        for nv in str(row.get("name_value", "")).splitlines():
            h = nv.strip().lower().strip(".")
            if h and "." in h:
                hosts.add(h)
    return hosts


def _certspotter(apex: str, token: str | None = None, timeout: int = 30) -> set:
    """certspotter CT-log issuances for `apex` (+subdomains) → set of hostnames. Free tier is
    keyless (rate-limited); a token raises the limit. Best-effort — failure returns an empty set."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={apex}"
           "&include_subdomains=true&expand=dns_names")
    headers = {"User-Agent": "Mozilla/5.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            rows = _json.loads(r.read(8 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception:
        return set()
    hosts = set()
    for row in rows if isinstance(rows, list) else []:
        for h in (row.get("dns_names") or []):
            h = str(h).strip().lower().strip(".")
            if h and "." in h:
                hosts.add(h)
    return hosts


def _massdns_a(path: Path) -> dict[str, list[str]]:
    """Parse puredns' massdns simple output (`host. A 1.2.3.4`) → {host: [A records]}. Best-effort:
    a missing/garbled file yields {} (resolved just falls back to a:[])."""
    out: dict[str, list[str]] = {}
    try:
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "A":
                host = parts[0].rstrip(".").lower()
                if host:
                    out.setdefault(host, []).append(parts[2])
    except OSError:
        pass
    return out


def _resolvers(ctx) -> tuple[Path | None, Path | None]:
    """Locate resolver lists. Framework-managed under ~/.config/quarry, else None."""
    home = Path.home()
    candidates = [home / ".config/quarry/resolvers.txt", home / "wordlists/resolvers.txt"]
    trusted = [home / ".config/quarry/trusted-resolvers.txt",
               home / "wordlists/trusted-resolvers.txt"]
    r = next((p for p in candidates if p.exists()), None)
    t = next((p for p in trusted if p.exists()), None)
    if t is None:  # always provide a trusted fallback
        t = ctx.tmp("trusted-resolvers.txt")
        t.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n1.0.0.1\n208.67.222.222\n")
    return r, t


def _wordlist(ctx) -> Path | None:
    home = Path.home()
    for p in (home / ".config/quarry/wordlists/dns.txt",       # canonical (clean layout)
              home / ".config/quarry/dns-wordlist.txt",        # back-compat (pre-reorg installs)
              home / "wordlists/best-dns-wordlist.txt",
              home / "wordlists/subdomains.txt"):
        if p.exists():
            return p
    return None


_LABEL_RX = _re.compile(r"[a-z0-9][a-z0-9-]{1,62}")


def _target_wordlist(ctx, base_words: set, cap: int = 2000) -> list[str]:
    """A1d — build a TARGET-SPECIFIC label wordlist from what the crawl already mined.

    xnLinkFinder (run in the crawl phase over waymore responses + JS + recovered source) writes a
    `-owl` wordlist per input dir. Those files are the target's OWN vocabulary — product names,
    internal service names, path segments — the exact words a generic dictionary misses. Here we
    harvest every `*_wordlist.txt` xnLinkFinder produced, tokenize each entry into DNS-label pieces,
    keep only plausible labels (has a letter, len>=3, valid label chars — drops `v1`/`api`-vs-nothing
    noise and pure-numeric junk that would explode a brute), drop anything already in the base
    wordlist (no point re-brute-forcing dictionary words), dedup, and cap. Bounded by construction so
    the recursive brute load can't blow up. Empty when the crawl mined nothing."""
    wl_dir = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder"
    if not wl_dir.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for f in sorted(wl_dir.glob("*_wordlist.txt")):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            for piece in _LABEL_RX.findall(line.strip().lower()):
                if (len(piece) >= 3 and any(c.isalpha() for c in piece)
                        and piece not in base_words and piece not in seen):
                    seen.add(piece)
                    out.append(piece)
                    if len(out) >= cap:
                        return sorted(out)
    return sorted(out)


def _wildcard_differentiate(ctx, zones: set, *, extra_words=None,
                            phase: str = "vertical", label: str = "wildcard",
                            source: str = "wildcard-http") -> set[str]:
    """A1 — recover the distinct vhosts hidden behind a wildcard zone. A `*.zone` cert makes every
    `<word>.zone` resolve to one IP, so a DNS-gated pipeline strips them all as noise and loses the
    real hosts (CDN / k8s ingress / SaaS). Instead: brute `<word>.zone` + a couple of guaranteed-bogus
    baseline names, HTTP-probe them all, capture the wildcard's HTTP baseline (the bogus responses'
    status/length/title/favicon), and keep the candidates whose response DIFFERS from it — the real
    vhosts. Active + bounded (needs httpx + a wordlist). A non-wildcard zone yields no baseline response
    → nothing kept. Uses the label wordlist; the target-specific wordlist (A1d) folds in later."""
    import json as _json
    import uuid as _uuid
    scope = ctx.scope
    ZONE_CAP = 5
    _zones_all = sorted(z for z in zones if scope.in_scope(z) and not scope.is_oos(z))
    zones = _zones_all[:ZONE_CAP]
    if not zones or scope.passive_only or not have("httpx"):
        return set()                               # passive/no-httpx: no active pass -> no coverage counter
    from .probe import _vhost_wordlist          # small label list (lives in probe); DNS list is fallback
    wl = _vhost_wordlist() or _wordlist(ctx)
    if wl is None:
        return set()                               # no wordlist -> zero zones actually attempted; no counter
    block_private = netguard._block_private(ctx)
    words = [w.strip() for w in wl.read_text().splitlines()
             if w.strip() and not w.startswith("#")]
    # A1d: fold the target-specific words (mined from the crawl) IN FRONT so the target's own
    # naming vocabulary is tried first, then dedup + cap so brute load stays bounded.
    if extra_words:
        words = list(dict.fromkeys([w for w in extra_words if w] + words))
    words = words[:5000]

    def _sig(o):
        return (o.get("status_code"), o.get("content_length"),
                (o.get("title") or "").strip(), o.get("favicon"))

    kept: set[str] = set()
    zones_probed = 0
    for zone in zones:
        # self-attack guard: if the wildcard resolves to the SCAN BOX / metadata, don't vhost-scan the zone
        # (record it as intel). A private wildcard is CONTACTED by default (recorded either way).
        _wstate, _wdeny, _wintel = netguard.contact_state(f"quarry-wc-guard-{_uuid.uuid4().hex[:8]}.{zone}",
                                                          block_private=block_private)
        if _wintel:
            netguard.record_internal(ctx, f"*.{zone}", _wintel)
        if _wstate in ("self", "private_blocked"):
            continue
        zones_probed += 1
        bogus = [f"quarry-wc-{_uuid.uuid4().hex[:10]}.{zone}" for _ in range(2)]
        cf = ctx.write_list(f"{label}_cand_{zone.replace('.', '_')}.txt",
                            [f"{w}.{zone}" for w in words] + bogus)
        hx = ctx.run.raw_path(phase, label, f"{zone}.jsonl")
        # -follow-redirects so the signature is the FINAL response, not a bare redirect: without it a
        # candidate httpx probes on http gets the wildcard's uniform 308→https (status 308, len 0) —
        # which "differs" from the 200 baseline and floods false positives. Following it collapses
        # every noise candidate back onto the real baseline, leaving only the genuinely-distinct vhosts.
        hx_cmd = ["httpx", "-l", str(cf), "-json", "-silent", "-sc", "-cl", "-title",
                  "-favicon", "-follow-host-redirects",   # same-host only (http->https collapse), never off-scope
                  "-deny", netguard.self_deny_list(),     # never hit the scan box / metadata (private is contacted)
                  "-t", str(settings.workers("httpx", 15))]
        if ctx.profile.http_rl:                           # honor a configured HTTP rate
            hx_cmd += ["-rl", str(ctx.profile.http_rl)]
        r = exec_tool("httpx", hx_cmd, raw_path=hx, timeout=ctx.http_timeout)
        ctx.run.record(phase, r)
        if not (r.raw_path and r.raw_path.exists()):
            continue
        rows = []
        for line in r.raw_path.read_text().splitlines():
            try:
                rows.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
        base = {_sig(o) for o in rows if (o.get("input") or o.get("host") or "") in bogus}
        if not base:                            # bogus didn't respond → not a live wildcard → skip
            continue
        for o in rows:
            host = (o.get("input") or o.get("host") or "").lower().rstrip(".")
            if not host or host in bogus or not scope.in_scope(host) or scope.is_oos(host):
                continue
            if (o.get("status_code") or 0) // 100 == 3:   # un-followed redirect = infra noise, not a vhost
                continue
            if _sig(o) not in base:             # differs from the wildcard baseline → a REAL vhost
                if ctx.run.add("subdomain", {"host": host, "sources": [source],
                                             "raw_ref": str(hx)}):
                    ctx.run.add("resolved", {"host": host, "a": o.get("a") or [],
                                             "sources": [source], "raw_ref": str(hx)})
                    kept.add(host)
    # coverage AFTER filtering (audit #5): `tested` = zones ACTUALLY probed (safe candidates existed), so a
    # zone skipped for being internal / dnsx-missing is honestly counted as omitted, not tested.
    events.coverage_partial("vertical.wildcard_http", kind=events.COVERAGE_CAP, measure="zones",
                            eligible=len(_zones_all), tested=zones_probed,
                            omitted=max(0, len(_zones_all) - zones_probed),
                            reason=f"wildcard vhost zones {zones_probed}/{len(_zones_all)} probed "
                                   f"(cap {ZONE_CAP}; internal/unresolved zones skipped)")
    if kept:
        ctx.echo(f"  wildcard: +{len(kept)} distinct vhost(s) recovered via HTTP-differentiation ({label})")
    return kept


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    roots_file = ctx.write_list("roots.txt", prof.apex_domains)

    # ── passive: subfinder ──
    sf_raw = ctx.run.raw_path("vertical", "subfinder", "passive.txt")
    # `-all` = every configured source. NO `-recursive`: upstream defines it as "use ONLY sources that can
    # handle subdomains recursively" (verified subfinder v2.14.0 -h), so `-all -recursive` RESTRICTS to the
    # recursive-capable SUBSET and silently drops the other providers — a coverage loss (T1.2). Dropping it
    # runs all sources: the selected provider SET is a superset of the old recursive-only subset (observed
    # results can still vary run-to-run, as passive APIs do). A separate recursive pass seeded from NS/delegation
    # evidence is a later enhancement (needs the dns phase's records; running -recursive blind over all
    # roots adds nothing over -all). -stats prints per-source/API-key health to stderr (kept; captured).
    # C07: run under the authoritative contract (stable source_id + start/terminal events). The event layer
    # is additive — we still record the RunResult to the manifest below.
    r = run_contract("vertical.subfinder", ["subfinder", "-dL", str(roots_file), "-all",
                                            "-stats", "-silent"], raw_path=sf_raw, timeout=ctx.http_timeout)
    ctx.run.record("vertical", r)
    if r.raw_path:
        n = sum(ctx.run.add("subdomain", e) for e in
                normalize.hosts(r.raw_path.read_text(), "subfinder", str(sf_raw))
                if scope.in_scope(e["host"]))
        ctx.echo(f"  subfinder: +{n} in-scope ({r.stdout_lines} raw, {r.status.value})")

    # ── passive: CT-log sources (crt.sh free + certspotter) — coverage/resilience over subfinder ──
    # A `*.X.apex` wildcard cert name → register `X.apex` as a WILDCARD BRUTE-ZONE candidate (A1):
    # a DNS-gated pipeline resolves every `<word>.X.apex` to one IP and strips them as noise; A1
    # brutes the zone + HTTP-differentiates instead. wildcard_zones is fed by CT + censys below.
    wildcard_zones: set[str] = set()
    cs_token = secrets.certspotter()
    ct_new = 0
    for src, fn in (("crtsh", lambda a: _crtsh(a)),
                    ("certspotter", lambda a: _certspotter(a, cs_token))):
        hosts = set()
        for apex in prof.apex_domains:
            hosts |= fn(apex)
        if not hosts:
            continue
        raw = ctx.run.raw_path("vertical", src, "hosts.txt")
        raw.write_text("\n".join(sorted(hosts)) + "\n")
        for h in hosts:
            name = h[2:] if h.startswith("*.") else h        # `*.X.apex` → derived zone `X.apex`
            if not name or "." not in name or not scope.in_scope(name) or scope.is_oos(name):
                continue
            if h.startswith("*."):
                wildcard_zones.add(name)
            if ctx.run.add("subdomain", {"host": name, "sources": [src], "raw_ref": str(raw)}):
                ct_new += 1
    if ct_new:
        ctx.echo(f"  CT logs (crt.sh + certspotter): +{ct_new} in-scope")

    # ── passive: openintel-subs (ADVANCED — SILENT unless config.yaml `openintel:` set; secrets.yaml legacy) ──
    oi = settings.openintel()   # config.yaml (proper home) with secrets.yaml back-compat
    if oi.get("binary") and oi.get("db"):
        oi_hosts = set()
        for apex in prof.apex_domains:
            oi_hosts |= _openintel(ctx, oi, apex)
        if oi_hosts:
            raw = ctx.run.raw_path("vertical", "openintel", "hosts.txt")
            raw.write_text("\n".join(sorted(oi_hosts)) + "\n")
            n = sum(ctx.run.add("subdomain", {"host": h, "sources": ["openintel"], "raw_ref": str(raw)})
                    for h in oi_hosts if scope.in_scope(h) and not scope.is_oos(h))
            if n:
                ctx.echo(f"  openintel: +{n} in-scope (local top1M subs DB)")

    # ── passive: Censys Platform cert search (OPTIONAL — SILENT unless secrets.yaml `censys:` set) ──
    cen = secrets.censys()
    if cen.get("token") and cen.get("org"):
        cen_hosts = set()
        for apex in prof.apex_domains:
            cen_hosts |= _censys(cen, apex)
        if cen_hosts:
            raw = ctx.run.raw_path("vertical", "censys", "hosts.txt")
            raw.write_text("\n".join(sorted(cen_hosts)) + "\n")
            n = 0
            for h in cen_hosts:
                name = h[2:] if h.startswith("*.") else h
                if not name or "." not in name or not scope.in_scope(name) or scope.is_oos(name):
                    continue
                if h.startswith("*."):
                    wildcard_zones.add(name)                  # A1: censys wildcard cert → brute-zone
                if ctx.run.add("subdomain", {"host": name, "sources": ["censys"], "raw_ref": str(raw)}):
                    n += 1
            if n:
                ctx.echo(f"  censys: +{n} in-scope (Platform cert search)")

    # ── passive: github-subdomains (optional, needs token) ──
    gh_token = secrets.github_tokens_file()   # 0600 temp file from secrets.yaml; None if unset
    if gh_token:
        try:
            for d in prof.apex_domains:
                r = exec_tool("github-subdomains",
                        ["github-subdomains", "-d", d, "-t", str(gh_token)],
                        raw_path=ctx.run.raw_path("vertical", "github-subdomains", f"{d}.txt"),
                        timeout=ctx.http_timeout)
                ctx.run.record("vertical", r)
                if r.raw_path:
                    for e in normalize.hosts(r.raw_path.read_text(), "github-subdomains", str(r.raw_path)):
                        if scope.in_scope(e["host"]):
                            ctx.run.add("subdomain", e)
        finally:
            gh_token.unlink(missing_ok=True)
    else:
        ctx.run.record("vertical", skipped("github-subdomains",
                       "no GitHub token in secrets.yaml"))

    # ── shosubgo (Shodan subs, optional, needs key) ──
    sho_key = secrets.shodan()
    if have("shosubgo") and sho_key:
        sho = ctx.run.raw_path("vertical", "shosubgo", "sho.txt")
        sho.unlink(missing_ok=True)                    # stale artifact must not fake completion
        # `-fail` (verified upstream main.go): exit 1 on ANY API error (invalid/rate-limited key). WITHOUT
        # it, an auth error just prints to stderr and the run exits 0 -> looks like a clean-empty result
        # (false-negative). With it, the error surfaces as FAILED and the file-output adapter keeps it hard.
        # shosubgo writes to the -o FILE, not stdout. Reclassify (status-only) INSIDE the contract so the
        # terminal event carries the FINAL status; the ingest below re-reads the file (fail-closed, cheap).
        def _sho_reclassify(res):
            hosts, artifact_ok = _shosubgo_read(sho)
            reclassify_from_artifact(res, None if hosts is None else len(hosts), label="shosubgo")
            # a clean-EXIT run whose artifact had malformed lines / bad UTF-8 is NOT a trustworthy clean
            # result: downgrade to PARTIAL (completion uncertain) while KEEPING the valid hosts.
            if not artifact_ok and res.status in (Status.SUCCESS, Status.EMPTY):
                res.status = Status.PARTIAL
                res.note = f"shosubgo: {len(hosts or [])} host(s) — artifact had malformed lines, completion uncertain"
            return res
        r = run_contract("vertical.shosubgo", ["shosubgo", "-f", str(roots_file),
                                               "-s", sho_key, "-o", str(sho), "-fail"],
                         reclassify=_sho_reclassify, timeout=ctx.http_timeout)
        ctx.run.record("vertical", r)
        hosts, _ = _shosubgo_read(sho)                  # re-read for ingest (392 names were dropped when unread)
        for e in (hosts or []):
            if scope.in_scope(e["host"]):
                ctx.run.add("subdomain", e)

    # ── brute force (puredns) ──
    resolvers, trusted = _resolvers(ctx)
    wl = _wordlist(ctx)
    if scope.passive_only:
        ctx.run.record("vertical", skipped("puredns", "passive-only mode"))
    elif wl is None:
        ctx.run.record("vertical", skipped("puredns",
                       "no DNS wordlist (~/.config/quarry/wordlists/dns.txt) — brute skipped"))
        ctx.run.notes.append("vertical: DNS brute skipped, no wordlist")
    else:
        for d in prof.apex_domains:
            cmd = ["puredns", "bruteforce", str(wl), d, "--resolvers-trusted", str(trusted), "-q"]
            if resolvers:
                cmd += ["-r", str(resolvers)]
            if prof.dns_rate:
                cmd += ["--rate-limit", str(prof.dns_rate)]
            br = ctx.run.raw_path("vertical", "puredns", f"brute-{d}.txt")
            r = exec_tool("puredns", cmd, raw_path=br, timeout=ctx.http_timeout)
            ctx.run.record("vertical", r)
            if r.raw_path:
                for e in normalize.hosts(r.raw_path.read_text(), "puredns-brute", str(br)):
                    if scope.in_scope(e["host"]):
                        ctx.run.add("subdomain", e)

    # ── recursive permute → resolve loop (word-cloud mutations) ──
    # Recursive enumeration: each iteration enriches + mines target-specific permutation patterns
    # (alterx -enrich -mode both) from the GROWING known set, resolves, and feeds newly-resolved hosts back
    # as seeds. Stops when an iteration finds nothing new.
    # C20 (T2.3) frontier-only RESOLVE: resolve a candidate only until it is SETTLED, not once per iteration.
    # The old loop re-resolved the ENTIRE candidate set every iteration (OTC: ~9.9M candidate lines / 10M
    # massdns rows for 8 net additions) — mostly re-resolution of already-settled names. Here a candidate is
    # settled (added to `seen_candidates`, never re-submitted) only after a CLEAN puredns batch resolves the
    # batch it was in; a DEGRADED batch settles just its confirmed-resolved names and RE-SUBMITS the rest
    # next iteration (bounded by MAX_ITERS). NOTE: the resolved-union equality with the old blanket
    # re-resolution rests on the assumption that a CLEAN puredns batch has no transient false-negatives that
    # would flip on a re-submit — this is validated by benchmark (measure-don't-guess), not set arithmetic.
    # alterx STILL runs over the full known set (its -enrich word cloud is mined from ALL observed names —
    # feeding it only the frontier would shrink the vocabulary and LOSE cross-pollinated permutations).
    MAX_ITERS = 3
    prev = -1
    seen_candidates: set[str] = set()
    for it in range(1, MAX_ITERS + 1):
        seed = sorted(set(ctx.run.values("subdomain") + prof.apex_domains
                          + ctx.run.values("resolved")))
        known = ctx.write_list(f"known_{it}.txt", seed)
        cand = list(seed)

        # word-cloud permutations (active only): -enrich extracts words from observed names,
        # -mode both adds default + target-mined patterns. Runs over the FULL known set (word cloud).
        if not scope.passive_only and have("alterx"):
            perms = ctx.run.raw_path("vertical", "alterx", f"perms_{it}.txt")
            r = exec_tool("alterx", ["alterx", "-l", str(known), "-enrich", "-mode", "both",
                                     "-silent"], raw_path=perms, timeout=600)
            ctx.run.record("vertical", r)
            if perms.exists():
                cand += perms.read_text().splitlines()

        if scope.passive_only:
            # PASSIVE = no target contact. `dnsx -a` resolves candidates against the target's DNS, so it
            # is skipped: passively-discovered subdomain names are already stored (CT/subfinder/etc above);
            # we simply don't resolve them to A records here. Honest skip, then stop (no active growth).
            ctx.run.record("vertical", skipped("dnsx", "passive-only mode — no recursive DNS resolution"))
            break

        # frontier-only: resolve only candidates NOT already ATTEMPTED-AND-SETTLED (dedup, first-seen order).
        new_cand = [c for c in dict.fromkeys(cand) if c and c not in seen_candidates]
        _n_all, _n_new = len(set(filter(None, cand))), len(new_cand)
        if not new_cand:
            ctx.echo(f"  recursion iter {it}: no new candidates — converged")
            break
        candidates = ctx.write_list(f"all_candidates_{it}.txt", new_cand)
        res = ctx.run.raw_path("vertical", "puredns", f"resolved_{it}.txt")
        # --write-massdns captures the A records so `resolved` carries its IPs (was a:[] — puredns
        # -q emits hostnames only, leaving the host→IP edge to live solely in dns_record; the digest
        # and the v0.4 relationship layer both want it on `resolved`).
        md = ctx.run.raw_path("vertical", "puredns", f"resolved_{it}.massdns")
        cmd = ["puredns", "resolve", str(candidates), "--resolvers-trusted", str(trusted),
               "--write-massdns", str(md), "-q"]
        if resolvers:
            cmd += ["-r", str(resolvers)]
        if prof.dns_rate:
            cmd += ["--rate-limit", str(prof.dns_rate)]
        r = exec_tool("puredns", cmd, raw_path=res, timeout=ctx.http_timeout)
        if _n_all != _n_new:                              # dedup SAVINGS is optimization telemetry, NOT a gap
            r.note = (f"frontier: {_n_new} new candidate(s), {_n_all - _n_new} already-settled skipped; "
                      f"{r.note or ''}").strip()
        ctx.run.record("vertical", r)
        resolved_now: set[str] = set()
        if r.raw_path:
            ips = _massdns_a(md)                # host -> [A records]
            for e in normalize.hosts(r.raw_path.read_text(), "puredns-resolve", str(res)):
                resolved_now.add(e["host"])     # every resolved name (in/out of scope) is settled
                if scope.in_scope(e["host"]):
                    ctx.run.add("resolved", {"host": e["host"], "a": ips.get(e["host"], []),
                                             "sources": ["puredns-resolve"], "raw_ref": str(res)})
                    # newly-resolved permutations are new subdomains → seed next iteration
                    ctx.run.add("subdomain", {"host": e["host"], "sources": ["puredns-resolve"]})
        # SETTLE candidates only when the batch is trustworthy: a CLEAN puredns run resolves every attempted
        # candidate (an unresolved name won't resolve later within the run), so mark ALL new_cand seen. A
        # DEGRADED batch (timeout/error/partial) settles ONLY the confirmed-resolved names — its UNRESOLVED
        # candidates stay retryable so a transient resolver failure is re-attempted next iteration (bounded
        # by MAX_ITERS). This preserves set-equality of the RESOLVED union with the old blanket re-resolution.
        if r.status in (Status.SUCCESS, Status.EMPTY):
            seen_candidates.update(new_cand)
        else:
            seen_candidates.update(resolved_now)
            retryable = len(set(new_cand) - resolved_now)
            _budget = "retry budget exhausted (final iteration)" if it == MAX_ITERS else "retryable next iteration"
            events.coverage_partial("vertical.puredns_resolve", reason=f"iter {it}: puredns {r.status.value} — "
                                    f"{retryable} candidate(s) unresolved, {_budget}")

        cur = ctx.run.count("resolved")
        ctx.echo(f"  recursion iter {it}: resolved={cur}"
                 + ("" if prev < 0 else f" (+{cur - prev} new)"))
        if prev >= 0 and cur == prev:
            break          # converged — nothing new this iteration
        prev = cur

    # ── A1: wildcard-zone brute + HTTP-differentiation (recover distinct vhosts a wildcard hides) ──
    # Runs before the CNAME/takeover pass so recovered vhosts get takeover analysis too.
    # Persist the derived zones so the post-crawl A1d recursion (enrich) can re-brute them with the
    # target-specific wordlist — enrich runs after crawl, where the target vocabulary is mined.
    for _z in sorted(wildcard_zones):
        ctx.run.add("wildcard_zone", {"value": _z})
    _wildcard_differentiate(ctx, wildcard_zones)

    # ── CNAME collection for subdomain-takeover analysis (workflow 1.13) ──
    if prof.takeover and scope.passive_only:
        # `dnsx -cname -a` resolves against the target's DNS — target contact, so skip in passive mode.
        ctx.run.record("vertical", skipped("dnsx", "passive-only mode — CNAME/takeover resolution skipped"))
    elif prof.takeover and have("dnsx"):
        # Scan the UNION of resolved + all known subdomains — not "resolved or subdomain".
        # A dangling CNAME (host with a CNAME but no A record of its own) is exactly the
        # takeover signal, and it lives in `subdomain`, never in `resolved`. The old
        # short-circuit dropped every dangling host whenever any host A-resolved.
        all_known = sorted(set(ctx.run.values("resolved")) | set(ctx.run.values("subdomain")))
        res_hosts = ctx.write_list("resolved_hosts.txt", all_known)
        cn = ctx.run.raw_path("vertical", "dnsx", "cnames.jsonl")
        # -a so each result carries the host's A records: dangling = has CNAME but no A in THIS
        # result. (Not "host not in resolved" — a no-A CNAME host can still get a `resolved`
        # entity with a:[], which would wrongly clear the takeover flag.)
        r = exec_tool("dnsx", ["dnsx", "-l", str(res_hosts), "-cname", "-a", "-json", "-silent"],
                      raw_path=cn, timeout=ctx.http_timeout)
        ctx.run.record("vertical", r)
        if r.raw_path:
            n = ntk = 0
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
                    n += 1
                    if dangling:
                        ntk += 1
            tk = f", {ntk} dangling → takeover candidate" if ntk else ""
            ctx.echo(f"  cnames: {n}{tk} (takeover analysis in params phase)")

    ctx.echo(f"  subdomains: {ctx.run.count('subdomain')}  resolved: {ctx.run.count('resolved')}")
