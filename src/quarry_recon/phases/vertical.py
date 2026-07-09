"""Phase 3: Vertical subdomain discovery.

passive (subfinder -all -recursive) + github-subdomains -> brute (puredns) ->
permutations (alterx/dnsgen) -> trusted-resolver validation. Records source deltas so
a human can spot "one source found many another missed" (methodology day1).
"""
from __future__ import annotations

import json as _json
import os
import re as _re
import shutil
import subprocess
import urllib.request
from pathlib import Path

from .. import normalize, secrets, settings
from ..runner import Status, have, run as exec_tool, skipped


def _openintel(cfg: dict, apex: str, timeout: int = 180) -> set:
    """ADVANCED optional passive source: query a local openintel-subs binary + subs.db for `apex`.
    Returns an empty set (SILENT) unless both paths are configured AND present — no noise otherwise.
    Best-effort: any failure returns an empty set and never breaks the run."""
    binary, db = cfg.get("binary"), cfg.get("db")
    if not binary or not db:
        return set()
    exe = shutil.which(binary) or (binary if os.path.isfile(binary) and os.access(binary, os.X_OK) else None)
    if not exe or not os.path.isfile(db):
        return set()
    try:
        p = subprocess.run([exe, "query", "-d", apex, "-s", "-b", db],
                           capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        out = p.stdout.decode("utf-8", "replace")
    except Exception:
        return set()
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
    zones = sorted(z for z in zones if scope.in_scope(z) and not scope.is_oos(z))[:5]
    if not zones or scope.passive_only or not have("httpx"):
        return set()
    from .probe import _vhost_wordlist          # small label list (lives in probe); DNS list is fallback
    wl = _vhost_wordlist() or _wordlist(ctx)
    if wl is None:
        return set()
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
    for zone in zones:
        bogus = [f"quarry-wc-{_uuid.uuid4().hex[:10]}.{zone}" for _ in range(2)]
        cf = ctx.write_list(f"{label}_cand_{zone.replace('.', '_')}.txt",
                            [f"{w}.{zone}" for w in words] + bogus)
        hx = ctx.run.raw_path(phase, label, f"{zone}.jsonl")
        # -follow-redirects so the signature is the FINAL response, not a bare redirect: without it a
        # candidate httpx probes on http gets the wildcard's uniform 308→https (status 308, len 0) —
        # which "differs" from the 200 baseline and floods false positives. Following it collapses
        # every noise candidate back onto the real baseline, leaving only the genuinely-distinct vhosts.
        r = exec_tool("httpx", ["httpx", "-l", str(cf), "-json", "-silent", "-sc", "-cl", "-title",
                                "-favicon", "-follow-redirects",
                                "-t", str(settings.workers("httpx", 15))],
                      raw_path=hx, timeout=ctx.http_timeout)
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
    if kept:
        ctx.echo(f"  wildcard: +{len(kept)} distinct vhost(s) recovered via HTTP-differentiation ({label})")
    return kept


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    roots_file = ctx.write_list("roots.txt", prof.apex_domains)

    # ── passive: subfinder ──
    sf_raw = ctx.run.raw_path("vertical", "subfinder", "passive.txt")
    # -stats prints per-source/API-key health to stderr (captured in stderr_tail)
    r = exec_tool("subfinder", ["subfinder", "-dL", str(roots_file), "-all", "-recursive",
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
            oi_hosts |= _openintel(oi, apex)
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
        r = exec_tool("shosubgo", ["shosubgo", "-f", str(roots_file),
                                   "-s", sho_key, "-o", str(sho)], timeout=ctx.http_timeout)
        ctx.run.record("vertical", r)
        if r.raw_path:
            for e in normalize.hosts(r.raw_path.read_text(), "shosubgo", str(sho)):
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
    # Recursive enumeration: each iteration enriches + mines target-specific
    # permutation patterns (alterx -enrich -mode both) from the GROWING known set, resolves,
    # and feeds newly-resolved hosts back as seeds. Stops when an iteration finds nothing new.
    MAX_ITERS = 3
    prev = -1
    for it in range(1, MAX_ITERS + 1):
        seed = sorted(set(ctx.run.values("subdomain") + prof.apex_domains
                          + ctx.run.values("resolved")))
        known = ctx.write_list(f"known_{it}.txt", seed)
        cand = list(seed)

        # word-cloud permutations (active only): -enrich extracts words from observed names,
        # -mode both adds default + target-mined patterns.
        if not scope.passive_only and have("alterx"):
            perms = ctx.run.raw_path("vertical", "alterx", f"perms_{it}.txt")
            r = exec_tool("alterx", ["alterx", "-l", str(known), "-enrich", "-mode", "both",
                                     "-silent"], raw_path=perms, timeout=600)
            ctx.run.record("vertical", r)
            if perms.exists():
                cand += perms.read_text().splitlines()

        candidates = ctx.write_list(f"all_candidates_{it}.txt", cand)

        if scope.passive_only:
            res = ctx.run.raw_path("vertical", "dnsx", f"resolved_{it}.txt")
            r = exec_tool("dnsx", ["dnsx", "-l", str(candidates), "-a", "-resp", "-json",
                                   "-silent"], raw_path=res, timeout=ctx.http_timeout)
            ctx.run.record("vertical", r)
            if r.raw_path:
                for e in normalize.dnsx_resolved(r.raw_path.read_text(), "dnsx", str(res)):
                    if scope.in_scope(e["host"]):
                        ctx.run.add("resolved", e)
                        ctx.run.add("subdomain", {"host": e["host"], "sources": ["dnsx-resolved"]})
        else:
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
            ctx.run.record("vertical", r)
            if r.raw_path:
                ips = _massdns_a(md)                # host -> [A records]
                for e in normalize.hosts(r.raw_path.read_text(), "puredns-resolve", str(res)):
                    if scope.in_scope(e["host"]):
                        ctx.run.add("resolved", {"host": e["host"], "a": ips.get(e["host"], []),
                                                 "sources": ["puredns-resolve"], "raw_ref": str(res)})
                        # newly-resolved permutations are new subdomains → seed next iteration
                        ctx.run.add("subdomain", {"host": e["host"], "sources": ["puredns-resolve"]})

        cur = ctx.run.count("resolved")
        ctx.echo(f"  recursion iter {it}: resolved={cur}"
                 + ("" if prev < 0 else f" (+{cur - prev} new)"))
        if prev >= 0 and cur == prev:
            break          # converged — nothing new this iteration
        prev = cur
        if scope.passive_only:
            break          # no permutation growth without active alterx

    # ── A1: wildcard-zone brute + HTTP-differentiation (recover distinct vhosts a wildcard hides) ──
    # Runs before the CNAME/takeover pass so recovered vhosts get takeover analysis too.
    # Persist the derived zones so the post-crawl A1d recursion (enrich) can re-brute them with the
    # target-specific wordlist — enrich runs after crawl, where the target vocabulary is mined.
    for _z in sorted(wildcard_zones):
        ctx.run.add("wildcard_zone", {"value": _z})
    _wildcard_differentiate(ctx, wildcard_zones)

    # ── CNAME collection for subdomain-takeover analysis (workflow 1.13) ──
    if prof.takeover and have("dnsx"):
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
