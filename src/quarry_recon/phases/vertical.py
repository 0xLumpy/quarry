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

from .. import normalize, secrets
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
    return {m.lower().lstrip("*.").rstrip(".") for m in pat.findall(raw) if "." in m}


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
            h = nv.strip().lower().lstrip("*.").rstrip(".")
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
            h = str(h).strip().lower().lstrip("*.").rstrip(".")
            if h and "." in h:
                hosts.add(h)
    return hosts


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
    for p in (home / ".config/quarry/dns-wordlist.txt",
              home / "wordlists/best-dns-wordlist.txt",
              home / "wordlists/subdomains.txt"):
        if p.exists():
            return p
    return None


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
        ct_new += sum(ctx.run.add("subdomain", {"host": h, "sources": [src], "raw_ref": str(raw)})
                      for h in hosts if scope.in_scope(h) and not scope.is_oos(h))
    if ct_new:
        ctx.echo(f"  CT logs (crt.sh + certspotter): +{ct_new} in-scope")

    # ── passive: openintel-subs (ADVANCED — SILENT unless secrets.yaml `openintel:` is configured) ──
    oi = secrets.openintel()
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
            n = sum(ctx.run.add("subdomain", {"host": h, "sources": ["censys"], "raw_ref": str(raw)})
                    for h in cen_hosts if scope.in_scope(h) and not scope.is_oos(h))
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
                       "no DNS wordlist (~/.config/quarry/dns-wordlist.txt) — brute skipped"))
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
            cmd = ["puredns", "resolve", str(candidates), "--resolvers-trusted", str(trusted), "-q"]
            if resolvers:
                cmd += ["-r", str(resolvers)]
            if prof.dns_rate:
                cmd += ["--rate-limit", str(prof.dns_rate)]
            r = exec_tool("puredns", cmd, raw_path=res, timeout=ctx.http_timeout)
            ctx.run.record("vertical", r)
            if r.raw_path:
                for e in normalize.hosts(r.raw_path.read_text(), "puredns-resolve", str(res)):
                    if scope.in_scope(e["host"]):
                        ctx.run.add("resolved", {"host": e["host"], "a": [],
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
            import json as _json
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
