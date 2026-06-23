"""Phase 3: Vertical subdomain discovery.

passive (subfinder -all -recursive) + github-subdomains -> brute (puredns) ->
permutations (alterx/dnsgen) -> trusted-resolver validation. Records source deltas so
a human can spot "one source found many another missed" (methodology day1).
"""
from __future__ import annotations

from pathlib import Path

from .. import normalize, secrets
from ..runner import Status, have, run as exec_tool, skipped


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
        res_hosts = ctx.write_list("resolved_hosts.txt",
                                   ctx.run.values("resolved") or ctx.run.values("subdomain"))
        cn = ctx.run.raw_path("vertical", "dnsx", "cnames.jsonl")
        r = exec_tool("dnsx", ["dnsx", "-l", str(res_hosts), "-cname", "-json", "-silent"],
                      raw_path=cn, timeout=ctx.http_timeout)
        ctx.run.record("vertical", r)
        if r.raw_path:
            import json as _json
            n = 0
            for line in r.raw_path.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                for c in (o.get("cname") or []):
                    ctx.run.add("review", {"id": f"cname:{o.get('host')}->{c}", "klass": "cname",
                                           "value": f"{o.get('host')} -> {c}", "host": o.get("host"),
                                           "cname": c, "sources": ["dnsx"]})
                    n += 1
            ctx.echo(f"  cnames: {n} (takeover analysis in params phase)")

    ctx.echo(f"  subdomains: {ctx.run.count('subdomain')}  resolved: {ctx.run.count('resolved')}")
