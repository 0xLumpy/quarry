"""Phase 4: Probe / fingerprint / screenshots / ports.

httpx json (source of truth for live services) with the methodology's full flag set
(follow-host-redirects, asn, location, random-agent) at RoE rate limit + full-monty ports;
gowitness screenshots; naabu ports → nmap -sV service detection (only on in-scope CIDR);
optional smap passive (Shodan-backed) port scan.
"""
from __future__ import annotations

import ipaddress as _ipaddr
import json as _json
import re as _re
import urllib.parse
import urllib.request

from .. import normalize, secrets, settings
from ..runner import (Status, have, nuclei_timeout, reclassify_from_files, run as exec_tool,
                      scaled_timeout, skipped)

# Serialized-object / token markers that surface in Set-Cookie + response headers. Spotting the
# FORMAT is PASSIVE recon evidence (a hand-off to the attack layer), never exploitation. Only
# distinctive markers are used — pickle (`gAR`) / Ruby-Marshal (`BAg`) base64 prefixes are too
# collision-prone from a raw header string to include without noise. Source: TBHM cheatsheet §9.
_DESER_MARKERS = (
    ("java-serialized", "rO0AB"),            # ObjectOutputStream AC ED 00 05 → base64
    ("dotnet-binaryformatter", "AAEAAAD"),   # 00 01 00 00 00 FF FF FF FF → base64 AAEAAAD/////
    ("node-serialize", "_$$ND_FUNC$$_"),     # node-serialize function marker
)
_PHP_OBJ_RX = _re.compile(r'O:\d+:"[A-Za-z0-9_\\]+":')          # PHP serialize() object in a cookie
_JWT_RX = _re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def _shodan_pivot(ctx, key, values, facet, source, label, note) -> int:
    """Generic Shodan search pivot: for each value, query `<facet>:<value>` and turn the matching
    hosts' hostnames into in-scope subdomains (coverage) or bounded off-scope related-host review
    candidates (verify-ownership). Generic collisions (huge result count) are skipped as noise, and
    each pivot is bounded. `label`/`note` are `{}`-formatted with the value for provenance/context.
    Returns the count of new in-scope subdomains. Passive OSINT query — no target contact."""
    scope = ctx.scope
    new_sub = 0
    for v in sorted({str(x) for x in values if x})[:20]:
        try:
            url = (f"https://api.shodan.io/shodan/host/search?key={key}"
                   f"&query={urllib.parse.quote(f'{facet}:{v}')}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = _json.loads(r.read(4 * 1024 * 1024).decode("utf-8", "replace"))
        except Exception:
            continue
        if (data.get("total") or 0) > 200:              # too-generic → skip (collision noise)
            continue
        raw = ctx.run.raw_path("probe", label, f"{_re.sub(r'[^A-Za-z0-9]', '_', v)[:32]}.json")
        raw.write_text(_json.dumps(data.get("matches") or [])[:2 * 1024 * 1024])
        oos = 0
        for m in (data.get("matches") or [])[:100]:
            for hn in (m.get("hostnames") or []):
                hn = str(hn).lower().rstrip(".")
                if not hn or "." not in hn:
                    continue
                if scope.in_scope(hn) and not scope.is_oos(hn):
                    if ctx.run.add("subdomain", {"host": hn, "sources": [source],
                                                 "raw_ref": str(raw)}):
                        new_sub += 1
                elif oos < 15:                          # bounded off-scope related-host candidates
                    if ctx.run.add("review", {"id": f"{label}:{v}:{hn}", "klass": "related-host",
                            "value": hn, "note": note.format(v), "sources": [source],
                            "raw_ref": str(raw)}):
                        oos += 1
    return new_sub


def _favicon_pivot(ctx) -> None:
    """Shodan favicon-hash pivot: httpx already computed each live host's favicon mmh3 hash; search
    Shodan `http.favicon.hash:<h>` for hosts serving the SAME favicon → related infrastructure.
    Key-gated (silent without a shodan key)."""
    key = secrets.shodan()
    if not key:
        return
    n = _shodan_pivot(ctx, key,
                      (l.get("favicon") for l in ctx.run.read("live") if l.get("favicon")),
                      "http.favicon.hash", "favicon-shodan", "favicon",
                      "same favicon (hash {}) as an in-scope host — VERIFY OWNERSHIP")
    if n:
        ctx.echo(f"  favicon: +{n} in-scope host(s) via Shodan favicon-hash pivot")


def _cert_pivot(ctx) -> None:
    """Shodan cert-fingerprint pivot (karma-style): tlsx recorded each cert's SHA1 fingerprint;
    search Shodan `ssl.cert.fingerprint:<sha1>` for hosts presenting the SAME leaf certificate →
    shared/related infrastructure. Key-gated (silent without a shodan key)."""
    key = secrets.shodan()
    if not key:
        return
    n = _shodan_pivot(ctx, key,
                      (c.get("sha1") for c in ctx.run.read("certificate") if c.get("sha1")),
                      "ssl.cert.fingerprint", "cert-shodan", "cert",
                      "same TLS cert (sha1 {}) as an in-scope host — VERIFY OWNERSHIP")
    if n:
        ctx.echo(f"  cert: +{n} in-scope host(s) via Shodan cert-fingerprint pivot")


def _vhost_wordlist():
    """Locate a DEDICATED vhost wordlist (small, label-per-line). We deliberately do NOT fall back to
    the big DNS brute list — vhost fuzzing is IPs×apexes×words, so an unbounded list is a footgun.
    None → the step records a skip (opt-in by dropping a list at one of these paths)."""
    from pathlib import Path
    home = Path.home()
    for p in (home / ".config/quarry/wordlists/vhost.txt",     # canonical (clean layout)
              home / ".config/quarry/vhost-wordlist.txt",      # back-compat (pre-reorg installs)
              home / "wordlists/vhosts.txt", home / "wordlists/subdomains-top1million-5000.txt"):
        if p.exists():
            return p
    return None


def _vhost_enum(ctx) -> None:
    """Virtual-host enumeration (ffuf `-H 'Host: FUZZ.<apex>'`): an origin frequently serves name-based
    vhosts that DON'T resolve in public DNS (staging/internal/legacy/pre-prod). We fuzz the Host header
    against a REPRESENTATIVE live URL of each non-CDN origin — NOT `http://<ip>/`. A bare-IP request
    fails on HTTPS/redirecting origins: Caddy/CDN answers port 80 with a uniform redirect that `-ac`
    folds to nothing, and a bare-IP TLS handshake fails SNI. Connecting via a real live host (valid
    scheme + SNI + cert) still reaches the same origin, and the overridden Host header surfaces the
    DNS-invisible vhosts. `-ac` drops the catch-all so a distinct response stands out. Hits are `vhost`
    review candidates (a 200 isn't proof the name resolves/is owned — human verifies). Active; needs
    ffuf + a vhost wordlist. Origins de-duped by IP so each is fuzzed once.

    Only DNS-INVISIBLE hits are surfaced — a vhost that's already a known subdomain is dropped (the
    signal is names that DON'T resolve). Base URL is chosen HTTPS-first + subdomain-first (the apex is
    often a separate static site). Matching is the "served/exists" set (2xx/3xx/401/403) + `-ac` (drops
    the catch-all baseline) — broader than a bare 200/301, but a 404/5xx means the Host isn't served so
    it's excluded. Redirects are NOT followed (no `-r`): a vhost that 30x's is already a hit via `-mc`
    (3xx matched) and `-ac` folds a uniform catch-all by response SIZE whether or not we follow — so we
    classify on the 3xx itself and never chase a Location cross-host / off-scope."""
    if not have("ffuf"):
        return
    wl = _vhost_wordlist()
    if wl is None:
        ctx.run.record("probe", skipped("ffuf-vhost",
                       "no vhost wordlist (~/.config/quarry/wordlists/vhost.txt) — vhost enum skipped"))
        return
    scope, prof = ctx.scope, ctx.profile
    # BEST connection URL per non-CDN origin IP (co-hosted names fuzz once). Prefer HTTPS (valid SNI,
    # no port-80 redirect dance) and a SUBDOMAIN host — the bare apex is often a SEPARATE static site,
    # not the vhost-routing app, so fuzzing it misses the app's vhosts. score = https(2) + subdomain(1).
    apexset = {a.lower() for a in prof.apex_domains}
    best: dict[str, tuple[int, str]] = {}
    for l in ctx.run.read("live"):
        if l.get("cdn"):
            continue
        url = (l.get("url") or "").strip()
        m = _re.match(r"(?i)(https?://[^/]+)", url)
        host = normalize.host_of_url(url)
        if not m or not scope.active_allowed(host):
            continue
        score = (2 if url.lower().startswith("https://") else 0) + (1 if host not in apexset else 0)
        key = str((l.get("a") or [None])[0] or host)   # origin identity (IP preferred, else host)
        if key not in best or score > best[key][0]:
            best[key] = (score, m.group(1))
    origins = {k: v[1] for k, v in list(best.items())[:25]}
    if not origins:
        ctx.run.record("probe", skipped("ffuf-vhost", "no non-CDN origin live hosts to fuzz"))
        return
    # a vhost that's ALREADY a known subdomain isn't the signal — vhost enum's value is the
    # DNS-INVISIBLE hosts. Filter results against everything we already discovered.
    known = set(ctx.run.values("subdomain")) | set(ctx.run.values("resolved"))
    apexes = [a for a in prof.apex_domains if scope.in_scope(a)]
    found = 0
    # per-call ceiling scaled by wordlist size (each ffuf fuzzes one origin×apex over the vhost list);
    # the flat 1800s cut a big-wordlist run. Higher -t (I/O-bound concurrency) makes each call faster.
    wl_n = sum(1 for _ in wl.open())
    ffuf_to = scaled_timeout(wl_n, ctx.http_timeout, per_unit=0.4)
    for origin, base in origins.items():
        for apex in apexes:
            out = ctx.run.raw_path("probe", "ffuf-vhost", f"{origin}_{apex}.json")
            # -mc = "served/exists" (2xx/3xx/401/403), NOT `all`: a 404/5xx means the origin does NOT
            # serve that Host, so it isn't a vhost. -ac drops the catch-all baseline. NO -r: a redirecting
            # vhost is matched on its 3xx (in -mc) and -ac folds a uniform catch-all by size regardless —
            # so we never follow a Location to another (possibly off-scope) host.
            cmd = ["ffuf", "-w", f"{wl}:FUZZ", "-H", f"Host: FUZZ.{apex}",
                   "-u", f"{base}/", "-ac", "-timeout", "7",
                   "-t", str(settings.workers("ffuf", 40)), "-s",
                   "-mc", "200-299,301,302,303,307,308,401,403",
                   "-o", str(out), "-of", "json"]
            if prof.http_rl:
                cmd += ["-rate", str(prof.http_rl)]
            r = exec_tool("ffuf", cmd, timeout=ffuf_to)
            ctx.run.record("probe", r)
            if not out.exists():
                continue
            try:
                res = _json.loads(out.read_text()).get("results") or []
            except Exception:
                continue
            for hit in res:
                word = (hit.get("input") or {}).get("FUZZ") or ""
                host = f"{word.lower().strip('.')}.{apex}" if word else ""
                if not host or "." not in host or not scope.in_scope(host) or host in known:
                    continue                           # skip junk + already-known subs (DNS-invisible only)
                if ctx.run.add("review", {"id": f"vhost:{origin}:{host}", "klass": "vhost",
                        "value": host, "host": host, "ip": origin,
                        "status_code": hit.get("status"),
                        "note": f"origin {origin} serves vhost {host} (may not resolve in DNS) — VERIFY",
                        "sources": ["ffuf-vhost"], "raw_ref": str(out)}):
                    found += 1
    if found:
        ctx.echo(f"  vhost: {found} name-based vhost candidate(s) via Host-header fuzz (ffuf)")


def _httpx_probe_cmd(hosts_file, ports, http_rl) -> list[str]:
    """The shared httpx fingerprint command (v0.3.4 discipline: NO -probe-all-ips / -no-fallback
    multipliers, bounded -timeout/-retries; rich response-derived flags kept — they cost only on hosts
    that answer). Used by the bulk probe, every prefilter port-group, the direct fallback, and enrich."""
    cmd = ["httpx", "-l", str(hosts_file), "-json", "-silent",
           "-ports", ",".join(str(p) for p in ports),
           "-td", "-title", "-sc", "-cl", "-favicon", "-cdn", "-web-server",
           "-asn", "-location", "-ip", "-cname", "-irh",
           # -follow-host-redirects (NOT -follow-redirects): follow only SAME-HOST 30x (http->https on the
           # same host), never cross-host/off-scope — an in-scope host that 30x's off-scope is not fetched.
           # `-location` still records the Location for cross-host redirects (intel without following).
           "-follow-host-redirects", "-random-agent", "-timeout", "7", "-retries", "0",
           "-t", str(settings.workers("httpx", 15))]
    if http_rl:
        cmd += ["-rl", str(http_rl)]
    return cmd


def _run_httpx(ctx, hosts, ports, phase, tag):
    """Probe `hosts` on `ports` (hostnames, so Host/SNI/cert/CDN stay correct) → record + return
    (raw_ref, lines) so each live entity keeps its OWN immutable raw evidence file (per httpx call).
    Timeout scales with host × port-weight."""
    hf = ctx.write_list(f"{tag}_targets.txt", sorted(set(hosts)))
    hx = ctx.run.raw_path(phase, "httpx", f"{tag}.jsonl")
    cmd = _httpx_probe_cmd(hf, ports, ctx.profile.http_rl)
    to = scaled_timeout(len(hosts), ctx.http_timeout, per_unit=max(6, len(ports) // 12))
    r = exec_tool("httpx", cmd, raw_path=hx, timeout=to)
    ctx.run.record(phase, r)
    return str(hx), (r.raw_path.read_text().splitlines() if r.raw_path else [])


def _host_public_ip_map(ctx, hosts):
    """Returns (pubmap, a_known). pubmap = {host: [global PUBLIC A-record IPs]} from resolved.a +
    dns_record A (private/loopback/link-local/multicast/reserved dropped via is_global). a_known = set of
    hosts that had ANY A record at all. The caller MUST distinguish 'no A data known' (unknown IP → probe
    by hostname) from 'A data but all private' (an internal host → NOT a scan target, skip)."""
    want = set(hosts)
    a_by_host: dict[str, set] = {}
    for r in ctx.run.read("resolved"):
        h = r.get("host")
        if h in want and r.get("a"):
            a_by_host.setdefault(h, set()).update(r["a"])
    for d in ctx.run.read("dns_record"):
        if d.get("type") == "a" and d.get("host") in want and d.get("value"):
            a_by_host.setdefault(d["host"], set()).add(d["value"])
    a_known = set(a_by_host)
    pubmap: dict[str, list] = {}
    for h in hosts:
        pub = []
        for ip in a_by_host.get(h, ()):
            try:
                if ip and _ipaddr.ip_address(ip).is_global:
                    pub.append(ip)
            except ValueError:
                continue
        pubmap[h] = sorted(set(pub))
    return pubmap, a_known


def _web_port_prefilter(ctx, hosts, phase, pubmap):
    """v0.3.5 SYN web-port prefilter (bbot-style, NOT the infra portscan). `hosts` are PUBLIC-IP hosts
    only (private-only ones already dropped by the caller). naabu SYN over their public IPs × prof.ports
    (never top-1000/CIDR/nmap) → open ip:ports → mapped back to hosts → {host:[open ports]}. Returns None
    to signal FULL fallback to direct-httpx. Only a CLEAN naabu completion is trusted — a truncated scan
    (timeout / block / error / partial) falls back so a few ports found mid-failure can't silently
    suppress the rest. Stores web_port evidence + echoes the matrix."""
    if not have("naabu"):
        return None
    prof = ctx.profile
    ip_to_hosts: dict[str, list] = {}
    for h in hosts:
        for ip in pubmap.get(h, ()):
            ip_to_hosts.setdefault(ip, []).append(h)
    unique_ips = sorted(ip_to_hosts)
    if not unique_ips:
        return None
    ips_file = ctx.write_list(f"{phase}_webports_ips.txt", unique_ips)
    raw = ctx.run.raw_path(phase, "naabu-web", "open.json")
    cmd = ["naabu", "-list", str(ips_file), "-p", ",".join(str(p) for p in prof.ports),
           "-json", "-scan-type", "s", "-Pn", "-silent", "-o", str(raw)]   # SYN, no host-disco, web ports only
    if prof.portscan_rate:
        cmd += ["-rate", str(prof.portscan_rate)]
    to = scaled_timeout(len(unique_ips) * len(prof.ports), ctx.http_timeout, per_unit=0.02)
    res = exec_tool("naabu", cmd, timeout=to)
    raw_status = res.status
    # naabu writes findings to the -o FILE (empty stdout) → parse it FIRST, then fix the audit status
    # (same file-output mislabel class as gowitness) BEFORE recording.
    open_by_ip: dict[str, set] = {}
    if raw.exists():
        for line in raw.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            ip = port = None
            try:
                o = _json.loads(line)
                ip, port = o.get("ip") or o.get("host"), o.get("port")
            except _json.JSONDecodeError:
                if ":" in line:
                    ip, _, port = line.rpartition(":")
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if ip:
                open_by_ip.setdefault(ip, set()).add(port)
    n_open = sum(len(v) for v in open_by_ip.values())
    if n_open and raw_status == Status.EMPTY:            # clean run, findings in file, empty-stdout mislabel
        res.status = Status.SUCCESS
        res.note = f"{n_open} open port(s)"
        res.stdout_lines = n_open
    ctx.run.record(phase, res)
    # HIGH 2: trust the prefilter ONLY on a clean completion. A truncated/errored scan (TIMED_OUT /
    # BLOCKED / FAILED / PARTIAL) → FULL fallback, even if some ports were found — never thin coverage.
    if raw_status not in (Status.SUCCESS, Status.EMPTY):
        return None
    if n_open == 0:
        return None                                     # zero open (or clean-empty) -> don't trust, fall back
    host_ports: dict[str, set] = {}
    for ip, ports in open_by_ip.items():
        for h in ip_to_hosts.get(ip, []):
            host_ports.setdefault(h, set()).update(ports)
            for p in sorted(ports):
                ctx.run.add("web_port", {"id": f"{h}|{ip}|{p}", "host": h, "ip": ip, "port": p,
                                         "sources": ["naabu-web"], "raw_ref": str(raw)})
    host_ports = {h: sorted(ps) for h, ps in host_ports.items()}
    n_targets = sum(len(ps) for ps in host_ports.values())
    ctx.echo(f"  web-port prefilter: {len(unique_ips)} public IPs × {len(prof.ports)} ports -> "
             f"{n_open} open ip:ports -> {n_targets} host:port probes")
    ctx.run.notes.append(f"{phase} web-port prefilter: public_ips={len(unique_ips)} "
                         f"ports={len(prof.ports)} ip_port_checks={len(unique_ips) * len(prof.ports)} "
                         f"open_ip_ports={n_open} httpx_host_port_targets={n_targets}")
    return host_ports


def fingerprint_hosts(ctx, hosts, phase):
    """Fingerprint `hosts` → list of (raw_ref, json_lines) per httpx call (callers parse each with its
    REAL raw file for per-entity provenance). v0.3.5: SYN-prefilter → httpx only on OPEN host:ports
    (grouped by open-port set); hosts with NO known IP → direct-httpx by hostname. SAFETY RAILS:
    - private/reserved-only hosts (A data but no public IP) are NOT scan targets → skipped + noted.
    - FALLBACK-SAFE: prefilter off / naabu missing / truncated / zero-open → v0.3.4 direct-httpx over the
      public + unknown-IP hosts (never private-only, never a thin run). Shared by probe + enrich."""
    prof = ctx.profile
    pubmap, a_known = _host_public_ip_map(ctx, hosts)
    private_only = [h for h in hosts if h in a_known and not pubmap[h]]   # HIGH 1: internal, not a target
    public_hosts = [h for h in hosts if pubmap[h]]
    no_ip = [h for h in hosts if h not in a_known]                        # unknown IP → probe by hostname
    if private_only:
        ctx.echo(f"  web-port: {len(private_only)} host(s) resolve only to private/reserved IPs — "
                 f"skipped (not scan targets)")
        ctx.run.notes.append(f"{phase}: {len(private_only)} private-only host(s) skipped (not scan targets)")

    def _direct(targets):
        return [_run_httpx(ctx, targets, prof.ports, phase, "httpx")] if targets else []

    if not settings.web_port_prefilter():
        return _direct(public_hosts + no_ip)                             # v0.3.4 direct (still skips private-only)
    host_ports = _web_port_prefilter(ctx, public_hosts, phase, pubmap) if public_hosts else None
    if host_ports is None:
        return _direct(public_hosts + no_ip)                             # fallback: full direct, never private-only
    results = []
    groups: dict[tuple, list] = {}
    for h, ps in host_ports.items():
        groups.setdefault(tuple(ps), []).append(h)
    for i, (ps, hs) in enumerate(sorted(groups.items())):
        results.append(_run_httpx(ctx, hs, list(ps), phase, f"httpx-g{i}"))   # httpx on OPEN ports only
    if no_ip:
        results.append(_run_httpx(ctx, no_ip, prof.ports, phase, "httpx-direct"))
    return results


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        ctx.run.record("probe", skipped("httpx", "passive-only mode"))
        return

    hosts = ctx.run.values("resolved") or ctx.run.values("subdomain")
    hosts = scope.filter_hosts(hosts, active=True)
    if not hosts:
        ctx.run.record("probe", skipped("httpx", "no in-scope hosts to probe"))
        ctx.run.notes.append("probe: no hosts (run vertical first)")
        return

    # ── httpx full fingerprint -> live services (v0.3.5: SYN-prefilter → httpx on open ports only) ──
    groups = fingerprint_hosts(ctx, hosts, "probe")     # [(raw_ref, json_lines)] per httpx call
    lines = [ln for _ref, gl in groups for ln in gl]    # combined, for the CSP/deser pass below
    if groups:
        n = 0
        for raw_ref, glines in groups:                  # parse each group with its OWN raw file (provenance)
            for e in normalize.httpx_json("\n".join(glines), "httpx", raw_ref):
                if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                    if ctx.run.add("live", e):
                        n += 1
                        for tech in e.get("tech") or []:
                            ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                                 "url": e["url"], "sources": ["httpx"]})
        ctx.echo(f"  httpx: {n} live services")

        # ── CSP-advertised siblings (horizontal discovery from live response headers) ──
        # httpx -irh carries the Content-Security-Policy; in-scope hosts named there (e.g. an
        # internal/staging host in script-src) are a real discovery channel. Parsed here over
        # live hosts because the CSP lives on a probed host (www), not the bare apex — which is
        # why csprecon over apex roots in horizontal found nothing.
        _CSP_HOST = _re.compile(r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", _re.I)
        csp_added = deser_n = 0
        for line in lines:
            try:
                o = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            hdr = o.get("header") or {}
            rhost = (o.get("input") or o.get("host") or "").lower().rstrip(".")
            # ── deserialization / token FORMAT fingerprint (passive: Set-Cookie + response headers) ──
            if hdr and rhost and scope.in_scope(rhost):
                blob = " ".join(str(v) for v in hdr.values())
                fmts = [f for f, marker in _DESER_MARKERS if marker in blob]
                if _PHP_OBJ_RX.search(blob):
                    fmts.append("php-serialized")
                if _JWT_RX.search(blob):
                    fmts.append("jwt")
                for fmt in fmts:
                    hint = ("check alg:none / weak HS256 secret / RS256→HS256 confusion"
                            if fmt == "jwt" else "untrusted-deserialization surface")
                    if ctx.run.add("review", {
                            "id": f"deser:{rhost}:{fmt}", "klass": "deser", "value": rhost,
                            "host": rhost, "format": fmt,
                            "note": f"{fmt} marker in response headers/cookies — {hint} "
                                    "(attack-layer target; verify)",
                            "sources": ["deser-fingerprint"]}):
                        deser_n += 1
            # ── CSP-advertised siblings ──
            csp = hdr.get("content_security_policy")
            if not csp:
                continue
            for host in {m.lower() for m in _CSP_HOST.findall(csp)}:
                if scope.in_scope(host) and ctx.run.add(
                        "subdomain", {"host": host, "sources": ["csp"]}):
                    csp_added += 1
        if csp_added:
            ctx.echo(f"  csp: +{csp_added} sibling host(s) from response headers")
        if deser_n:
            ctx.echo(f"  deser: {deser_n} serialization/token fingerprint(s) in headers/cookies")

    # ── tlsx over in-scope hosts — cert SAN harvest (new sibling hostnames) + cert context ──
    # tlsx is used in horizontal over IP RANGES; here it runs over the resolved HOST set: cert SANs
    # reveal sibling hostnames we'd otherwise miss (coverage → enrich resolves/probes them), and the
    # cert (cn/issuer/expiry/wildcard) is stored as first-class context (the `certificate` entity).
    if have("tlsx"):
        thosts = sorted(h for h in set(ctx.run.values("resolved"))
                        if h and scope.in_scope(h) and not scope.is_oos(h))
        if thosts:
            tf = ctx.write_list("tls_targets.txt", thosts)
            tr = ctx.run.raw_path("probe", "tlsx", "certs.jsonl")
            r = exec_tool("tlsx", ["tlsx", "-l", str(tf), "-p", "443,8443,4443",
                                   "-json", "-silent"], raw_path=tr, timeout=ctx.http_timeout)
            ctx.run.record("probe", r)
            san_new = 0
            if r.raw_path and r.raw_path.exists():
                for c in normalize.tlsx_certs(r.raw_path.read_text(), "tlsx", str(tr)):
                    all_san = c.get("san") or []
                    # scope-safe normalized entity: keep only in-scope SANs (shared/CDN/vendor certs
                    # carry unrelated names). Full SAN list stays in raw via raw_ref. Context counts.
                    in_scope_san = [s for s in all_san if scope.in_scope(s) and not scope.is_oos(s)]
                    c["san"] = in_scope_san
                    c["san_count"] = len(all_san)
                    c["oos_san_count"] = len(all_san) - len(in_scope_san)
                    c["has_oos_sans"] = c["oos_san_count"] > 0
                    ctx.run.add("certificate", c)
                    for s in in_scope_san:                     # in-scope SANs → new hosts (coverage)
                        if not s.startswith("*.") and ctx.run.add(
                                "subdomain", {"host": s, "sources": ["tlsx-san"]}):
                            san_new += 1
            if san_new:
                ctx.echo(f"  tlsx: +{san_new} sibling host(s) from cert SANs")

    # ── Shodan pivots (key-gated, silent): same favicon + same TLS cert fingerprint → related hosts ──
    _favicon_pivot(ctx)
    _cert_pivot(ctx)

    # ── virtual-host enumeration (ffuf Host-header fuzz over origin IPs; needs a vhost wordlist) ──
    _vhost_enum(ctx)

    # ── WAF fingerprint (nuclei waf-detect templates over live hosts) ──
    # Recon-side only: identify WHICH WAF fronts each host (Cloudflare/Akamai/F5…).
    # Bypass tooling (nomore403/nowafpls/NewTowner) stays human/Burp work.
    if have("nuclei") and ctx.run.count("live"):
        waf_in = ctx.write_list("waf_targets.txt", ctx.run.values("live"))
        waf_out = ctx.run.raw_path("probe", "nuclei", "waf.jsonl")
        waf_cmd = ["nuclei", "-l", str(waf_in), "-tags", "waf", "-jsonl", "-o", str(waf_out)]
        if prof.http_rl:                       # else native default (empty = fast)
            waf_cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("nuclei", waf_cmd,
                      timeout=nuclei_timeout(ctx.run.count("live"), ctx.http_timeout))
        ctx.run.record("probe", r)
        if waf_out.exists():
            n = 0
            for line in waf_out.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                ex = o.get("extracted-results") or []
                name = (ex[0] if ex else None) or o.get("matcher-name") or "unknown"
                host = o.get("matched-at", o.get("host", ""))
                ctx.run.add("tech", {"id": f"{host}|waf:{name}", "tech": f"WAF:{name}",
                                     "url": host, "sources": ["nuclei-waf"]})
                n += 1
            ctx.echo(f"  waf: {n} hosts fingerprinted")

    # ── screenshots (write structured jsonl too for the asset DB) ──
    if prof.screenshots and ctx.run.count("live"):
        live_file = ctx.write_list("live.txt", ctx.run.values("live"))
        shot_dir = ctx.run.dir / "raw" / "probe" / "gowitness"
        shot_dir.mkdir(parents=True, exist_ok=True)
        r = exec_tool("gowitness",
                ["gowitness", "scan", "file", "-f", str(live_file),
                 "--screenshot-path", str(shot_dir), "--write-jsonl",
                 "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                timeout=ctx.http_timeout)
        # gowitness writes to FILES, not stdout → the runner mislabels it BLOCKED on a stderr WAF line
        # even when it screenshotted most hosts (observed 43/51). Reclassify from shots on disk.
        shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
        reclassify_from_files(r, shots, "screenshot")
        ctx.run.record("probe", r)
        for img in shot_dir.glob("*.jpeg"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})
        for img in shot_dir.glob("*.png"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

    # ── ports: naabu (in-scope CIDR) → nmap -sV service detection ──
    if prof.portscan and prof.cidr:
        cidr_file = ctx.write_list("cidr.txt", prof.cidr)
        cmd = ["naabu", "-list", str(cidr_file), "-top-ports", "1000", "-silent"]
        if prof.portscan_rate:
            cmd += ["-rate", str(prof.portscan_rate)]
        pr = ctx.run.raw_path("probe", "naabu", "ranges.txt")
        # naabu concurrency is RATE-based (portscan_rate), not thread-based — but a big CIDR can still
        # wall the flat timeout, so scale the ceiling by range count.
        naabu_to = scaled_timeout(len(prof.cidr), ctx.http_timeout, per_unit=300)
        r = exec_tool("naabu", cmd, raw_path=pr, timeout=naabu_to)
        ctx.run.record("probe", r)
        open_ports = {}
        if r.raw_path:
            for line in r.raw_path.read_text().splitlines():
                line = line.strip()
                if ":" in line:
                    ctx.run.add("port", {"id": line, "sources": ["naabu"]})
                    ip, _, port = line.rpartition(":")
                    open_ports.setdefault(ip, set()).add(port)
        # nmap -sV only on the ports naabu found open (methodology: don't full-scan)
        if open_ports and have("nmap"):
            ips_file = ctx.write_list("naabu_ips.txt", list(open_ports))
            ports_csv = ",".join(sorted({p for ps in open_ports.values() for p in ps}, key=int))
            nm = ctx.run.raw_path("probe", "nmap", "service.txt")
            r = exec_tool("nmap", ["nmap", "-sV", "-Pn", "-T4", "-iL", str(ips_file),
                                   "-p", ports_csv, "-oN", str(nm)],
                          timeout=scaled_timeout(len(open_ports), ctx.http_timeout, per_unit=30))
            ctx.run.record("probe", r)
    elif prof.portscan:
        ctx.run.record("probe", skipped("naabu", "no in-scope CIDR — port scan skipped"))

    # ── smap: passive (Shodan-backed) port scan, no packets to target (optional) ──
    if have("smap") and ctx.run.count("live"):
        sm_in = ctx.write_list("smap_targets.txt",
                               [normalize.host_of_url(u) for u in ctx.run.values("live")])
        sm = ctx.run.raw_path("probe", "smap", "smap.txt")
        r = exec_tool("smap", ["smap", "-iL", str(sm_in)], raw_path=sm, timeout=600)
        ctx.run.record("probe", r)
