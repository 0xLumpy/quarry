"""Phase 2: Horizontal discovery.

Surfaces MORE in-scope hostnames on owned IP space + cert data. We do NOT pivot to
new apex roots automatically (scope stays fixed); ASN findings are recorded as
candidates for human review (design Q7). Methodology: ASN->cert chain,
kaeferjaeger SNI dataset, tlsx SAN harvest, reverse DNS.
"""
from __future__ import annotations

import re as _re

from .. import fetch, netguard, normalize

# in-scope hostnames named in a Content-Security-Policy (script-src / connect-src / …) — same shape probe
# uses on live-host CSP headers, here on the apex's CSP fetched safely (no csprecon auto-follow).
_CSP_HOST = _re.compile(r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", _re.I)
# CSP via <meta http-equiv="Content-Security-Policy" content="..."> — ANY attribute order (audit #7).
_META_TAG = _re.compile(r"<meta\b[^>]*>", _re.I)
_META_HTTPEQUIV = _re.compile(r"""http-equiv\s*=\s*["']?content-security-policy""", _re.I)
_META_CONTENT = _re.compile(r"""content\s*=\s*["']([^"']*)["']""", _re.I)


def _meta_csp(html: str) -> list[str]:
    out = []
    for tag in _META_TAG.findall(html):
        if _META_HTTPEQUIV.search(tag):
            m = _META_CONTENT.search(tag)
            if m:
                out.append(m.group(1))
    return out
from ..runner import RunResult, Status, have, run as exec_tool, skipped


# kaeferjaeger cloud-SNI name harvest reads an OPERATOR-PROVIDED LOCAL dataset — NEVER a remote fetch
# (audit #3: the registry declares this source `default: off, setup (local dataset, manual)`, but the code
# used to urlopen ~4 GB of provider SNI dumps on EVERY horizontal run — a plan/registry lie + a VPS-egress
# footgun). Same model as openintel's local DB: the operator downloads the provider `*_sni.txt` files they
# want (kaeferjaeger.gay/sni-ip-ranges/<provider>/…) ONCE to ~/.config/quarry/kaeferjaeger/, and we STREAM
# whatever is there LINE-BY-LINE (bounded RAM, but the COMPLETE file — never a nonrepresentative prefix) for
# in-scope hosts. Absent dataset -> quiet recorded skip.
_KJ_HOST_RX = _re.compile(r"[a-z0-9_.-]+\.[a-z]{2,}", _re.I)


def _kaeferjaeger_dir():
    from pathlib import Path
    return Path.home() / ".config/quarry/kaeferjaeger"


def _kaeferjaeger(ctx) -> int:
    """Passive cloud-SNI name harvest from the operator's LOCAL dataset — NO remote fetch. STREAMS every
    `*.txt` under ~/.config/quarry/kaeferjaeger/ line-by-line (bounded RAM, complete file) for in-scope
    hostnames; each match keeps `host<TAB>file:lineno` provenance. Honest status: FAILED if NO file could be
    read, PARTIAL if some failed, SUCCESS/EMPTY only after every file was fully processed. Returns count."""
    import time
    ddir = _kaeferjaeger_dir()
    files = sorted(ddir.glob("*.txt")) if ddir.is_dir() else []
    if not files:
        ctx.run.record("horizontal", skipped(
            "kaeferjaeger", "no local SNI dataset — optional setup: download provider *_sni.txt to "
            "~/.config/quarry/kaeferjaeger/"))
        return 0
    t0 = time.monotonic()
    raw_path = ctx.run.raw_path("horizontal", "kaeferjaeger", "matches.txt")
    # matched = every unique in-scope host THIS source found (drives status + raw_path — a rerun where the
    # entities already exist is still a real match, NOT empty). added = new store entities. provenance is
    # written once per (host, file) so a host appearing in two provider dumps keeps BOTH sources.
    matched, added, prov_seen, add_seen, read_files, failed = set(), 0, set(), set(), 0, 0
    with raw_path.open("w", encoding="utf-8") as out:
        for f in files:
            try:
                with f.open("r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):        # STREAM: RAM bounded to a line, whole file read
                        for m in _KJ_HOST_RX.findall(line):
                            h = m.lower().rstrip(".")
                            if not ctx.scope.in_scope(h):
                                continue
                            matched.add(h)
                            if (h, f.name) not in prov_seen:
                                prov_seen.add((h, f.name))
                                out.write(f"{h}\t{f.name}:{lineno}\n")   # first occ per (host, file)
                            if h not in add_seen:
                                add_seen.add(h)
                                if ctx.run.add("subdomain", {"host": h, "sources": ["kaeferjaeger"],
                                                             "raw_ref": str(raw_path)}):
                                    added += 1
                read_files += 1
            except OSError as e:
                failed += 1
                ctx.run.notes.append(f"kaeferjaeger: {f.name} unreadable: {e}")
    status = (Status.FAILED if read_files == 0 else Status.PARTIAL if failed
              else Status.SUCCESS if matched else Status.EMPTY)
    ctx.run.record("horizontal", RunResult("kaeferjaeger", ["<local SNI dataset>"], status, 0,
                   round(time.monotonic() - t0, 2), raw_path if matched else None, len(matched),
                   note=f"{read_files}/{len(files)} file(s) read, {failed} failed, {len(matched)} matched, +{added} added"))
    return len(matched)


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    # kaeferjaeger = passive OSINT over the operator's LOCAL SNI dataset (no remote fetch). One line if hits.
    n = _kaeferjaeger(ctx)
    if n:
        ctx.echo(f"  kaeferjaeger: {n} in-scope host(s) matched in local SNI dataset")

    # CSP siblings: related in-scope domains named in the apex's Content-Security-Policy. csprecon is NOT
    # used — it is an active HTTP requester that AUTO-FOLLOWS redirects (a public apex can 30x to a private/
    # off-scope host, audit #2). Quarry fetches the CSP itself via fetch.scoped_headers: the apex roots are
    # resolve-guarded, every hop is scope+IP-guarded, and it paces to a configured http_rl (audit #1/#5).
    if not scope.passive_only:
        roots = netguard.guard_hosts(ctx, prof.apex_domains, phase="horizontal.csp")
        raw = ctx.run.raw_path("horizontal", "csp", "csp.txt")
        added = responses = failed = 0
        dump = []
        for apex in roots:
            for scheme in ("https", "http"):
                # transport-safe (audit #2) + self-signed OK (insecure): a bad request never aborts the phase.
                hdrs, body, final, st = fetch.scoped_headers(ctx, f"{scheme}://{apex}/", insecure=True)
                if hdrs is None:                          # transport failure OR off-scope redirect -> NOT a usable fetch
                    failed += 1
                    continue
                responses += 1
                csp = " ".join(str(hdrs.get(k) or "") for k in    # all CSP header variants + <meta http-equiv>
                               ("Content-Security-Policy", "Content-Security-Policy-Report-Only",
                                "X-Content-Security-Policy", "X-WebKit-CSP"))
                csp = (csp + " " + " ".join(_meta_csp(body.decode("utf-8", "replace")))).strip()
                if csp:
                    dump.append(f"# {final} (status {st})\n{csp}")
                for m in _CSP_HOST.findall(csp):
                    h = m.lower().strip(".")
                    if scope.in_scope(h) and ctx.run.add(
                            "subdomain", {"host": h, "sources": ["csp"], "raw_ref": str(raw)}):
                        added += 1
        raw.write_text("\n".join(dump))
        # honest source-level status (audit #6): FAILED only if NOTHING answered; PARTIAL if some fetches
        # failed; EMPTY if everything answered but no CSP; SUCCESS only when CSP was actually found.
        _st = (Status.SKIPPED if not roots else Status.FAILED if responses == 0 else
               Status.PARTIAL if failed else Status.SUCCESS if (dump or added) else Status.EMPTY)
        ctx.run.record("horizontal", RunResult("csp", ["<native scoped CSP fetch>"], _st, 0, 0.0,
                                               raw if dump else None, len(dump),
                                               note=f"{responses} responded, {failed} failed, +{added} host(s)"))
        if added:
            ctx.echo(f"  csp: +{added} in-scope host(s) from apex Content-Security-Policy")

    # cloud-asset candidates: S3/GCS bucket enum from apex/org (non-mutating detect, verify-ownership).
    # ABOVE the CIDR early-return — it's apex/org-derived and must run for domain-only profiles too.
    if not scope.passive_only:
        from .. import cloud
        nc = cloud.discover(ctx)
        if nc:
            ctx.echo(f"  cloud: +{nc} bucket candidate(s) — VERIFY OWNERSHIP")

    if not prof.cidr:
        ctx.echo("  no CIDR in profile — skipping ASN/range/tls-SAN/revdns steps")
        ctx.run.notes.append("horizontal: CIDR empty, IP-based steps skipped")
        return

    cidr_file = ctx.write_list("cidr.txt", prof.cidr)

    # expand CIDR -> IPs
    ips_path = ctx.run.raw_path("horizontal", "mapcidr", "ips.txt")
    r = exec_tool("mapcidr", ["mapcidr", "-cidr", ",".join(prof.cidr), "-silent"],
            raw_path=ips_path, timeout=120)
    ctx.run.record("horizontal", r)
    ips_file = ips_path if r.ok else cidr_file

    # tls SAN harvest on the ranges -> in-scope hostnames
    if scope.passive_only:
        ctx.run.record("horizontal", skipped("tlsx", "passive-only mode"))
    else:
        tls_raw = ctx.run.raw_path("horizontal", "tlsx", "san.txt")
        r = exec_tool("tlsx", ["tlsx", "-l", str(ips_file), "-san", "-cn", "-silent",
                         "-p", "443,8443,4443", "-resp-only"], raw_path=tls_raw, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            added = 0
            for ent in normalize.hosts(r.raw_path.read_text(), "tlsx-san", str(tls_raw)):
                if scope.in_scope(ent["host"]) and ctx.run.add("subdomain", ent):
                    added += 1
            ctx.echo(f"  tlsx SAN: +{added} in-scope hosts")

    # reverse DNS (PTR) on range IPs
    if not scope.passive_only:
        ptr_raw = ctx.run.raw_path("horizontal", "dnsx", "ptr.txt")
        r = exec_tool("dnsx", ["dnsx", "-l", str(ips_file), "-ptr", "-resp-only", "-silent"],
                raw_path=ptr_raw, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            for ent in normalize.hosts(r.raw_path.read_text(), "revdns", str(ptr_raw)):
                if scope.in_scope(ent["host"]):
                    ctx.run.add("subdomain", ent)

    # Caduceus: live ASN/CIDR -> TLS cert scan -> real hostnames behind CDN
    # (surfaces hosts behind Akamai/Cloudflare that DNS enum misses). Needs active mode + CIDR.
    if not scope.passive_only and have("caduceus"):
        cad = ctx.run.raw_path("horizontal", "caduceus", "certs.json")
        r = exec_tool("caduceus", ["caduceus", "-i", str(cidr_file),
                                   "-p", "443,8443,4443", "-j"], raw_path=cad, timeout=ctx.http_timeout)
        ctx.run.record("horizontal", r)
        if r.raw_path:
            import json as _json
            added = 0
            raw_text = r.raw_path.read_text()
            try:
                parsed = _json.loads(raw_text)
                records = parsed if isinstance(parsed, list) else [parsed]
            except _json.JSONDecodeError:
                records = []
                for line in raw_text.splitlines():
                    try:
                        records.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        continue
            for obj in records:
                if not isinstance(obj, dict):
                    continue
                domains = obj.get("domains") or obj.get("domain") or obj.get("names") or []
                if isinstance(domains, str):
                    domains = [domains]
                for d in domains:
                    h = str(d).lower().rstrip(".")
                    if scope.in_scope(h) and ctx.run.add("subdomain",
                            {"host": h, "sources": ["caduceus"], "raw_ref": str(cad)}):
                        added += 1
            if not records:
                try:
                    # Last-resort extraction keeps the run useful if Caduceus changes shape.
                    for h in set(__import__("re").findall(r"[a-z0-9_.-]+\.[a-z]{2,}", raw_text, __import__("re").I)):
                        h = h.lower().rstrip(".")
                        if scope.in_scope(h) and ctx.run.add("subdomain",
                                {"host": h, "sources": ["caduceus"], "raw_ref": str(cad)}):
                            added += 1
                except Exception:
                    pass
            ctx.echo(f"  caduceus: +{added} in-scope hosts from certs")
    elif not scope.passive_only:
        ctx.run.record("horizontal", skipped("caduceus", "not installed (optional) — quarry install --only caduceus"))

    # asnmap: context only, never block (hard timeout in runner)
    asn_seeds = prof.asn
    if asn_seeds:
        asn_raw = ctx.run.raw_path("horizontal", "asnmap", "ranges.txt")
        r = exec_tool("asnmap", ["asnmap", "-silent"], stdin_data="\n".join(asn_seeds),
                raw_path=asn_raw, timeout=60)
        ctx.run.record("horizontal", r)
