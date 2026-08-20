"""Horizontal discovery: surface more in-scope hostnames on owned IP space + cert data. Scope stays
fixed — no automatic pivot to new apex roots; ASN findings are review candidates. Methodology:
ASN→cert chain, kaeferjaeger SNI dataset, tlsx SAN harvest, reverse DNS.
"""
from __future__ import annotations

import re as _re

from .. import fetch, netguard, normalize

# in-scope hostnames named in a Content-Security-Policy (script-src / connect-src / …).
_CSP_HOST = _re.compile(r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", _re.I)
# CSP via <meta http-equiv="Content-Security-Policy" content="..."> — any attribute order.
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
from ..runner_repository import RepositoryOutput
from . import _local_raw


# hostname matcher for the operator's local kaeferjaeger SNI dataset (never fetched remotely).
_KJ_HOST_RX = _re.compile(r"[a-z0-9_.-]+\.[a-z]{2,}", _re.I)


class _RawWriteError(OSError):
    """A repository-stage write failed, rather than one local input file."""


def _kaeferjaeger_dir():
    from pathlib import Path
    return Path.home() / ".config/quarry/kaeferjaeger"


def _kaeferjaeger(ctx) -> int:
    """Cloud-SNI name harvest from the operator's local dataset (no remote fetch). Streams every `*.txt`
    under ~/.config/quarry/kaeferjaeger/ line-by-line for in-scope hostnames, keeping `host<TAB>file:lineno`
    provenance. Status distinguishes no file read / some failed / all processed. Returns the match count."""
    import time
    ddir = _kaeferjaeger_dir()
    t0 = time.monotonic()
    # matched = unique in-scope hosts found (drives status + raw_path; a rerun re-finding existing
    # entities still counts). added = new store entities; provenance is written once per (host, file).
    matched, added, prov_seen, read_files, failed = set(), 0, set(), 0, 0
    with _local_raw.lifecycle(ctx.run):
        # The lifecycle claim exists before even enumerating the local dataset.
        # An absent dataset therefore stays an honest skip without publishing a
        # misleading empty replacement artifact.
        files = sorted(ddir.glob("*.txt")) if ddir.is_dir() else []
        if not files:
            ctx.run.record("horizontal", skipped(
                "kaeferjaeger", "no local SNI dataset — optional setup: download provider *_sni.txt to "
                "~/.config/quarry/kaeferjaeger/"))
            return 0
        with _local_raw.text_writer(
            ctx.run, "horizontal", "kaeferjaeger", "matches.txt",
        ) as (raw_path, out):
            for f in files:
                try:
                    with f.open("r", encoding="utf-8", errors="replace") as fh:
                        for lineno, line in enumerate(fh, 1):    # stream: RAM bounded to a line
                            for m in _KJ_HOST_RX.findall(line):
                                h = m.lower().rstrip(".")
                                if not ctx.scope.in_scope(h):
                                    continue
                                matched.add(h)
                                if (h, f.name) not in prov_seen:
                                    prov_seen.add((h, f.name))
                                    try:
                                        out.write(f"{h}\t{f.name}:{lineno}\n")
                                    except OSError as exc:
                                        # Do not misclassify a failed repository stage as an unreadable input.
                                        raise _RawWriteError(str(exc)) from exc
                    read_files += 1
                except _RawWriteError:
                    raise
                except OSError as e:
                    failed += 1
                    ctx.run.notes.append(f"kaeferjaeger: {f.name} unreadable: {e}")
        # The inner claim has published. Keep the outer marker through every
        # entity append so each raw_ref names this invocation's committed bytes.
        for h in sorted(matched):
            if ctx.run.add("subdomain", {"host": h, "sources": ["kaeferjaeger"],
                                         "raw_ref": str(raw_path)}):
                added += 1
        status = (Status.FAILED if read_files == 0 else Status.PARTIAL if failed
                  else Status.SUCCESS if matched else Status.EMPTY)
        ctx.run.record("horizontal", RunResult(
            "kaeferjaeger", ["<local SNI dataset>"], status, 0,
            round(time.monotonic() - t0, 2), raw_path if matched else None, len(matched),
            note=(f"{read_files}/{len(files)} file(s) read, {failed} failed, "
                  f"{len(matched)} matched, +{added} added"),
        ))
        return len(matched)


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    n = _kaeferjaeger(ctx)
    if n:
        ctx.echo(f"  kaeferjaeger: {n} in-scope host(s) matched in local SNI dataset")

    # CSP siblings: in-scope domains named in the apex's Content-Security-Policy, fetched via
    # fetch.scoped_headers (resolve/scope/IP-guarded, paced to http_rl; not csprecon, which auto-follows).
    if not scope.passive_only:
        with _local_raw.lifecycle(ctx.run):
            # Fresh resolution is provider-contact preparation, so even it
            # starts only after the durable lifecycle claim exists.
            roots = netguard.guard_hosts(ctx, prof.apex_domains, phase="horizontal.csp")
            raw = _local_raw.destination(ctx.run, "horizontal", "csp", "csp.txt")
            added = responses = failed = 0
            dump = []
            discovered = set()
            for apex in roots:
                for scheme in ("https", "http"):
                    # Pinned peer plus ordinary hostname/certificate verification.
                    hdrs, body, final, st = fetch.scoped_headers(
                        ctx, f"{scheme}://{apex}/", insecure=False,
                        source_id="horizontal.csp",
                    )
                    if hdrs is None:                          # transport failure or off-scope redirect
                        failed += 1
                        continue
                    responses += 1
                    csp = " ".join(str(hdrs.get(k) or "") for k in  # all CSP variants + <meta http-equiv>
                                   ("Content-Security-Policy", "Content-Security-Policy-Report-Only",
                                    "X-Content-Security-Policy", "X-WebKit-CSP"))
                    csp = (csp + " " + " ".join(_meta_csp(body.decode("utf-8", "replace")))).strip()
                    if csp:
                        dump.append(f"# {final} (status {st})\n{csp}")
                    discovered.update(h for h in (m.lower().strip(".") for m in _CSP_HOST.findall(csp))
                                      if scope.in_scope(h))
            raw = _local_raw.replace_text(
                ctx.run, "horizontal", "csp", "csp.txt", "\n".join(dump),
            )
            # No record may cite a prior same-name artifact when this publication did not commit.
            for h in sorted(discovered):
                if ctx.run.add("subdomain", {"host": h, "sources": ["csp"], "raw_ref": str(raw)}):
                    added += 1
            # Source accounting is part of the same terminal base mutation: the
            # seal cannot observe raw/entities without their source result.
            _st = (Status.SKIPPED if not roots else Status.FAILED if responses == 0 else
                   Status.PARTIAL if failed else Status.SUCCESS if (dump or added) else Status.EMPTY)
            ctx.run.record("horizontal", RunResult(
                "csp", ["<native scoped CSP fetch>"], _st, 0, 0.0,
                raw if dump else None, len(dump),
                note=f"{responses} responded, {failed} failed, +{added} host(s)",
            ))
        if added:
            ctx.echo(f"  csp: +{added} in-scope host(s) from apex Content-Security-Policy")

    # cloud-asset candidates: S3/GCS bucket enum from apex/org (non-mutating, verify-ownership). Above
    # the CIDR early-return so it runs for domain-only profiles too.
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
    r = exec_tool(
        "mapcidr", ["mapcidr", "-duc", "-cidr", ",".join(prof.cidr), "-silent"],
        repository=ctx.run,
        stdout=RepositoryOutput.publish(*ips_path.relative_to(ctx.run.dir).parts),
        stderr=RepositoryOutput.discard(), timeout=120,
    )
    ctx.run.record("horizontal", r)
    # ``raw_path`` is the runner's publication proof.  A clean process whose
    # repository publication fenced is PARTIAL (and therefore ``r.ok``), but
    # its fixed final may still contain a prior invocation's bytes.
    ips_file = r.raw_path if r.raw_path == ips_path else cidr_file

    # tls SAN harvest on the ranges -> in-scope hostnames
    if scope.passive_only:
        ctx.run.record("horizontal", skipped("tlsx", "passive-only mode"))
    else:
        tls_raw = ctx.run.raw_path("horizontal", "tlsx", "san.txt")
        r = exec_tool(
            "tlsx", ["tlsx", "-duc", "-l", str(ips_file), "-san", "-cn", "-silent",
                     "-p", "443,8443,4443", "-resp-only"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*tls_raw.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
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
        r = exec_tool(
            "dnsx", ["dnsx", "-duc", "-l", str(ips_file), "-ptr", "-resp-only", "-silent"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*ptr_raw.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
        ctx.run.record("horizontal", r)
        if r.raw_path:
            for ent in normalize.hosts(r.raw_path.read_text(), "revdns", str(ptr_raw)):
                if scope.in_scope(ent["host"]):
                    ctx.run.add("subdomain", ent)

    # Caduceus: live ASN/CIDR -> TLS cert scan -> real hostnames behind CDN
    # (surfaces hosts behind Akamai/Cloudflare that DNS enum misses). Needs active mode + CIDR.
    if not scope.passive_only and have("caduceus"):
        cad = ctx.run.raw_path("horizontal", "caduceus", "certs.json")
        r = exec_tool(
            "caduceus", ["caduceus", "-i", str(cidr_file),
                         "-p", "443,8443,4443", "-j"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*cad.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
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
        r = exec_tool(
            "asnmap", ["asnmap", "-duc", "-silent"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*asn_raw.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(),
            stdin_data="\n".join(asn_seeds), timeout=60,
        )
        ctx.run.record("horizontal", r)
