"""Phase 3: Vertical subdomain discovery.

passive (subfinder -all) + github-subdomains -> brute (puredns) -> permutations
(alterx/dnsgen) -> trusted-resolver validation. Records per-source deltas.
"""
from __future__ import annotations

import ipaddress as _ipaddress
import json as _json
import os
import re as _re
import shutil
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

from .. import budget, campaign, events, netguard, normalize, policy, remainder, secrets, settings, sweep
from ..contract import (ProviderResult, ProviderSkip, classify_provider_error, read_bounded,
                        registered, run_contract,
                        run_provider)
from ..runner import (RunResult, Status, have, reclassify_from_artifact, run as exec_tool,
                       skipped)

_SUBFINDER_DEFAULT_MIN = 60                  # default -max-time budget (minutes)
_SUBFINDER_UNBOUNDED_MIN = 1440             # 0 -> 24h ceiling (subfinder cancels on -max-time 0)


def _subfinder_budget_min(http_timeout) -> int:
    """Effective subfinder -max-time in minutes from PERFORMANCE.SUBFINDER_MAX_TIME (default 60, max 1440);
    a non-integer/out-of-range value falls back to 60, and 0 -> 1440 (never 0 to subfinder)."""
    knob = settings.strict_int("SUBFINDER_MAX_TIME",
                               default=_SUBFINDER_DEFAULT_MIN, maximum=_SUBFINDER_UNBOUNDED_MIN)
    if knob <= 0:
        return _SUBFINDER_UNBOUNDED_MIN
    return knob


def _subfinder_reclassifier(budget_min: int):
    """Reclassify callback: a SUCCESS/EMPTY whose wall-clock reached the budget hit the -max-time ceiling ->
    PARTIAL (results kept). A finish below the budget stays SUCCESS/EMPTY."""
    budget_s = budget_min * 60

    def _reclassify(res):
        if res.status in (Status.SUCCESS, Status.EMPTY) and res.duration >= budget_s:
            return replace(res, status=Status.PARTIAL,
                           note=f"hit subfinder -max-time {budget_min}m ceiling — coverage capped (results kept)")
        return res
    return _reclassify


def _subfinder_config_paths() -> "tuple[Path, Path]":
    """(provider-config, config) paths subfinder reads: SUBFINDER_PROVIDER_CONFIG / SUBFINDER_CONFIG env
    overrides win, else `<XDG_CONFIG_HOME or ~/.config>/subfinder/{provider-config,config}.yaml`."""
    cfg_dir = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "subfinder"
    provider = Path(os.environ.get("SUBFINDER_PROVIDER_CONFIG") or (cfg_dir / "provider-config.yaml"))
    config = Path(os.environ.get("SUBFINDER_CONFIG") or (cfg_dir / "config.yaml"))
    return provider, config


def _subfinder_provider_fp() -> str:
    """sha256 over both config files' contents + a fingerprint of the PDCP key, folded into the resume
    work_unit so a config change (e.g. adding a key) invalidates resume. Never emits a raw secret."""
    import hashlib
    provider, config = _subfinder_config_paths()
    h = hashlib.sha256()
    for label, p in (("provider-config", provider), ("config", config)):
        try:
            data = p.read_bytes()
        except OSError:
            data = b"\x00<absent>"
        h.update(label.encode() + b"\x00" + len(data).to_bytes(8, "big") + data)   # length-framed
    key = (os.environ.get("PDCP_API_KEY") or "").encode()
    h.update(b"pdcp-key\x00" + hashlib.sha256(key).digest())  # key fingerprint, never the raw key
    return h.hexdigest()


def _run_subfinder(ctx, prof, scope) -> None:
    """Passive subfinder, run once per apex (subfinder applies -max-time per domain, so one -dL batch would
    charge a summed duration against one ceiling). Flags: `-all` = every source; no `-recursive` (upstream
    restricts to the recursive-capable subset). Collection budget is subfinder's own -max-time; the outer
    subprocess backstop = budget + 60s so it caps itself gracefully, except --timeout 0 which passes outer 0."""
    budget_min = _subfinder_budget_min(ctx.http_timeout)
    reclassify = _subfinder_reclassifier(budget_min)
    outer = 0 if ctx.http_timeout == 0 else budget_min * 60 + 60   # --timeout 0 -> no outer kill; else budget+60s
    providers = _subfinder_provider_fp()                     # coverage-affecting: folded into resume
    for apex in sorted(set(prof.apex_domains)):
        sf_raw = ctx.run.raw_path("vertical", "subfinder", f"passive_{apex}.txt")
        sf_wu = events.work_unit("vertical.subfinder", inputs={"root": apex},
                                 config={"sources": "all", "max_time_min": budget_min, "providers": providers})
        r = run_contract("vertical.subfinder",
                         ["subfinder", "-d", apex, "-all", "-max-time", str(budget_min),
                          "-stats", "-silent"], work_unit=sf_wu, raw_path=sf_raw,
                         reclassify=reclassify, timeout=outer)
        ctx.run.record("vertical", r)
        if r.raw_path:
            n = sum(ctx.run.add("subdomain", e) for e in
                    normalize.hosts(r.raw_path.read_text(), "subfinder", str(sf_raw))
                    if scope.in_scope(e["host"]))
            ctx.echo(f"  subfinder [{apex}]: +{n} in-scope ({r.stdout_lines} raw, {r.status.value})")


def _shosubgo_read(path):
    """Fail-closed read of shosubgo's -o host file. Returns (hosts, artifact_ok): hosts = validated host
    dicts to ingest; artifact_ok = True only when clean UTF-8 and every non-blank line was a valid host.
    Returns (None, False) when the file is missing or unreadable."""
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
        text, artifact_ok = raw.decode("utf-8", "replace"), False
    hosts = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        parsed = list(normalize.hosts(s, "shosubgo", str(path)))
        if parsed:
            hosts.extend(parsed)
        else:
            artifact_ok = False                                     # a non-blank non-host line -> malformed
    return hosts, artifact_ok


def _openintel(ctx, cfg: dict, apex: str, timeout: int = 180) -> set:
    """Optional passive source: query a local openintel-subs binary + subs.db for `apex`. Silent when
    unconfigured (the caller guards on binary+db). Runs through the runner and records its RunResult so a
    configured failure is observable. Returns the in-DB host set, empty on any non-clean result."""
    binary, db = cfg.get("binary"), cfg.get("db")
    exe = shutil.which(binary) or (binary if binary and os.path.isfile(binary)
                                   and os.access(binary, os.X_OK) else None)
    if not exe or not os.path.isfile(db):
        ctx.run.record("vertical", skipped("openintel-subs", "configured binary or db not found"))
        return set()
    raw = ctx.run.raw_path("vertical", "openintel", f"{apex}.txt")
    r = exec_tool("openintel-subs", [exe, "query", "-d", apex, "-s", "-b", db],
                  raw_path=raw, timeout=timeout)
    ctx.run.record("vertical", r)
    if r.status not in (Status.SUCCESS, Status.EMPTY) or not (r.raw_path and Path(r.raw_path).exists()):
        return set()
    out = Path(r.raw_path).read_text(encoding="utf-8", errors="replace")
    return {h for h in (line.strip().lower().rstrip(".") for line in out.splitlines())
            if h and "." in h}


#: the provider's own 403 sentence for a Free PAT hitting the org-gated Platform search API.
CENSYS_ORG_REQUIRED = ("This endpoint requires an organization ID for API access. Free users can only "
                       "access this endpoint through the Platform UI.")


def censys_entitlement_skip(cen: dict, apexes) -> bool:
    """Record a provider skip when a Censys token is configured without an org id: the Platform search
    API is org-gated, so a Free PAT cannot run this lane. Only that one state is reported (no config, or
    an org with no token, stays silent). Returns True when the skip was recorded."""
    if not (cen.get("token") and not cen.get("org")):
        return False
    run_provider("vertical.censys",
                 lambda: (_ for _ in ()).throw(ProviderSkip(
                     f"Censys token configured WITHOUT an organization id — the Platform search API is "
                     f"org-gated (MEASURED 2026-07-30: HTTP 403 \"{CENSYS_ORG_REQUIRED}\"). A Free account "
                     f"cannot run this lane; nothing was queried and no credit was spent.")),
                 input_total=len(list(apexes)))
    return True


def _censys_hit_names(hit: dict) -> list:
    """The cert-names list from the exact Censys hit path ``certificate_v1.resource.names`` — no fallbacks.
    An absent path or non-list value is a schema failure (raised), never a silent skip."""
    res = hit.get("certificate_v1")
    res = res.get("resource") if isinstance(res, dict) else None
    names = res.get("names") if isinstance(res, dict) else None
    if not isinstance(names, list):
        raise ValueError("censys: hit missing certificate_v1.resource.names list — schema failure")
    return names


def _censys_next_token(doc: dict) -> str | None:
    """Extract the Platform v3 next-page token from its known locations (result.links.next /
    result.next_page_token / next_page_token), returning a non-empty string or None."""
    res = doc.get("result") if isinstance(doc.get("result"), dict) else {}
    links = res.get("links") if isinstance(res.get("links"), dict) else {}
    for v in (links.get("next"), res.get("next_page_token"), doc.get("next_page_token")):
        if isinstance(v, str) and v:
            return v
    return None


def _censys(cfg: dict, apex: str, timeout: int = 30, max_pages: int = 5) -> set:
    """Optional Censys Platform v3 global-search cert query for `apex` -> subdomain set. Empty (silent)
    unless both `token` and `org` are configured. Query is CenQL `cert.names: "<apex>"`. Fail-closed parse:
    names come from `certificate_v1.resource.names`, filtered to the queried apex; a missing path / non-list
    / non-string raises. Follows the `page_token` cursor up to `max_pages`; hitting the cap with a live token
    (or a later-page failure) returns a PARTIAL ProviderResult keeping earlier pages. Errors propagate."""
    token, org = cfg.get("token"), cfg.get("org")
    if not token or not org:
        return set()                                        # not configured
    hosts: set = set()
    page_token = None
    pages = 0
    truncated = False
    for i in range(max(1, max_pages)):
        pages = i + 1
        # quote the apex (a numeric-leading domain is not a valid unquoted CenQL literal); request only
        # `cert.names` so the response carries exactly the field we parse.
        payload = {"query": f'cert.names: "{apex}"', "page_size": 100, "fields": ["cert.names"]}
        if page_token:
            payload["page_token"] = page_token              # v3 pagination field (not `cursor`)
        req = urllib.request.Request(
            "https://api.platform.censys.io/v3/global/search/query", data=_json.dumps(payload).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {token}", "X-Organization-ID": str(org),
                     "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
        try:
            # fetch and validate/extract in one block: a later-page schema/parse error must preserve
            # earlier pages, not propagate and lose them.
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = read_bounded(r, CENSYS_READ_LIMIT, provider="censys", bound="CENSYS_READ_LIMIT").decode("utf-8", "replace")
            doc = _json.loads(raw)
            # a success carries a `result` object whose `hits` is a list; anything else is malformed
            if not (isinstance(doc, dict) and isinstance(doc.get("result"), dict)
                    and isinstance(doc["result"].get("hits"), list)):
                raise ValueError("censys: unexpected response envelope (no 'result.hits' list) — not a valid empty result")
            hits = doc["result"]["hits"]
            page_hosts = set()
            for hit in hits:
                if not isinstance(hit, dict):
                    raise ValueError("censys: non-object hit row")
                for nm in _censys_hit_names(hit):
                    if not isinstance(nm, str):
                        raise ValueError("censys: hit name is not a string")
                    nm = nm.lower().strip(".")
                    if nm == apex or nm.endswith("." + apex):   # keep names under the queried apex
                        page_hosts.add(nm)
            nxt = _censys_next_token(doc)
        except Exception as e:
            if i == 0:                                       # first-page failure propagates
                raise
            return ProviderResult(hosts, partial=True, cursor=page_token, pages=i,
                                  error_class=classify_provider_error(e))
        hosts |= page_hosts                                  # merge only a fully-validated page
        if not nxt or nxt == page_token:                     # no next page (or non-advancing token)
            break
        page_token = nxt
    else:
        truncated = True                                     # ran all max_pages with a live token
    return ProviderResult(hosts, partial=truncated, cursor=page_token, pages=pages)


#: max bytes read from one response per free source; hitting it raises `oversize` (ours), not `parse`.
CENSYS_READ_LIMIT = 64 * 1024 * 1024
CRTSH_READ_LIMIT = 64 * 1024 * 1024
CERTSPOTTER_READ_LIMIT = 64 * 1024 * 1024


def _crtsh(apex: str, timeout: int = 30) -> set:
    """Direct crt.sh CT-log pull for `%.apex` -> set of hostnames (SANs, wildcards stripped). Keyless,
    complements subfinder's CT sources. Errors propagate to run_provider (never a fake-empty)."""
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = read_bounded(r, CRTSH_READ_LIMIT, provider="crt.sh", bound="CRTSH_READ_LIMIT")
    rows = _json.loads(data.decode("utf-8", "replace"))
    # success shape is a JSON array; a non-list root is an error, not zero results
    if not isinstance(rows, list):
        raise ValueError("crt.sh: non-list JSON root — not a valid empty result")
    hosts = set()
    for row in rows:
        if not isinstance(row, dict):                        # fail-closed: a non-object row is corruption
            raise ValueError("crt.sh: non-object row")
        for nv in str(row.get("name_value", "")).splitlines():
            h = nv.strip().lower().strip(".")
            if h and "." in h:
                hosts.add(h)
    return hosts


def _certspotter(apex: str, token: str | None = None, timeout: int = 30, max_pages: int = 5) -> set:
    """certspotter (SSLMate CT Search API v1) issuances for `apex` (+subdomains) -> set of hostnames.
    Keyless free tier; a token raises the rate limit. Paginates via `after=<last issuance id>` until an
    empty page (a short page is not terminal). Bounded to `max_pages`; hitting the cap with a live cursor
    returns a PARTIAL ProviderResult. Errors propagate to run_provider."""
    base = (f"https://api.certspotter.com/v1/issuances?domain={apex}"
            "&include_subdomains=true&expand=dns_names")
    headers = {"User-Agent": "Mozilla/5.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    hosts: set = set()
    after = None
    pages = 0
    truncated = False
    for i in range(max(1, max_pages)):
        pages = i + 1
        url = base + (f"&after={urllib.parse.quote(after)}" if after else "")   # encode the opaque cursor id
        try:
            # fetch and validate/extract in one block: a later-page schema/parse error must preserve
            # earlier pages, not propagate and discard them.
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                rows = _json.loads(read_bounded(r, CERTSPOTTER_READ_LIMIT, provider="certspotter", bound="CERTSPOTTER_READ_LIMIT")
                                   .decode("utf-8", "replace"))
            # success shape is a JSON array of issuances; a non-list root is an error
            if not isinstance(rows, list):
                raise ValueError("certspotter: non-list JSON root — not a valid empty result")
            page_hosts = set()
            for row in rows:
                if not isinstance(row, dict):                # fail-closed: a non-object row is corruption
                    raise ValueError("certspotter: non-object issuance row")
                # expand=dns_names was requested, so each row must carry a list of strings
                dns_names = row.get("dns_names")
                if not isinstance(dns_names, list) or not all(isinstance(x, str) for x in dns_names):
                    raise ValueError("certspotter: dns_names is not a list of strings")
                for h in dns_names:
                    h = h.strip().lower().strip(".")
                    if h and "." in h:
                        page_hosts.add(h)
            if rows:                                         # the cursor id must be a scalar (str/int)
                _id = rows[-1].get("id")
                if _id is not None and not isinstance(_id, (str, int)):
                    raise ValueError(f"certspotter: cursor id not a scalar ({type(_id).__name__})")
                nxt = str(_id or "")
            else:
                nxt = ""
        except Exception as e:
            # a later-page failure keeps earlier pages as PARTIAL; only a first-page failure propagates
            if i == 0:
                raise
            return ProviderResult(hosts, partial=True, cursor=after, pages=i, error_class=classify_provider_error(e))
        hosts |= page_hosts                                  # merge only a fully-validated page
        if not rows:
            break                                            # empty array = documented end of pagination
        if not nxt or nxt == after:                          # no cursor / non-advancing
            break
        after = nxt
    else:
        truncated = True                                     # ran all max_pages without an empty page
    return ProviderResult(hosts, partial=truncated, cursor=after, pages=pages)


def _massdns_a(path: Path) -> dict[str, list[str]]:
    """Parse puredns' massdns simple output (`host. A 1.2.3.4`) -> {host: [A records]}. A missing or
    garbled file yields {}."""
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
    for p in (home / ".config/quarry/wordlists/dns.txt",       # canonical
              home / ".config/quarry/dns-wordlist.txt",        # back-compat
              home / "wordlists/best-dns-wordlist.txt",
              home / "wordlists/subdomains.txt"):
        if p.exists():
            return p
    return None


_LABEL_RX = _re.compile(r"[a-z0-9][a-z0-9-]{1,62}")


def _target_wordlist(ctx, loss: dict | None = None) -> list[str]:
    """A1d — build a target-specific label wordlist from what the crawl mined. Harvests every
    `*_wordlist.txt` xnLinkFinder produced, tokenizes each entry into DNS-label pieces, keeps plausible
    labels (has a letter, len>=3, valid label chars) and dedups in encounter order. Retention only:
    base-dictionary subtraction and the selection bound are the caller's job. `loss` is an out-parameter
    for undecodable lines and unreadable artifacts, filled even on early returns."""
    loss = loss if loss is not None else {}
    loss.setdefault("dropped_lines", 0)
    loss.setdefault("unreadable_files", 0)
    loss.setdefault("files", 0)
    #: word -> the artifacts that produced it; what the scheduler attributes a submitted word against.
    origins = loss.setdefault("origins", {})
    wl_dir = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder"
    if not wl_dir.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    dropped = 0
    for f in sorted(wl_dir.glob("*_wordlist.txt")):
        loss["files"] += 1
        try:
            raw = f.read_bytes()
        except OSError:
            loss["unreadable_files"] += 1
            continue
        for chunk in raw.splitlines():
            # strict decode: these words drive an active puredns brute, so an undecodable line is a
            # dropped line, not vocabulary.
            try:
                line = chunk.decode("utf-8")
            except UnicodeDecodeError:
                dropped += 1
                continue
            for piece in _LABEL_RX.findall(line.strip().lower()):
                if len(piece) >= 3 and any(c.isalpha() for c in piece):
                    origins.setdefault(piece, set()).add(f.name)
                    if piece not in seen:
                        seen.add(piece)
                        out.append(piece)
    loss["dropped_lines"] = dropped
    return out


#: an exact DNS label: letters/digits/hyphen, no leading/trailing hyphen, 1..63 chars; the gate between a
#: mined word and a hostname Quarry will contact. Matched with `fullmatch` (not `$`, which allows a newline).
_DNS_LABEL_RX = _re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")

#: how many labels one wildcard pass may probe per zone. A policy bound (brute load), reported separately
#: from what the parser could not use.
WILDCARD_WORD_CAP = 5000

#: bump when the differ's parser changes what the same artifact means; a different parser is a different
#: work unit.
WC_PARSER_SCHEMA = 2

#: how many eligible wildcard zones one run may contact. A throughput allowance, not a membership cap: the
#: rotation continues across runs. `0` removes the per-run limit.
WILDCARD_ZONES_PER_RUN = 5

#: permutation rounds over names already held; the loop stops when a round adds nothing. `--unbound` sets
#: it to 0 = until convergence.
MAX_ITERS = 3


def wildcard_zones_per_run() -> int:
    """Per-run zone allowance from PERFORMANCE (0 under `quarry run --unbound`). Read at call time so a
    test or operator setting is honoured."""
    from .. import settings as _settings
    return _settings.strict_int("WILDCARD_ZONES_PER_RUN", default=WILDCARD_ZONES_PER_RUN, maximum=10000)


def _wc_with_ledger(st: dict, why: str, raised=None) -> str:
    """Fold any recorded ledger failure into an exceptional exit's reason. The raised failure is skipped
    by identity, not by matching its rendered text (two failures can carry the same type and message)."""
    ids = st.get("ledger_error_ids") or []
    errs = [e for i, e in enumerate(st.get("ledger_errors") or [])
            if raised is None or i >= len(ids) or ids[i] != id(raised)]
    return "; ".join(p for p in (why, f"{len(errs)} tool result(s) not recorded ({'; '.join(errs)})"
                                 if errs else "") if p)


def _wc_base_facts(st: dict, kept: set) -> str:
    """The measured zone facts for an exceptional exit, or the statement that eligibility was never
    determined (composing `_wc_terminal` before eligibility is known would assert a false zero)."""
    if not st.get("eligibility_known"):
        return "the eligible wildcard zone set was never determined"
    return _wc_terminal(st, kept)[1] or ""


def _wc_reasons(st: dict) -> tuple:
    """(selection, execution, combined) causes from the raw facts only, so it is idempotent whether the
    body finished or a gate returned early."""
    blocked = st.get("blocked", {}) or {}
    sel = "; ".join(p for p in (
        st.get("selection_reason") or "",
        f"{blocked.get('zone_cap', 0)} zone(s) deferred to a later run by the "
        f"{wildcard_zones_per_run()}-zone per-run allowance" if blocked.get("zone_cap") else "",
        f"{blocked.get('self_or_private', 0)} zone(s) refused by the self/private contact guard"
        if blocked.get("self_or_private") else "") if p)
    ex = "; ".join(p for p in (st.get("gate_reason") or "", st.get("stopped") or "") if p)
    return sel, ex, "; ".join(p for p in (ex, sel) if p)


def _wc_report(sid: str, label: str, st: dict) -> None:
    """Every coverage record this lane owns, emitted from one boundary the wrapper runs on every path."""
    if not st.get("eligibility_known"):
        # scope filtering never finished, so the eligible set is UNKNOWN, not zero
        for measure, unit in (("zones", label), ("zone_execution", f"{label}:execution")):
            events.coverage_partial(sid, kind=events.COVERAGE_UNKNOWN, unit=unit, measure=measure,
                                    reason=f"{label}: the eligible wildcard zone set could not be "
                                           f"determined — nothing was selected or probed")
        _wc_rows_coverage(sid, label, st)
        _wc_artifact_coverage(sid, label, st)
        return
    eligible = st.get("eligible_zones", 0)
    selected = max(0, eligible - st.get("blocked", {}).get("zone_cap", 0)
                   - st.get("blocked", {}).get("self_or_private", 0))
    probed = st.get("probed_zones", 0)
    sel_why, exec_why, _ = _wc_reasons(st)
    events.coverage_partial(sid, kind=events.COVERAGE_CAP, measure="zones", unit=label,
                            eligible=eligible, tested=selected, omitted=max(0, eligible - selected),
                            reason=f"{label}: wildcard vhost zones {selected}/{eligible} selected for "
                                   f"contact" + (f" ({sel_why})" if sel_why else ""))
    missing = max(0, selected - probed)
    events.coverage_partial(sid,
                            # execution is timeout-class only when a selected zone did not return
                            kind=events.COVERAGE_TIMEOUT if missing else events.COVERAGE_CAP,
                            measure="zone_execution", unit=f"{label}:execution",
                            eligible=selected, tested=probed, omitted=missing,
                            reason=f"{label}: {probed}/{selected} selected zone(s) returned an invocation"
                                   + (f" ({exec_why})" if exec_why else ""))
    if st.get("vocabulary"):
        _wc_vocab_coverage(sid, label, st["vocabulary"])
    _wc_rows_coverage(sid, label, st)
    _wc_artifact_coverage(sid, label, st)


def _wc_artifact_coverage(sid: str, label: str, st: dict) -> None:
    """Structured artifact coverage: an invocation that returned but wrote no output is evidence we asked
    for and did not get. The denominator is every invocation that returned, whatever its status."""
    returned = st.get("returned_invocations", 0)
    missing = st.get("missing_artifacts", 0) + st.get("unreadable_artifacts", 0)
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT if missing else events.COVERAGE_CAP,
                            unit=f"{label}:artifacts", measure="output_artifacts",
                            eligible=returned, tested=max(0, returned - missing), omitted=missing,
                            reason=(f"{label}: {max(0, returned - missing)}/{returned} returned "
                                    f"invocation(s) left an artifact"
                                    + (f" — {st.get('missing_artifacts', 0)} produced none, "
                                       f"{st.get('unreadable_artifacts', 0)} unreadable" if missing
                                       else "")))


def _wc_rows_coverage(sid: str, label: str, st: dict) -> None:
    """Structured output-row coverage: rows we could not read are evidence we did not get. Emitted on
    every run, including the clean zero, because coverage is latest-per-(source, unit)."""
    seen, parsed = st.get("rows_seen", 0), st.get("rows_parsed", 0)
    lost = max(0, seen - parsed)
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT if lost else events.COVERAGE_CAP,
                            unit=f"{label}:rows", measure="output_rows",
                            eligible=seen, tested=parsed, omitted=lost,
                            reason=(f"{label}: {parsed}/{seen} output row(s) parsed"
                                    + (f" — {lost} unreadable or not this invocation's" if lost else "")))


def _wc_vocab_coverage(sid: str, label: str, vocab: dict) -> None:
    """Structured vocabulary coverage for a wildcard pass: words we could not use are un-probed surface.
    Parsing is counted in `vocabulary_entries` (what the input offered), selection in `vocabulary_words`
    (what survived parsing) — the two stages are sequential over the same words, so they use distinct
    measures to keep a rollup from double-counting them."""
    lost = vocab["undecodable"] + vocab["rejected"]
    # coverage is latest-per-(source, unit), so a clean pass must say so
    if vocab["unreadable"]:
        # a present list we cannot read: ran, unmeasurable -> a gap the reconciler admits
        events.coverage_partial(sid, kind=events.COVERAGE_UNKNOWN,
                                unit=f"{label}:vocabulary", measure="vocabulary_entries",
                                reason=f"{label}: the wildcard wordlist is present and UNREADABLE — the "
                                       f"generic vocabulary was NOT probed")
    else:
        eligible = vocab["valid_entries"] + lost
        events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT,
                                unit=f"{label}:vocabulary", measure="vocabulary_entries",
                                eligible=eligible, tested=vocab["valid_entries"], omitted=lost,
                                reason=f"{label}: {vocab['valid_entries']}/{eligible} vocabulary entr(ies) "
                                       f"usable — {vocab['undecodable']} not valid UTF-8, "
                                       f"{vocab['rejected']} not a single DNS label (a URL-shaped word "
                                       f"would introduce another authority); {vocab['usable']} unique "
                                       f"name(s) after canonicalisation")
    # retention is its own fact, under its own stable unit: what the parse produced is not what a bound
    # submits.
    events.coverage_partial(sid, kind=events.COVERAGE_CAP,
                            unit=f"{label}:vocabulary_cap", measure="vocabulary_words",
                            eligible=vocab["usable"], tested=vocab["selected"], omitted=vocab["withheld"],
                            # this stage retains; the per-zone spend bound withholds candidate pairs (the
                            # scheduler's `candidate_pairs` measure), not vocabulary.
                            reason=f"{label}: {vocab['selected']}/{vocab['usable']} usable name(s) RETAINED "
                                   f"for probing — the per-zone spend bound withholds candidate pairs, not "
                                   f"vocabulary")


class _LedgerStop(RuntimeError):
    """This lane's own stop: an invocation whose result could not be recorded. A named type gives the
    scheduler's contained-exception record a structural identity the lane can recognise without matching
    English."""


def _wc_continuation(ctx, st: dict, phase: str, label: str) -> str:
    """Selected, completed and remaining zones, plus the command that continues this rotation. Answered
    is this lifecycle's (zones whose invocation came back usable); owed is cumulative from the durable
    rotation. Pairs withheld by the per-zone spend bound are stated beside the zone remainder as a
    separate unit. Returns "" when the sweep never reported or nothing is owed."""
    eligible = int(st.get("eligible_zones", 0))
    selected = int(st.get("admitted_zones", 0))
    pairs_left = int((st.get("candidate_pairs_by_cause") or {}).get("bound", 0))
    st["zones_selected"] = selected
    if "zones_remaining" not in st:
        # the sweep never reported, so nothing here knows what is still owed
        st["zones_completed"] = int(st.get("zones_obtained", 0))
        return ""
    answered = int(st.get("zones_obtained", 0))
    st["zones_completed"] = answered
    remaining = int(st["zones_remaining"])
    if not remaining and not pairs_left:
        return ""
    target = getattr(getattr(ctx, "profile", None), "target", None) or "<target>"
    more = f" · {pairs_left} candidate pair(s) still owed by contacted zone(s)" if pairs_left else ""
    return (f"  {label}: {selected}/{eligible} zone(s) selected · {answered} answered this run · "
            f"{remaining} still owed by the rotation{more}\n"
            f"      continue: quarry run -t {target} --phases {phase}"
            # `--unbound` lifts volume bounds only; a guard-refused/unschedulable zone stays out of reach
            + (f"   (or --unbound to sweep the remaining SCHEDULABLE zone(s) in one run, without the "
               f"per-run volume limits — guards and scope are unchanged)" if remaining else ""))


def _wc_reject_constant(token: str):
    """`json.loads(parse_constant=...)` hook: NaN/Infinity are not JSON and are not evidence."""
    raise ValueError(f"non-standard JSON constant {token!r}")


def _wc_eligible_zones(ctx, zones) -> list:
    """The zones this pass may contact: in scope, not out of scope. Computed by the wrapper so
    `input_total` is the real eligible set, and handed to the body so both agree."""
    scope = ctx.scope
    return sorted(z for z in zones if scope.in_scope(z) and not scope.is_oos(z))


def _wc_terminal(st: dict, kept: set):
    """One terminal for the differ. Three independent facts degrade it and accumulate: zones never
    contacted (a policy bound or the contact guard), invocations that did not return usable, and rows we
    could not parse."""
    eligible, probed = st.get("eligible_zones", 0), st.get("probed_zones", 0)
    obtained = st.get("zones_obtained", probed)
    classes = st.get("invocation_classes") or {}
    parse_errors = st.get("parse_errors", 0)
    blocked = st.get("blocked", {}) or {}
    why = st.get("blocked_reason") or ""
    if not eligible:
        return Status.EMPTY, why or "no in-scope wildcard zone"
    if not probed:
        # nothing contacted: a mode, a missing tool, no vocabulary, or the contact guard. A clean SKIP
        # only when nothing went wrong on the way — a failed write is trouble, not a skip.
        if st.get("ledger_errors") or st.get("unreadable_artifacts") or st.get("missing_artifacts"):
            return Status.FAILED, "; ".join(facts) if (facts := [p for p in (
                why, f"{len(st.get('ledger_errors') or [])} tool result(s) not recorded "
                     f"({'; '.join(st.get('ledger_errors') or [])})"
                if st.get("ledger_errors") else "") if p]) else "no zone was probed"
        return Status.SKIPPED, why or "no zone was probed"
    no_base = st.get("zones_without_baseline", 0)
    # the per-zone spend is a bound of this pass like the zone allowance: a run that submitted 3 of 10
    # candidate pairs is not a clean EMPTY however many zones it contacted.
    by_cause = st.get("candidate_pairs_by_cause") or {}
    pairs_bound = int(by_cause.get("bound", 0))
    ledger = st.get("ledger_errors") or []
    facts = [p for p in (why,
                         f"{len(ledger)} tool result(s) not recorded ({'; '.join(ledger)})"
                         if ledger else "",
                         f"{st.get('missing_artifacts', 0)} invocation(s) produced no artifact"
                         if st.get("missing_artifacts") else "",
                         f"{st.get('unreadable_artifacts', 0)} artifact(s) present and UNREADABLE "
                         f"({'; '.join(st.get('artifact_errors') or [])})"
                         if st.get("unreadable_artifacts") else "",
                         f"{no_base} zone(s) answered with NO wildcard baseline" if no_base else "",
                         f"{pairs_bound}/{st.get('candidate_pairs_eligible', 0)} candidate pair(s) "
                         f"withheld by the {st.get('word_spend', 0)}-per-zone spend bound — they rotate "
                         f"in on a later run" if pairs_bound else "",
                         # `invocation_classes` counts calls, and a zone can take several of them
                         f"invocation outcomes {dict(sorted(classes.items()))}" if classes else "",
                         f"{parse_errors} unparseable output row(s)" if parse_errors else "") if p]
    # a mid-run SKIP is dependency loss, not policy: the tool stopped and the rest went unprobed. Same
    # for an answer whose artifact never appeared.
    trouble = bool(classes or parse_errors or obtained < probed or st.get("stopped")
                   or st.get("missing_artifacts") or st.get("unreadable_artifacts"))
    bounded = bool(probed < eligible or blocked.get("self_or_private") or blocked.get("zone_cap")
                   or pairs_bound)
    if trouble:
        return ((Status.PARTIAL if kept else Status.FAILED),
                "; ".join(facts) or f"{probed}/{eligible} zone(s) probed")
    if bounded:
        # a clean operator boundary (zone cap, contact-guard refusal): LIMITED = clean, deliberately
        # incomplete — never FAILED, which would show a failed source for a run that behaved as configured
        return Status.LIMITED, "; ".join(facts) or f"{probed}/{eligible} zone(s) probed"
    # an absent wildcard baseline is a fact about the zone, not a failure of this pass
    return (Status.SUCCESS if kept else Status.EMPTY), "; ".join(facts) or None


def _wildcard_differentiate(ctx, zones: set, *, extra_words=None,
                            phase: str = "vertical", label: str = "wildcard",
                            source: str = "wildcard-http", stats: dict | None = None,
                            source_id: str = "vertical.wildcard_http",
                            word_spend: int | None = None) -> set[str]:
    """The differ's own source lifecycle: registry gate, one start, one terminal, whatever happens
    inside, so a manifest can tell a pass that never ran from one that ran and found nothing."""
    st = stats if stats is not None else {}
    st.clear()
    st.update({"eligible_zones": 0, "probed_zones": 0, "blocked_reason": "", "selection_reason": "",
               "gate_reason": "", "eligibility_known": False,
               "blocked": {"zone_cap": 0, "self_or_private": 0}})
    if not registered(source_id):
        # the gate comes before eligibility: a refused lane must not report work for a pass that never ran
        return set()
    machinery = None                # the exception that ended the pass, if one did
    unrecorded = None               # a failure to record the outcome
    kept: set[str] = set()          # hosts accepted as distinct vhosts (novel or already known)
    novel: set[str] = set()         # the subset the store had never seen — an echo detail, not production
    eligible: list = []
    started = False
    fp = None
    outcome = (Status.FAILED, "the wildcard differ did not report an outcome")
    try:
        # fallible setup lives inside the protected interval so a scope/zone/vocabulary failure still
        # emits a start/terminal pair.
        eligible = _wc_eligible_zones(ctx, zones)
        st["eligible_zones"] = len(eligible)
        st["eligibility_known"] = True          # a FAILED scope filter is not an empty set
        # per-run allowance is a selection fact whose worst case is known the moment eligibility is; the
        # sweep's real deferral count replaces it once it has run.
        _allow = wildcard_zones_per_run()
        st["blocked"]["zone_cap"] = max(0, len(eligible) - _allow) if _allow else 0
        # caller's spend, or this lane's registered bound read through the registry so `--unbound` lifts it
        spend = word_spend if word_spend is not None else policy.limit("WILDCARD_WORD_CAP")
        words = _wc_vocabulary(extra_words, st) if eligible else []
        # the key binds the vocabulary the invocation submits, canonicalised the way `write_list` does
        # (sorted + deduplicated), so two selections with the same members are the same submission.
        fp = events.work_unit(source_id,
                              inputs={"zones": eligible,
                                      "vocabulary": _wc_digest(sorted(set(words)))},
                              # `zones_per_run` is NOT in the identity (the rotation is durable across a
                              # change); `word_spend` stays because it changes slot boundaries and grouping.
                              config={"word_spend": spend},
                              schema_version=WC_PARSER_SCHEMA)
        events.tool_start(source_id, cmd=["httpx", "(wildcard-differ)"], input_total=len(eligible),
                          work_unit=fp)
        started = True
        _wc_differentiate(ctx, eligible, words=words, phase=phase, label=label, source=source, st=st,
                          source_id=source_id, kept=kept, novel=novel, word_spend=spend)
        outcome = _wc_terminal(st, kept)
    except (KeyboardInterrupt, SystemExit):
        # zone facts gathered before the exit are stated first — an invocation whose RunResult never
        # reached the ledger has no other durable trace.
        _base = _wc_base_facts(st, kept)
        outcome = ((Status.PARTIAL if kept else Status.FAILED),
                   _wc_with_ledger(st, "; ".join(p for p in (
                       _base, "CANCELLED mid-differ — evidence KEPT" if kept
                       else "CANCELLED mid-differ") if p)))
        raise                                                  # after the terminal, never before
    except Exception as ex:
        _base = _wc_base_facts(st, kept)                       # before the carrier is overwritten
        st["blocked_reason"] = f"{type(ex).__name__}: {ex}"
        machinery = ex
        outcome = ((Status.PARTIAL if kept else Status.FAILED),
                   _wc_with_ledger(st, "; ".join(p for p in (
                       _base, f"the wildcard differ failed ({type(ex).__name__}: {ex})") if p),
                                   raised=ex))
    finally:
        try:
            _wc_report(source_id, label, st)      # every record, on every path
        except Exception as e:
            # losing the accounting is machinery: a lane that reported nothing must not finish clean
            machinery = machinery or e
            outcome = ((Status.PARTIAL if kept else Status.FAILED),
                       "; ".join(p for p in (outcome[1], f"coverage could not be reported "
                                                         f"({type(e).__name__}: {e})") if p))
        why = outcome[1]
        if machinery is not None:
            # machinery only: a capped/guard-refused pass is the coverage record's, and invocation
            # already recorded by the body, one per call
            try:
                ctx.run.record(phase, RunResult("wildcard-differ", ["httpx", "(wildcard-differ)"],
                                                outcome[0], None, 0.0, None, 0, note=why))
            except Exception as e:
                why = f"{why}; the outcome could not be recorded ({type(e).__name__})"
                unrecorded = e
        if not started:
            # setup failed before the start: emit the pair anyway so the source never goes silent
            events.tool_start(source_id, cmd=["httpx", "(wildcard-differ)"],
                              input_total=len(eligible), work_unit=fp or "setup-failed")
        events.tool_finish(source_id, status=outcome[0].value, reason=why, work_unit=fp or "setup-failed",
                           produced={"subdomains": len(kept)})
        try:
            # operator-facing continuation; contained so a broken echo costs the hint, never the run
            line = _wc_continuation(ctx, st, phase, label)
            if line:
                ctx.echo(line)
        except Exception:
            pass
    if unrecorded is not None:
        # a generic terminal is not folded into the manifest verdict, so a failed record must propagate to
        # the phase boundary rather than leave the run reading `complete`.
        raise RuntimeError(f"{source_id}: the outcome could not be recorded "
                           f"({type(unrecorded).__name__}: {unrecorded})") from unrecorded
    return kept


def _wc_digest(words) -> str:
    """sha256 of the vocabulary as given. Callers pass the canonical form (sorted + deduplicated, what
    `write_list` writes) so the key describes the file that is really sent."""
    import hashlib as _h
    d = _h.sha256()
    for w in words or []:
        d.update(w.encode("utf-8"))
        d.update(b"\n")
    return d.hexdigest()


def _wc_vocabulary(extra_words, st: dict) -> list:
    """The ordered vocabulary this pass will submit, and the parse facts behind it. Extracted from the
    body so the work unit binds exactly what the invocation submits and an unreadable list fails inside
    the lifecycle."""
    from .probe import _vhost_wordlist          # dedicated small label list (lives in probe)
    # no fallback to the DNS brute list (vhost fuzzing is IPs x apexes x words, so it explodes): the pass
    # runs on the caller's mined vocabulary or reports a vocabulary gap and probes nothing
    wl = _vhost_wordlist()
    # a missing generic list is not a missing wordlist when the caller brought its own: A1d's mined words
    # plus the bogus baseline are enough to differentiate.
    vocab = {"lines": 0, "entries": 0, "valid_entries": 0, "usable": 0, "selected": 0, "withheld": 0,
             "accepted": 0, "undecodable": 0, "rejected": 0, "unreadable": False, "absent": wl is None}
    st["vocabulary"] = vocab
    generic: list = []
    if wl is not None:
        try:
            raw = Path(wl).read_bytes()
        except OSError:
            # absent and present-but-unreadable are different facts: the loss is measured, not
            # swallowed as b""
            raw = b""
            vocab["unreadable"] = True
        for chunk in raw.splitlines():
            vocab["lines"] += 1
            try:
                w = chunk.decode("utf-8").strip()  # strict: these labels are contacted, like every other
            except UnicodeDecodeError:             # active vocabulary
                vocab["undecodable"] += 1
                continue
            if w and not w.startswith("#"):
                generic.append(w)
    # A1d: fold the target-specific words (mined from the crawl) in front so the target's own naming
    # vocabulary is tried first.
    candidates = [w for w in (extra_words or []) if w] + generic
    # a decodable line is not a label: `https://outside.example/x` would build a name whose authority
    # httpx resolves off-scope. Every candidate is validated structurally at this boundary.
    valid: list = []
    for w in candidates:
        if _DNS_LABEL_RX.fullmatch(w):
            valid.append(w.lower())            # canonicalised before dedup: API and api are one name
        else:
            vocab["rejected"] += 1
    # entries = everything the input offered (including undecodable lines); valid_entries counts labels.
    # Deduplication is not a loss (two spellings are one name), so it is neither omitted nor eligible twice.
    vocab["valid_entries"] = len(valid)
    vocab["entries"] = len(valid) + vocab["rejected"] + vocab["undecodable"]
    usable = list(dict.fromkeys(valid))
    # the whole retained corpus goes to the scheduler; the per-zone spend rotates through it rather than
    # truncating it
    vocab["usable"] = vocab["accepted"] = vocab["selected"] = len(usable)
    vocab["withheld"] = 0
    return usable


def _wc_differentiate(ctx, _zones_all: list, *, words: list, phase: str, label: str, source: str,
                      st: dict, source_id: str, kept: set, novel: set, word_spend: int) -> None:
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
    # `st` is the caller's out-parameter: whether this pass ran cannot be inferred from "there were
    # zones". Snapshot semantics, so a reused dict cannot mix this call's counters with a previous.
    zones = list(_zones_all)          # membership is not cut; the sweep bounds throughput

    def _gate(reason: str, *, selection: bool = False) -> None:
        """A hard exit that records why and returns; the wrapper's reporting boundary emits every record,
        so an exception on the way out cannot take the accounting with it."""
        st["blocked_reason"] = reason
        st["selection_reason" if selection else "gate_reason"] = reason

    if not zones:
        # nothing eligible: still emit (0/0/0 is valid and clears any earlier gap for this unit)
        return _gate("no in-scope wildcard zone", selection=True)
    if scope.passive_only:
        # an intentional mode, not a gap
        st["blocked_reason"] = st["gate_reason"] = "passive-only mode"
        return None
    if not have("httpx"):
        ctx.run.record(phase, skipped("httpx", f"not installed — {len(_zones_all)} wildcard zone(s) "
                                               f"undifferentiated ({label})"))
        return _gate("httpx is not installed")
    if not words:
        return _gate("no usable vocabulary")       # nothing to probe with -> zero zones attempted
    block_private = netguard._block_private(ctx)

    def _sig(o):
        return (o.get("status_code"), o.get("content_length"),
                (o.get("title") or "").strip(), o.get("favicon"))

    zones_probed = 0                       # distinct zones contacted (never a call count)
    contacted_zones: set = set()
    obtained_zones: set = set()
    st["invocations"] = 0
    st["returned_invocations"] = 0
    st["zones_obtained"] = 0               # zones whose invocation came back usable
    st["invocation_classes"] = {}
    st["parse_errors"] = 0
    st["rows_seen"] = 0
    st["rows_parsed"] = 0
    st["zones_without_baseline"] = 0
    st["missing_artifacts"] = 0
    st["unreadable_artifacts"] = 0
    st["artifact_errors"] = []
    st["ledger_errors"] = []
    st["ledger_error_ids"] = []
    st["stopped"] = ""

    # the contact guard is active work (it resolves a name under the zone), so it runs only for the zones
    # the scheduler admits, once each, rather than over every eligible zone.
    def _guard(zone: str) -> bool:
        # self-attack guard: if the wildcard resolves to the scan box / metadata, don't vhost-scan the
        # zone (record it as intel). A private wildcard is contacted by default.
        _wstate, _wdeny, _wintel = netguard.contact_state(f"quarry-wc-guard-{_uuid.uuid4().hex[:8]}.{zone}",
                                                          block_private=block_private)
        if _wintel:
            netguard.record_internal(ctx, f"*.{zone}", _wintel)
        if _wstate in ("self", "private_blocked"):
            st["blocked"]["self_or_private"] += 1     # a guard refusal, not a cap omission
            return False
        return True

    def _probe(zone: str, unit: str, ws):
        """One httpx invocation against one zone — what the sweep submits for a batch of its slots."""
        nonlocal zones_probed
        ledger_error = None
        bogus = [f"quarry-wc-{_uuid.uuid4().hex[:10]}.{zone}" for _ in range(2)]
        # one token names the whole invocation pair, so a retry cannot overwrite the exact contacted set
        # (random baselines included) that an earlier recorded command still points at.
        attempt = _uuid.uuid4().hex[:12]
        cf = ctx.write_list(f"{label}_cand_{zone.replace('.', '_')}_{attempt}.txt",
                            [f"{w}.{zone}" for w in ws] + bogus)
        # immutable per-invocation path: a stable per-zone one let a timed-out retry re-read the previous
        # attempt's artifact or overwrite evidence earlier records point at.
        hx = ctx.run.raw_path(phase, label, f"{zone}-{unit}-{attempt}.jsonl")
        # -follow-redirects so the signature is the final response: without it every candidate gets the
        # wildcard's uniform 308->https, which "differs" from the 200 baseline and floods false positives.
        hx_cmd = ["httpx", "-l", str(cf), "-json", "-silent", "-sc", "-cl", "-title",
                  "-favicon", "-follow-host-redirects",   # same-host only (http->https collapse)
                  "-deny", netguard.self_deny_list(),     # never hit the scan box / metadata
                  "-t", str(settings.workers("httpx", 15))]
        if ctx.profile.http_rl:                           # honor a configured HTTP rate
            hx_cmd += ["-rl", str(ctx.profile.http_rl)]
        r = exec_tool("httpx", hx_cmd, raw_path=hx, timeout=ctx.http_timeout)
        # everything observable about this invocation is committed BEFORE the fallible ledger write, so a
        # `record()` that raises does not make the run forget what already happened.
        blob = None
        st["invocations"] = st.get("invocations", 0) + 1
        if r.status is Status.SKIPPED:
            # no process ran: not a zone contacted, and the tool will not run for the next zone either
            st["stopped"] = "httpx did not run"
        else:
            # a zone may take several invocations (batching, tiers); count distinct zones, not calls, so
            # `tested` cannot exceed `eligible`.
            contacted_zones.add(zone)
            zones_probed = len(contacted_zones)
            st["probed_zones"] = zones_probed
            st["returned_invocations"] = st.get("returned_invocations", 0) + 1
            if r.status in (Status.SUCCESS, Status.EMPTY):
                obtained_zones.add(zone)
                st["zones_obtained"] = len(obtained_zones)
            else:
                _k = str(getattr(r.status, "value", r.status))
                st["invocation_classes"][_k] = st["invocation_classes"].get(_k, 0) + 1
            # ask the REQUESTED path, not `RunResult.raw_path` (which means "captured non-empty stdout"):
            # absent or unreadable is loss, present-and-empty is a clean nothing-found.
            try:
                blob = hx.read_bytes()
            except FileNotFoundError:
                st["missing_artifacts"] += 1
            except OSError as e:
                st["unreadable_artifacts"] += 1
                st["artifact_errors"].append(f"{zone}: {type(e).__name__}")
        try:
            ctx.run.record(phase, r)
        except Exception as e:
            # the invocation happened and its bytes are in hand: keep the failure and raise it AFTER this
            # artifact is accounted for and ingested, so it degrades the run without erasing what it found.
            st["ledger_errors"].append(f"{zone}: {type(e).__name__}: {e}")
            st["ledger_error_ids"].append(id(e))       # identity, for the dedupe in `_wc_with_ledger`
            ledger_error = e
        if r.status is Status.SKIPPED or blob is None:
            # nothing left to ingest for this zone; if the ledger also failed, raise now rather than
            # contacting another zone.
            if ledger_error is not None:
                st["stopped"] = st.get("stopped") or "the invocation could not be recorded"
                st["ledger_raised"] = True     # the scheduler's machinery detail would repeat this
                raise _LedgerStop(str(ledger_error)) from ledger_error
            return r
        # bytes, not text: one invalid UTF-8 line costs one row, not the whole artifact. Every row is
        # validated structurally, and a row for a name this invocation never submitted is not our evidence.
        expected = {f"{w}.{zone}".lower() for w in ws} | {b.lower() for b in bogus}
        rows = []
        for chunk in blob.splitlines():
            if not chunk.strip():
                continue
            st["rows_seen"] += 1
            try:
                line = chunk.decode("utf-8")
            except UnicodeDecodeError:
                st["parse_errors"] += 1
                continue
            try:
                # strict JSON: NaN/Infinity would flow into a signature and a store row
                row = _json.loads(line, parse_constant=_wc_reject_constant)
            except (_json.JSONDecodeError, ValueError):
                st["parse_errors"] += 1
                continue
            if not isinstance(row, dict):
                st["parse_errors"] += 1
                continue
            host = row.get("input") or row.get("host")
            if not isinstance(host, str) or host.lower().rstrip(".") not in expected:
                st["parse_errors"] += 1
                continue
            # every field `_sig` and the store consume is validated, and the status code is required
            # (without one there is no HTTP signature). Values, not just types, are range/format-checked.
            sc = row.get("status_code")
            shape_ok = isinstance(sc, int) and not isinstance(sc, bool) and 100 <= sc <= 599
            cl = row.get("content_length")
            if cl is not None and (isinstance(cl, bool) or not isinstance(cl, int) or cl < 0):
                shape_ok = False
            title = row.get("title")
            if title is not None and not isinstance(title, str):
                shape_ok = False
            fav = row.get("favicon")
            if fav is not None and (isinstance(fav, bool) or not isinstance(fav, (str, int))):
                shape_ok = False                 # httpx writes a hash or a string; never a bool or float
            addrs = row.get("a")
            if addrs is not None:
                # `a` is httpx's A-record list: exact IPv4 strings only (ip_address accepts a bare int as
                # a packed address, so reject non-strings before canonicalising).
                if not isinstance(addrs, list):
                    shape_ok = False
                else:
                    canon = []
                    for x in addrs:
                        if not isinstance(x, str):
                            shape_ok = False
                            break
                        try:
                            canon.append(str(_ipaddress.IPv4Address(x)))
                        except _ipaddress.AddressValueError:
                            shape_ok = False
                            break
                    else:
                        row["a"] = canon
            if not shape_ok:
                st["parse_errors"] += 1
                continue
            st["rows_parsed"] += 1
            rows.append(row)
        _bogus_lower = {b.lower() for b in bogus}
        base = {_sig(o) for o in rows
                if (o.get("input") or o.get("host") or "").lower().rstrip(".") in _bogus_lower}
        if not base:
            # "the random controls did not respond" is not "nothing responded": with no baseline each
            # is distinct, so record the fact and judge the zone on its rows
            if any(r_ for r_ in rows if (r_.get("input") or r_.get("host") or "").lower().rstrip(".")
                   not in _bogus_lower):
                st["zones_without_baseline"] += 1
        for o in rows:
            host = (o.get("input") or o.get("host") or "").lower().rstrip(".")
            if not host or host in bogus or not scope.in_scope(host) or scope.is_oos(host):
                continue
            if (o.get("status_code") or 0) // 100 == 3:   # un-followed redirect = infra noise, not a vhost
                continue
            if _sig(o) not in base:             # differs from the wildcard baseline -> a real vhost
                # `Run.add` answers "new entity", not "accepted": acceptance is the production fact,
                # novelty an echo detail.
                if ctx.run.add("subdomain", {"host": host, "sources": [source],
                                             "raw_ref": str(hx)}):
                    novel.add(host)
                # the resolved observation is this pass's own evidence, independent of subdomain novelty
                ctx.run.add("resolved", {"host": host, "a": o.get("a") or [],
                                         "sources": [source], "raw_ref": str(hx)})
                kept.add(host)
        if ledger_error is not None:
            # this zone's evidence is in, and there is no further contact after a write we could not make:
            # raise with a machinery cause and leave the remaining zones to a later lifecycle.
            st["stopped"] = st.get("stopped") or "the invocation could not be recorded"
            st["ledger_raised"] = True         # the scheduler's machinery detail would repeat this
            raise _LedgerStop(str(ledger_error)) from ledger_error
        return r

    # which zones this lifecycle contacts, and in which order, is the sweep's: the rotation is durable and
    # project-scoped, so a bounded run advances instead of re-probing the same zones forever.
    swept = sweep.run_sweep(
        lane=f"wc_{source_id.replace('.', '_')}",
        state_dir=Path(ctx.run.project_dir) / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}",
        targets=zones, vocabulary=lambda _zone: list(words), execute=_probe, admit=_guard,
        budget_s=budget.budget_seconds("WILDCARD_BUDGET_S"), coverage_lane=source_id,
        dependency_ok=lambda: have("httpx"), max_pairs_per_target=word_spend,
        max_targets_per_run=wildcard_zones_per_run())
    # the per-run withholding is a candidate-pair fact, in the unit the scheduler measures — the
    # vocabulary is retained whole, and the spend bound rotates through it rather than truncating it.
    st["word_spend"] = word_spend
    st["candidate_pairs_eligible"] = swept.eligible_pairs
    st["candidate_pairs_submitted"] = swept.attempted_pairs
    st["candidate_pairs_withheld"] = max(0, swept.eligible_pairs - swept.attempted_pairs)
    # the remainder is not one fact: a guard refusal, a deferred zone, unschedulable work and a stop each
    # own their pairs, and only what is left belongs to the per-zone spend bound
    st["candidate_pairs_by_cause"] = swept.pair_remainder()
    # what this lane still OWES, in the supervisor's vocabulary (settle prerequisite B). Best effort: a
    # remainder is a REPORT, and losing it may never cost the run.
    try:
        if swept.remainder_known:          # zeroes we did not measure would read as a fixed point, so an
            remainder.emit(remainder.from_sweep(source_id, swept))   # unmeasured remainder says UNKNOWN
        else:                              # — ran and cannot say, which is not the same as not running
            remainder.unknown(source_id, why="the eligible set was never established")
    except Exception as _e:                                  # noqa: BLE001 - a report is never a stop
        st.setdefault("machinery", []).append(f"remainder not reported ({type(_e).__name__})")
    st["sweep_stop"] = swept.stop or ""
    st["sweep_stop_kind"] = swept.stop_kind or ""
    st["admitted_zones"] = swept.targets_admitted
    # CUMULATIVE, from the rotation ledger — not this lifecycle's arithmetic (step 4 review)
    st["zones_complete"] = swept.targets_complete
    st["zones_remaining"] = swept.targets_remaining
    st["deferred_zones"] = swept.deferred_targets
    st["blocked"]["zone_cap"] = swept.deferred_targets       # deferred to a LATER run, never dropped
    st["refused_zones"] = swept.targets_refused              # the guard's own answer, per ADMITTED zone
    # the lane's own cause and the scheduler's DETAIL are both facts — composing them keeps the
    # underlying error text (which the machinery entry carries) beside the lane's sentence.
    if st.get("ledger_raised"):
        # the scheduler's contained exception can duplicate the ledger failure the lane already names, so
        # the duplicate is identified by the scheduler's structured record, never by matching sentence text
        _dupe = {c.get("index") for c in swept.contained
                 if c.get("phase") == "execute" and c.get("exc") == _LedgerStop.__name__}
        swept.machinery = [m for i, m in enumerate(swept.machinery) if i not in _dupe]
    _sweep_why = "; ".join(swept.machinery) if swept.machinery else (
        swept.stop or "" if swept.stop_kind in ("machinery", "dependency", "contention", "budget")
        else "")
    st["stopped"] = "; ".join(p for p in (st.get("stopped") or "", _sweep_why) if p)
    # zone reasons only; the vocabulary facts live in `stats["vocabulary"]`
    st["blocked_reason"] = _wc_reasons(st)[2]
    if kept:
        ctx.echo(f"  wildcard: {len(kept)} distinct vhost(s) differentiated, {len(novel)} new ({label})")


def _github_subs(ctx, prof, scope) -> None:
    """github-subdomains — its own seam, because it is a door (acquisition closure).

    An external tool that paginates the GitHub code-search API internally, run through `exec_tool`, so no
    registry gate covers it and Quarry hands it our key: that makes it acquisition, and a campaign that closed
    acquisition stops it here. The gate comes before the token file is minted, so a declined lane never leaks
    a credential.
    """
    allowed, why = campaign.acquisition_allowed("vertical.github_subs")
    if not allowed:
        events.tool_blocked("vertical.github_subs", reason=why)
        ctx.run.record("vertical", skipped("github-subdomains", why))   # ONE skip, with the real cause
        return
    gh_token = secrets.github_tokens_file()   # 0600 temp file from secrets.yaml; None if unset
    if not gh_token:
        ctx.run.record("vertical", skipped("github-subdomains", "no GitHub token in secrets.yaml"))
        return
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


def _recursive_permute(ctx, prof, scope, trusted, resolvers, wildcard_zones) -> None:
    """The recursive permute -> resolve loop, in its own seam (flag-axis step 4).

    Extracted UNCHANGED from `run()` so the rounds policy can be driven directly: `--unbound` sets
    MAX_ITERS to 0 = "until it converges", and an unbounded loop is only safe if its termination is
    tested rather than assumed."""
    rounds = policy.limit("MAX_ITERS")          # 0 = until it converges (`--unbound`)
    stop, made = "bound", False        # WHY the loop ended, and whether its LAST round found anything
    clean_batch = True                 # ...and whether the last resolver batch could be trusted
    prev = -1
    seen_candidates: set[str] = set()
    it = 0
    while not rounds or it < rounds:
        it += 1
        base = ctx.run.count("resolved")           # the baseline THIS round has to beat
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
            # passive = no target contact: `dnsx -a` resolves against the target's DNS, so it is skipped;
            # passively-discovered names are already stored, just not resolved to A records here
            ctx.run.record("vertical", skipped("dnsx", "passive-only mode — no recursive DNS resolution"))
            stop = "passive"
            break

        # frontier-only: resolve only candidates NOT already ATTEMPTED-AND-SETTLED (dedup, first-seen order).
        new_cand = [c for c in dict.fromkeys(cand) if c and c not in seen_candidates]
        _n_all, _n_new = len(set(filter(None, cand))), len(new_cand)
        if not new_cand:
            ctx.echo(f"  recursion iter {it}: no new candidates — converged")
            stop = "no_candidates"
            break
        candidates = ctx.write_list(f"all_candidates_{it}.txt", new_cand)
        res = ctx.run.raw_path("vertical", "puredns", f"resolved_{it}.txt")
        # --write-massdns captures the A records so `resolved` carries its IPs; puredns -q emits hostnames
        # only, and the digest and relationship layer want the host->IP edge on `resolved`
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
        # settle only when the batch is trustworthy: a clean puredns run settles all of new_cand, a
        # degraded one only the confirmed-resolved names (the rest stay retryable, bounded by MAX_ITERS)
        clean_batch = r.status in (Status.SUCCESS, Status.EMPTY)
        if clean_batch:
            seen_candidates.update(new_cand)
        else:
            seen_candidates.update(resolved_now)
            retryable = len(set(new_cand) - resolved_now)
            # the EFFECTIVE rounds decide, not the module default — and an unbounded run has no final
            # iteration to exhaust, so it never promises one it will not run (step 4 review)
            _budget = ("retry budget exhausted (final iteration)" if rounds and it >= rounds
                       else "retryable next iteration")
            events.coverage_partial("vertical.puredns_resolve", reason=f"iter {it}: puredns {r.status.value} — "
                                    f"{retryable} candidate(s) unresolved, {_budget}")

        cur = ctx.run.count("resolved")
        made = cur > base                          # did THIS round resolve anything new?
        ctx.echo(f"  recursion iter {it}: resolved={cur}"
                 + ("" if prev < 0 else f" (+{cur - prev} new)"))
        if prev >= 0 and cur == prev:
            # an unchanged count is convergence only after a clean batch; after a degraded one it is
            # a failure to resolve, not a fixed point
            stop = "converged" if clean_batch else "no_progress"
            break
        prev = cur

    # ── what ended the recursion — a fixed point or a bound, recorded where it happens ──

    # a bound stopping a still-producing run leaves the rounds unknowable, so bounded non-convergence
    # is unknown coverage; exact counters are emitted only when the recursion finished
    try:
        remainder.emit(remainder.for_rounds("vertical.alterx_permute", stop=stop, rounds=rounds,
                                            ran=it, made=made))
    except Exception:                                        # noqa: BLE001 - a report is never a stop
        pass
    if stop == "bound" and made:
        events.coverage_partial("vertical.alterx_permute", kind=events.COVERAGE_UNKNOWN,
                                unit="vertical.permute_rounds", measure="permutation_rounds",
                                reason=f"{it} permutation round(s) ran and the last one STILL found new "
                                       f"names — the {rounds}-round bound stopped the recursion before it "
                                       f"converged, and how many rounds convergence needs is UNKNOWN")
    elif stop == "no_progress":
        events.coverage_partial("vertical.alterx_permute", kind=events.COVERAGE_UNKNOWN,
                                unit="vertical.permute_rounds", measure="permutation_rounds",
                                reason=f"{it} permutation round(s) — the last round resolved nothing new "
                                       f"after a DEGRADED batch, whose unresolved candidates stay "
                                       f"retryable: that is a failure to resolve, not convergence")
    elif stop == "passive":
        # PASSIVE deliberately excludes this active work, so the eligible set is ZERO — not unknown. A
        # gap here would turn a clean passive run into `complete_with_gaps` for work it never owed.
        events.coverage_partial("vertical.alterx_permute", kind=events.COVERAGE_CAP,
                                unit="vertical.permute_rounds", measure="permutation_rounds",
                                eligible=0, tested=0, omitted=0,
                                reason="PASSIVE mode — recursive DNS resolution is not this run's work")
    else:
        events.coverage_partial("vertical.alterx_permute", kind=events.COVERAGE_CAP,
                                unit="vertical.permute_rounds", measure="permutation_rounds",
                                eligible=it, tested=it, omitted=0,
                                reason=(f"{it} permutation round(s) — the recursion CONVERGED"
                                        if stop == "converged" else
                                        f"{it} permutation round(s) — nothing new was left to submit"
                                        if stop == "no_candidates" else
                                        f"{it} permutation round(s) — the last round added no resolved "
                                        f"name, so the {rounds}-round bound cost nothing"))


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    roots_file = ctx.write_list("roots.txt", prof.apex_domains)

    # ── passive: subfinder (per APEX) ──
    _run_subfinder(ctx, prof, scope)

    # ── passive CT-log sources (crt.sh + certspotter), coverage over subfinder ──

    # a `*.X.apex` wildcard cert name registers `X.apex` as a wildcard brute-zone candidate (A1), which
    # brutes the zone and HTTP-differentiates instead of letting DNS strip them as noise
    wildcard_zones: set[str] = set()
    cs_token = secrets.certspotter()
    _max_pages = settings.concurrency("PROVIDER_MAX_PAGES", 5)   # bounded cursor pagination (configurable)
    ct_new = 0
    def _provider_over_apexes(src_id, per_apex, acct=None):
        """Run each (provider, apex) as its own work unit, so one apex's failure is FAILED for that unit only
        while every other apex's discovery is still unioned. Also gives providers a per-apex resume key.
        """
        h = set()
        for apex in prof.apex_domains:
            # fold the page budget and a non-secret account scope + credential fingerprint (never the
            # credential): a changed account sees different data, so it is a different resume identity
            cfg = {"max_pages": _max_pages, **(acct or {})}
            wu = events.work_unit(src_id, inputs={"apex": apex}, config=cfg)
            r = run_provider(src_id, lambda a=apex: per_apex(a), work_unit=wu, input_total=1)
            if r:                                            # None on failure (that apex's terminal is FAILED)
                h |= r
        return h
    _cs_acct = {"cred_fp": secrets.fingerprint(cs_token)} if cs_token else None   # certspotter token identity
    for src, fn, acct in (("crtsh", lambda a: _crtsh(a), None),
                          ("certspotter", lambda a: _certspotter(a, cs_token, max_pages=_max_pages), _cs_acct)):
        # bracket the in-process CT provider (native HTTP) with a per-apex source lifecycle
        hosts = _provider_over_apexes(f"vertical.{src}", fn, acct)
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
    censys_entitlement_skip(cen, prof.apex_domains)
    if cen.get("token") and cen.get("org"):
        # org id (non-secret) + a token fingerprint (never the token) — a different account/org
        # sees different data, so the resume identity must change with it.
        cen_acct = {"org": str(cen["org"]), "cred_fp": secrets.fingerprint(cen["token"])}
        cen_hosts = _provider_over_apexes("vertical.censys", lambda a: _censys(cen, a, max_pages=_max_pages), cen_acct)
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

    _github_subs(ctx, prof, scope)

    # ── shosubgo (Shodan subs, optional, needs key) ──
    sho_key = secrets.shodan()
    if have("shosubgo") and sho_key:
        sho = ctx.run.raw_path("vertical", "shosubgo", "sho.txt")
        sho.unlink(missing_ok=True)                    # stale artifact must not fake completion
        # `-fail`: exit 1 on any API error, or an auth error exits 0 and reads as clean-empty. shosubgo
        # writes to the -o file; reclassify inside the contract so the terminal carries the final status.
        def _sho_reclassify(res):
            hosts, artifact_ok = _shosubgo_read(sho)
            reclassify_from_artifact(res, None if hosts is None else len(hosts), label="shosubgo")
            # a clean-EXIT run whose artifact had malformed lines / bad UTF-8 is NOT a trustworthy clean
            # result: downgrade to PARTIAL (completion uncertain) while KEEPING the valid hosts.
            if not artifact_ok and res.status in (Status.SUCCESS, Status.EMPTY):
                res.status = Status.PARTIAL
                res.note = f"shosubgo: {len(hosts or [])} host(s) — artifact had malformed lines, completion uncertain"
            return res
        # C10b resume: work_unit = the apex-root set (the shosubgo query surface). API key is not folded (a
        # rotated key is the same coverage intent), but a changed root set is a new unit.
        sho_wu = events.work_unit("vertical.shosubgo", inputs={"roots": sorted(prof.apex_domains)})
        r = run_contract("vertical.shosubgo", ["shosubgo", "-f", str(roots_file),
                                               "-s", sho_key, "-o", str(sho), "-fail"],
                         work_unit=sho_wu, reclassify=_sho_reclassify, timeout=ctx.http_timeout)
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

    # ── recursive permute -> resolve loop (word-cloud mutations) ──

    # each iteration mines permutations, resolves, seeds the next; stops on nothing new. Frontier-only
    # resolve settles after a clean batch; alterx runs over the full set to keep its -enrich vocabulary.
    _recursive_permute(ctx, prof, scope, trusted, resolvers, wildcard_zones)

    # ── A1: wildcard-zone brute + HTTP-differentiation (recover vhosts a wildcard hides) ──

    # runs before the CNAME/takeover pass so recovered vhosts get takeover analysis; the derived zones
    # are persisted so the post-crawl A1d recursion can re-brute them
    for _z in sorted(wildcard_zones):
        ctx.run.add("wildcard_zone", {"value": _z})
    _wildcard_differentiate(ctx, wildcard_zones)

    # ── CNAME collection for subdomain-takeover analysis (workflow 1.13) ──
    if prof.takeover and scope.passive_only:
        # `dnsx -cname -a` resolves against the target's DNS — target contact, so skip in passive mode.
        ctx.run.record("vertical", skipped("dnsx", "passive-only mode — CNAME/takeover resolution skipped"))
    elif prof.takeover and have("dnsx"):
        # scan the union of resolved + all known subdomains: a dangling CNAME (a CNAME but no A record) is
        # the takeover signal, and it lives in `subdomain`, never `resolved`
        all_known = sorted(set(ctx.run.values("resolved")) | set(ctx.run.values("subdomain")))
        res_hosts = ctx.write_list("resolved_hosts.txt", all_known)
        cn = ctx.run.raw_path("vertical", "dnsx", "cnames.jsonl")
        # -a so each result carries the host's A records: dangling = a CNAME but no A here. Not "not in
        # resolved" — a no-A CNAME host can still get a `resolved` entity with a:[]
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
