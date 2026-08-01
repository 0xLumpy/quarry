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
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

from .. import events, netguard, normalize, secrets, settings
from ..contract import (ProviderResult, ProviderSkip, classify_provider_error, registered, run_contract,
                        run_provider)
from ..runner import (RunResult, Status, have, reclassify_from_artifact, run as exec_tool,
                       skipped)

_SUBFINDER_DEFAULT_MIN = 60                  # default -max-time budget (minutes) for a normal bounded run
_SUBFINDER_UNBOUNDED_MIN = 1440             # Quarry's "0 = practically unbounded" -> 24h (subfinder can't take 0:
#                                             upstream feeds -max-time into context.WithTimeout, so 0 cancels)


def _subfinder_budget_min(http_timeout) -> int:
    """The EFFECTIVE subfinder -max-time budget (minutes). PERFORMANCE.SUBFINDER_MAX_TIME sets it (default 60).
    STRICT parse (review-r2#1): an EXACT integer (or clean integer string) in 0..1440 only — a bool / float /
    negative / oversized / garbage value falls back to 60 (never a silent 1-min cap from `true`, a 24h run from
    `false`/negatives, or a Go duration overflow). Quarry's 0 = 'practically unbounded' -> 1440m (NEVER 0 to
    subfinder, which would cancel); `quarry run --timeout 0` likewise forces the practical-unbounded budget."""
    knob = settings.strict_int("SUBFINDER_MAX_TIME",         # shared coverage-knob parser (same semantics)
                               default=_SUBFINDER_DEFAULT_MIN, maximum=_SUBFINDER_UNBOUNDED_MIN)
    if knob <= 0 or http_timeout == 0:                       # 0 (or unbounded outer) -> practically unbounded
        return _SUBFINDER_UNBOUNDED_MIN
    return knob


def _subfinder_reclassifier(budget_min: int):
    """Build the reclassify callback for the EFFECTIVE budget: a clean SUCCESS/EMPTY whose wall-clock reached the
    budget stopped at the -max-time ceiling -> coverage CAPPED -> PARTIAL (results kept + ingested). A natural
    finish BELOW the budget is an honest SUCCESS/EMPTY. NO tolerance below: Quarry starts timing before subfinder
    arms its internal timer, so a capped run always measures >= the budget."""
    budget_s = budget_min * 60

    def _reclassify(res):
        if res.status in (Status.SUCCESS, Status.EMPTY) and res.duration >= budget_s:
            return replace(res, status=Status.PARTIAL,
                           note=f"hit subfinder -max-time {budget_min}m ceiling — coverage capped (results kept)")
        return res
    return _reclassify


def _subfinder_config_paths() -> "tuple[Path, Path]":
    """The EFFECTIVE (provider-config, config) file paths subfinder will actually read (review-r4#1): the
    `SUBFINDER_PROVIDER_CONFIG` / `SUBFINDER_CONFIG` env overrides win, else `<XDG_CONFIG_HOME or ~/.config>/
    subfinder/{provider-config,config}.yaml`. BOTH affect `-all` coverage (config.yaml selects sources;
    provider-config.yaml holds keys)."""
    cfg_dir = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "subfinder"
    provider = Path(os.environ.get("SUBFINDER_PROVIDER_CONFIG") or (cfg_dir / "provider-config.yaml"))
    config = Path(os.environ.get("SUBFINDER_CONFIG") or (cfg_dir / "config.yaml"))
    return provider, config


def _subfinder_provider_fp() -> str:
    """Fingerprint of subfinder's EFFECTIVE configuration — both config files' CONTENTS (resolved via env
    overrides + XDG) + the effective PDCP env key — folded into the resume work_unit (review-r3#2). Coverage from
    `-all` depends on these, so a change (e.g. ADDING a key) must invalidate resume instead of skipping the wider
    run as 'already complete'. Domain-separated + length-prefixed framing; FULL sha256 (256-bit — no truncation
    that would discard entropy before the work_unit folds it, review-r4#2). NEVER a raw secret (the key is
    sha256-fingerprinted)."""
    import hashlib
    provider, config = _subfinder_config_paths()
    h = hashlib.sha256()
    for label, p in (("provider-config", provider), ("config", config)):
        try:
            data = p.read_bytes()
        except OSError:
            data = b"\x00<absent>"                            # a real file is never this (length-framed below)
        h.update(label.encode() + b"\x00" + len(data).to_bytes(8, "big") + data)   # unambiguous framing
    key = (os.environ.get("PDCP_API_KEY") or "").encode()
    h.update(b"pdcp-key\x00" + hashlib.sha256(key).digest())  # key FINGERPRINT (full sha256), never the raw key
    return h.hexdigest()                                      # full 256-bit hex


def _run_subfinder(ctx, prof, scope) -> None:
    """Passive subfinder — run ONCE PER APEX (review-r2#P1). subfinder applies `-max-time` PER DOMAIN (it
    enumerates `-dL` domains SEQUENTIALLY, each with its OWN ceiling), so a single `-dL` batch would compare a
    SUMMED multi-apex duration against one 600s cap — false-PARTIAL for apexes that each finished cleanly, and a
    fixed outer timeout could SIGKILL mid-batch on several apexes. Per apex we get an honest work_unit / raw
    artifact / classification / ingestion and independent resume. Flags: `-all` = every source; NO `-recursive`
    (upstream: it RESTRICTS to the recursive-capable subset — a coverage loss, T1.2). subfinder's collection
    budget is its OWN `-max-time` (PERFORMANCE.SUBFINDER_MAX_TIME minutes, default 60; Quarry's 0 -> practically
    unbounded 1440m — NEVER 0 to subfinder, which would cancel), SEPARATE from Quarry's `--timeout` outer kill.
    The per-apex outer subprocess backstop = budget + 60s so subfinder caps ITSELF gracefully (exit 0, results
    written) rather than being SIGKILLed — EXCEPT `quarry run --timeout 0` (unbounded) which also passes the
    outer timeout 0 (no kill). The reclassify uses the EFFECTIVE budget. -stats -> per-source health (captured)."""
    budget_min = _subfinder_budget_min(ctx.http_timeout)     # effective budget (minutes); folded into resume below
    reclassify = _subfinder_reclassifier(budget_min)
    outer = 0 if ctx.http_timeout == 0 else budget_min * 60 + 60   # --timeout 0 -> no outer kill; else budget+60s
    providers = _subfinder_provider_fp()                     # coverage-affecting: fold into resume (review-r3#2)
    for apex in sorted(set(prof.apex_domains)):              # defensive: never run a canonical apex twice
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


#: the provider's OWN sentence, MEASURED 2026-07-30 with a real Free PAT (HTTP 403,
#: `application/problem+json`, and the refusal cost 0 credits — the wallet still read 100 afterwards).
CENSYS_ORG_REQUIRED = ("This endpoint requires an organization ID for API access. Free users can only "
                       "access this endpoint through the Platform UI.")


def censys_entitlement_skip(cen: dict, apexes) -> bool:
    """Record the lane's lifecycle when a Censys token is configured but cannot possibly work.

    The Platform search API is ORG-GATED — measured, not inferred: a Free PAT reads its wallet fine (100
    credits, monthly reset) and `/v3/global/search/query` answers 403 with `CENSYS_ORG_REQUIRED`. This used
    to be total silence: no lifecycle, nothing in the manifest, so an operator who had set up a Free PAT
    could not tell "not configured" from "configured and cannot work".

    Only that ONE state is reported. No config at all, or an org with no token, stays silent — an operator
    is not told about a lane they never asked for."""
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
    """review-r6#2/r7#1: the cert-names list from the EXACT current Censys hit path
    ``certificate_v1.resource.names`` — no fallbacks (a `resource.names` / top-level `names` fallback reopened
    fail-open parsing: a drift hit became clean-EMPTY and a foreign `names` became a phantom host). The path's
    absence, or a non-list value, is a SCHEMA FAILURE — raised, never a silent skip."""
    res = hit.get("certificate_v1")
    res = res.get("resource") if isinstance(res, dict) else None
    names = res.get("names") if isinstance(res, dict) else None
    if not isinstance(names, list):
        raise ValueError("censys: hit missing certificate_v1.resource.names list — schema failure")
    return names


def _censys_next_token(doc: dict) -> str | None:
    """C06: extract the Platform v3 'next page' token DEFENSIVELY (schema drift-tolerant) — the documented
    field is a page token; try its known locations (result.links.next / result.next_page_token /
    next_page_token), returning a non-empty string or None. Sent back as `page_token` on the next request."""
    res = doc.get("result") if isinstance(doc.get("result"), dict) else {}
    links = res.get("links") if isinstance(res.get("links"), dict) else {}
    for v in (links.get("next"), res.get("next_page_token"), doc.get("next_page_token")):
        if isinstance(v, str) and v:
            return v
    return None


def _censys(cfg: dict, apex: str, timeout: int = 30, max_pages: int = 5) -> set:
    """OPTIONAL Censys Platform v3 global-search cert query for `apex` → subdomain set. Returns an empty set
    (SILENT) unless both a PAT `token` and `org` id are configured. Query is CenQL `cert.names: "<apex>"` (the
    current field; NOT the legacy `cert.parsed.names`), requesting only `fields: ["cert.names"]`. FAIL-CLOSED
    structured parse: names come from the EXACT hit path `certificate_v1.resource.names` (no fallbacks, no regex
    over the hit body) and are filtered to the queried apex — a missing path / non-list / non-string is a schema
    failure (raises), never a clean-EMPTY or a phantom host. C06: follows the `page_token` cursor (the v3 request
    field) up to `max_pages` (bounded, configurable), stops on a missing/repeat token; hitting the cap with a
    live token returns a PARTIAL ProviderResult (truncated); a later-page failure keeps earlier pages as PARTIAL.
    Errors propagate to run_provider."""
    token, org = cfg.get("token"), cfg.get("org")
    if not token or not org:
        return set()                                        # not configured — a genuine "not applicable" empty
    hosts: set = set()
    page_token = None
    pages = 0
    truncated = False
    for i in range(max(1, max_pages)):
        pages = i + 1
        # P2: QUOTE the apex — a valid numeric-leading domain is not a valid UNQUOTED CenQL string literal.
        # review-r7#1: request ONLY `cert.names` so the response carries exactly the field we parse (minimal
        # surface — no stray text that could yield a phantom host).
        payload = {"query": f'cert.names: "{apex}"', "page_size": 100, "fields": ["cert.names"]}
        if page_token:
            payload["page_token"] = page_token              # v3 pagination field (NOT `cursor`)
        req = urllib.request.Request(
            "https://api.platform.censys.io/v3/global/search/query", data=_json.dumps(payload).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {token}", "X-Organization-ID": str(org),
                     "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
        try:
            # review#2/r3#2: fetch AND validate/extract inside ONE protected block — do NOT swallow HTTP/transport
            # errors, and a later-page SCHEMA/parse error must ALSO preserve earlier pages (not propagate + lose).
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(8 * 1024 * 1024).decode("utf-8", "replace")
            doc = _json.loads(raw)
            # review#3 + P2 + r4#5: a success carries a `result` OBJECT whose `hits` is a LIST — anything else
            # (a bare object, a non-list hits) is malformed, an error, NOT a clean-EMPTY.
            if not (isinstance(doc, dict) and isinstance(doc.get("result"), dict)
                    and isinstance(doc["result"].get("hits"), list)):
                raise ValueError("censys: unexpected response envelope (no 'result.hits' list) — not a valid empty result")
            hits = doc["result"]["hits"]
            page_hosts = set()
            for hit in hits:
                if not isinstance(hit, dict):                # review-r5#3: `hits:[null]` / scalar rows are malformed
                    raise ValueError("censys: non-object hit row")
                # review-r6#2/r7#1: parse the EXACT cert-names list (certificate_v1.resource.names) — NOT a
                # regex over the hit JSON, and NO fallbacks. A missing path raises (schema failure), so a drift
                # hit can neither become a clean-EMPTY nor a phantom host.
                for nm in _censys_hit_names(hit):
                    if not isinstance(nm, str):
                        raise ValueError("censys: hit name is not a string")
                    nm = nm.lower().strip(".")
                    if nm == apex or nm.endswith("." + apex):   # keep names UNDER the queried apex (subs + `*.`)
                        page_hosts.add(nm)
            nxt = _censys_next_token(doc)
        except Exception as e:
            if i == 0:                                       # first-page failure -> FAILED (propagate)
                raise
            return ProviderResult(hosts, partial=True, cursor=page_token, pages=i,   # later page: KEEP earlier hosts
                                  error_class=classify_provider_error(e))
        hosts |= page_hosts                                  # merge only a FULLY-validated page
        if not nxt or nxt == page_token:                     # no next page (or a non-advancing token) — done
            break
        page_token = nxt
    else:
        truncated = True                                     # ran all max_pages with a live token — more remain
    return ProviderResult(hosts, partial=truncated, cursor=page_token, pages=pages)   # ALWAYS PR (complete clears)


def _crtsh(apex: str, timeout: int = 30) -> set:
    """Direct crt.sh CT-log pull for `%.apex` → set of hostnames (SANs, wildcards stripped).
    Best-effort + no key: complements subfinder's CT sources (coverage) and is a fallback when
    passive is thin (resilience). A failure returns an empty set — never breaks the run."""
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    # review#2: errors propagate to run_provider (FAILED terminal, not fake-empty).
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(8 * 1024 * 1024)              # bounded read
    rows = _json.loads(data.decode("utf-8", "replace"))
    # review#3: crt.sh's success shape is a JSON ARRAY. A non-list root (error page / schema drift) is NOT
    # zero results — raise into run_provider (FAILED), never launder it to a clean EMPTY.
    if not isinstance(rows, list):
        raise ValueError("crt.sh: non-list JSON root — not a valid empty result")
    hosts = set()
    for row in rows:
        if not isinstance(row, dict):                        # review-r3#3: FAIL-CLOSED — a non-object row is corruption
            raise ValueError("crt.sh: non-object row")
        for nv in str(row.get("name_value", "")).splitlines():
            h = nv.strip().lower().strip(".")
            if h and "." in h:
                hosts.add(h)
    return hosts


def _certspotter(apex: str, token: str | None = None, timeout: int = 30, max_pages: int = 5) -> set:
    """certspotter (SSLMate CT Search API v1) issuances for `apex` (+subdomains) → set of hostnames. Free tier
    is keyless (rate-limited); a token raises the limit. C06: PAGINATES via `after=<last issuance id>` — the
    API documents NO `limit` and terminates on an EMPTY array, so we follow the cursor until an empty page (or
    a non-advancing cursor) and NEVER treat a short page as terminal. Bounded to `max_pages`; hitting the cap
    with a live cursor returns a PARTIAL ProviderResult (truncated). Errors propagate to run_provider (FAILED)."""
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
        url = base + (f"&after={urllib.parse.quote(after)}" if after else "")   # P2: encode the opaque cursor id
        try:
            # review-r3#2: fetch AND validate/extract inside ONE protected block — a later-page SCHEMA/parse
            # error (not just network) must ALSO preserve earlier pages, not propagate and discard them.
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                rows = _json.loads(r.read(8 * 1024 * 1024).decode("utf-8", "replace"))
            # review#3: certspotter's success shape is a JSON ARRAY of issuances; a non-list root is an error.
            if not isinstance(rows, list):
                raise ValueError("certspotter: non-list JSON root — not a valid empty result")
            page_hosts = set()
            for row in rows:
                if not isinstance(row, dict):                # review-r3#3: FAIL-CLOSED — a non-object row is
                    raise ValueError("certspotter: non-object issuance row")   # corruption, not silently skipped
                # review-r4#5/r5#4: we requested expand=dns_names, so each row MUST carry a list of STRINGS —
                # a missing/null field or a non-string element is malformed (fail-closed), not silently coerced.
                dns_names = row.get("dns_names")
                if not isinstance(dns_names, list) or not all(isinstance(x, str) for x in dns_names):
                    raise ValueError("certspotter: dns_names is not a list of strings")
                for h in dns_names:
                    h = h.strip().lower().strip(".")
                    if h and "." in h:
                        page_hosts.add(h)
            if rows:                                         # review-r4#5: the cursor id must be a scalar (str/int)
                _id = rows[-1].get("id")
                if _id is not None and not isinstance(_id, (str, int)):
                    raise ValueError(f"certspotter: cursor id not a scalar ({type(_id).__name__})")
                nxt = str(_id or "")
            else:
                nxt = ""
        except Exception as e:
            # review-r2#4/r3#2: a LATER-page failure (network OR schema/parse) keeps earlier pages as PARTIAL
            # with the error class; only a FIRST-page failure propagates (-> FAILED, no result).
            if i == 0:
                raise
            return ProviderResult(hosts, partial=True, cursor=after, pages=i, error_class=classify_provider_error(e))
        hosts |= page_hosts                                  # merge only a FULLY-validated page
        if not rows:
            break                                            # EMPTY array = the documented end of pagination
        if not nxt or nxt == after:                          # no cursor / non-advancing — done
            break
        after = nxt
    else:
        truncated = True                                     # ran all max_pages without an empty page — more remain
    return ProviderResult(hosts, partial=truncated, cursor=after, pages=pages)   # ALWAYS PR (complete clears the gap)


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


def _target_wordlist(ctx, loss: dict | None = None) -> list[str]:
    """A1d — build a TARGET-SPECIFIC label wordlist from what the crawl already mined.

    xnLinkFinder (run in the crawl phase over waymore responses + JS + recovered source) writes a
    `-owl` wordlist per input dir. Those files are the target's OWN vocabulary — product names,
    internal service names, path segments — the exact words a generic dictionary misses. Here we
    harvest every `*_wordlist.txt` xnLinkFinder produced, tokenize each entry into DNS-label pieces,
    keep only plausible labels (has a letter, len>=3, valid label chars — drops `v1`/`api`-vs-nothing
    noise and pure-numeric junk that would explode a brute) and dedup, in ENCOUNTER order.

    review-step4-measure#3: base-dictionary subtraction and the selection bound used to happen HERE, which
    forced the caller to materialise the whole 9.5M-word base list (1.5 GB RSS, measured) just to exclude
    a few thousand mined words. Both moved to the caller: `enrich._a1d_subtract_base` streams the base file
    against this (small) set, and the selection bound is the caller's spend decision. RETENTION is what
    this function does; SELECTION is not its job."""
    # `loss` is the caller's OUT-parameter: undecodable lines and unreadable artifacts are facts A1d has
    # to report (review-B-audit-11#2/#3). Filled in even on the early returns.
    loss = loss if loss is not None else {}
    loss.setdefault("dropped_lines", 0)
    loss.setdefault("unreadable_files", 0)
    loss.setdefault("files", 0)
    #: word -> the artifacts that produced it. PROVENANCE stays with the evidence; this is what the
    #: scheduler attributes a submitted word against (one owner per word, chosen by rendezvous hashing).
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
            # review-B-audit-11#2: swallowing this made "every wordlist is unreadable" indistinguishable
            # from "the crawl mined nothing" — machinery failure reported as legitimate absence.
            loss["unreadable_files"] += 1
            continue
        for chunk in raw.splitlines():
            # review-B-audit-10#2: this decoded the whole file with `errors="replace"`, so a line the
            # crawl boundary REJECTED as undecodable still yielded labels — and these words drive an
            # ACTIVE puredns brute (A1d). A line we cannot decode is not vocabulary; it is a dropped line.
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


#: an EXACT DNS label: letters/digits/hyphen, no leading or trailing hyphen, 1..63 chars. Deliberately not
#: a "looks fine" filter — this is the gate between a mined word and a hostname Quarry will CONTACT.
#: review-B-audit-17#2: matched with `fullmatch`, because `$` also matches before a FINAL NEWLINE — so
#: `"safe\n"` passed the check and kept its newline in a name we would have contacted.
_DNS_LABEL_RX = _re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")

#: how many labels one wildcard pass may probe per zone. A POLICY bound (brute load), not a parse fact —
#: it is reported separately from what the parser could not use (review-B-audit-17#1).
WILDCARD_WORD_CAP = 5000

#: how many eligible wildcard zones one differ run may probe. Module scope since the lane's lifecycle
#: (its work unit) binds it, not only the body that applies it.
ZONE_CAP = 5


def _wc_vocab_coverage(sid: str, label: str, vocab: dict) -> None:
    """Structured VOCABULARY coverage for a wildcard pass — words we could not use are un-probed surface.

    review-B-audit-16#2: these losses lived only in `stats["blocked"]`, which nothing reconciles, so an
    unreadable or half-rejected wordlist could still leave the run reading `complete`.

    review-B-audit-18#1: the two stages are SEQUENTIAL over the same words, so they may not share a
    measure — a rollup sums units per (source, measure) as disjoint work, and 10 words became eligible=20.
    PARSING is counted in `vocabulary_entries` (what the input offered), SELECTION in `vocabulary_words`
    (what survived parsing, and how much of it the cap let through)."""
    lost = vocab["undecodable"] + vocab["rejected"]
    # review-B-audit-17#3: coverage is LATEST-per-(source, unit), so a clean pass has to say so — emitting
    # nothing left an earlier UNKNOWN or omission standing as the current truth for this unit.
    if vocab["unreadable"]:
        # a present list we cannot read: RAN, unmeasurable -> a gap the reconciler admits
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
    # the CAP is its own fact, under its own stable unit: policy truncation is not parse loss, and one
    # must never mask the other.
    events.coverage_partial(sid, kind=events.COVERAGE_CAP,
                            unit=f"{label}:vocabulary_cap", measure="vocabulary_words",
                            eligible=vocab["usable"], tested=vocab["selected"], omitted=vocab["withheld"],
                            # review-B-audit-19#2: this stage is SELECTION, not execution — whether the
                            # selected names were ever submitted is the `zones` measure's answer.
                            reason=f"{label}: {vocab['selected']}/{vocab['usable']} usable name(s) SELECTED "
                                   f"for probing (cap {WILDCARD_WORD_CAP}) — {vocab['withheld']} withheld")


def _wc_eligible_zones(ctx, zones) -> list:
    """The zones this pass may contact at all: in scope, not out of scope. Computed by the LIFECYCLE
    wrapper so `input_total` is the real eligible set, and handed to the body so both agree."""
    scope = ctx.scope
    return sorted(z for z in zones if scope.in_scope(z) and not scope.is_oos(z))


def _wc_terminal(st: dict, kept: set):
    """One terminal for the differ, from what it actually did (step 4.3).

    Three independent facts degrade it and they ACCUMULATE: zones we never contacted (a policy bound or
    the contact guard), invocations that did not come back usable, and rows we could not parse."""
    eligible, probed = st.get("eligible_zones", 0), st.get("probed_zones", 0)
    obtained = st.get("zones_obtained", probed)
    classes = st.get("invocation_classes") or {}
    parse_errors = st.get("parse_errors", 0)
    blocked = st.get("blocked", {}) or {}
    why = st.get("blocked_reason") or ""
    if not eligible:
        return Status.EMPTY, why or "no in-scope wildcard zone"
    if not probed:
        # nothing was contacted: a mode, a missing tool, no vocabulary, or the contact guard
        return Status.SKIPPED, why or "no zone was probed"
    facts = [p for p in (why,
                         f"zone outcomes {dict(sorted(classes.items()))}" if classes else "",
                         f"{parse_errors} unparseable output row(s)" if parse_errors else "") if p]
    if (probed < eligible or blocked.get("self_or_private") or blocked.get("zone_cap")
            or classes or parse_errors or obtained < probed):
        # PARTIAL asserts production; a differ that probed some zones and found nothing is not production
        return ((Status.PARTIAL if kept else Status.FAILED),
                "; ".join(facts) or f"{probed}/{eligible} zone(s) probed")
    return (Status.SUCCESS if kept else Status.EMPTY), why or None


def _wildcard_differentiate(ctx, zones: set, *, extra_words=None,
                            phase: str = "vertical", label: str = "wildcard",
                            source: str = "wildcard-http", stats: dict | None = None,
                            source_id: str = "vertical.wildcard_http") -> set[str]:
    """The differ's own SOURCE LIFECYCLE (step 4.3): registry gate, one start, one terminal, whatever
    happens inside. Until now this was a coverage identity only — it emitted coverage records under
    `source_id` but never a start or a terminal, so a manifest could not tell a pass that never ran from
    one that ran and found nothing."""
    st = stats if stats is not None else {}
    st.clear()
    st.update({"eligible_zones": 0, "probed_zones": 0, "blocked_reason": "",
               "blocked": {"zone_cap": 0, "self_or_private": 0}})
    if not registered(source_id):
        # the GATE comes before eligibility (v42#4): a refused lane that had filled the carrier made its
        # caller report withheld words and undifferentiated zones for a pass that never existed.
        return set()
    machinery = None                # the exception that ended the pass, if one did
    unrecorded = None               # a failure to RECORD the outcome — never silently a clean verdict
    kept: set[str] = set()          # hosts this pass ACCEPTED as distinct vhosts (novel or already known)
    novel: set[str] = set()         # the subset the store had never seen — an echo detail, not production
    eligible: list = []
    started = False
    fp = None
    outcome = (Status.FAILED, "the wildcard differ did not report an outcome")
    try:
        # fallible SETUP lives inside the protected interval (v42#5): a scope failure, a malformed zone
        # iterable or an unreadable vocabulary used to escape without a start/terminal pair at all.
        eligible = _wc_eligible_zones(ctx, zones)
        st["eligible_zones"] = len(eligible)
        # no eligible zone -> nothing to probe WITH either: the vocabulary is not read, so a run with
        # nothing to differentiate does not report parse facts about a list it would never have used.
        words = _wc_vocabulary(extra_words, st) if eligible else []
        # the key binds the ORDERED vocabulary the invocation really submits — the caller's words in
        # front, the dedicated list behind, deduped and capped (v42#3). A set digest could not tell
        # `["api", "admin"]` from its reverse, which probe different names under a cap of one.
        fp = events.work_unit(source_id, inputs={"zones": eligible, "vocabulary": _wc_digest(words)},
                              config={"zone_cap": ZONE_CAP, "word_cap": WILDCARD_WORD_CAP},
                              schema_version=1)
        events.tool_start(source_id, cmd=["httpx", "(wildcard-differ)"], input_total=len(eligible),
                          work_unit=fp)
        started = True
        _wc_differentiate(ctx, eligible, words=words, phase=phase, label=label,
                          source=source, st=st, source_id=source_id, kept=kept, novel=novel)
        outcome = _wc_terminal(st, kept)
    except (KeyboardInterrupt, SystemExit):
        outcome = ((Status.PARTIAL if kept else Status.FAILED),
                   "CANCELLED mid-differ — evidence KEPT" if kept else "CANCELLED mid-differ")
        raise                                                  # after the terminal, never before
    except Exception as ex:
        st["blocked_reason"] = f"{type(ex).__name__}: {ex}"
        machinery = ex
        outcome = ((Status.PARTIAL if kept else Status.FAILED),
                   f"the wildcard differ failed ({type(ex).__name__}: {ex})")
    finally:
        why = outcome[1]
        if machinery is not None:
            # MACHINERY only (v43#1): a capped or guard-refused pass is an omission the coverage record
            # already owns, and recording it as a failed tool made a normal run report `tools_failed=1`
            # with nothing failed. Invocation failures are already recorded by the body, one per call.
            # The manifest verdict folds RECORDED RunResults, not lifecycle events (v42#1).
            try:
                ctx.run.record(phase, RunResult("wildcard-differ", ["httpx", "(wildcard-differ)"],
                                                outcome[0], None, 0.0, None, 0, note=why))
            except Exception as e:
                why = f"{why}; the outcome could not be recorded ({type(e).__name__})"
                unrecorded = e
        if not started:
            # setup failed before the start: the pair is still emitted, so the source never goes silent
            events.tool_start(source_id, cmd=["httpx", "(wildcard-differ)"],
                              input_total=len(eligible), work_unit=fp or "setup-failed")
        events.tool_finish(source_id, status=outcome[0].value, reason=why, work_unit=fp or "setup-failed",
                           produced={"subdomains": len(kept)})
    if unrecorded is not None:
        # v43#5: the terminal is out, but a generic terminal is not folded into the manifest verdict — so
        # a failure to record the outcome would leave the run reading `complete`. It propagates to the
        # phase boundary, which owns phase exceptions, instead of disappearing here.
        raise RuntimeError(f"{source_id}: the outcome could not be recorded "
                           f"({type(unrecorded).__name__}: {unrecorded})") from unrecorded
    return kept


def _wc_digest(words) -> str:
    """The digest of the ORDERED vocabulary an invocation submits. Order matters: a cap selects a PREFIX,
    so two lists with the same members but different order probe different names (v42#3)."""
    import hashlib as _h
    d = _h.sha256()
    for w in words or []:
        d.update(w.encode("utf-8"))
        d.update(b"\n")
    return d.hexdigest()


def _wc_vocabulary(extra_words, st: dict) -> list:
    """The ORDERED vocabulary this pass will submit, and the parse facts behind it.

    Extracted from the body so the lane's work unit can bind exactly what the invocation submits, and so
    an unreadable list fails inside the lifecycle rather than beside it (v42#3 / v42#5)."""
    from .probe import _vhost_wordlist          # DEDICATED small label list (lives in probe)
    # review-step4-measure#2: this used to fall back to `_wordlist(ctx)` — the DNS brute list — which
    # `_vhost_wordlist` explicitly promises never to use, "because vhost fuzzing is IPs x apexes x words,
    # so an unbounded list is a footgun". MEASURED on this box: that fallback made the eligible set
    # 6,037,953 candidate hosts PER ZONE (6,030,367 of the 9.5M DNS entries are valid single labels), of
    # which the 5000-word cap probed 0.1%. No fallback: without a dedicated list the pass runs on the
    # CALLER's vocabulary (A1d's mined words) or reports a vocabulary gap and probes nothing.
    wl = _vhost_wordlist()
    # review-B-audit-15#1: a missing GENERIC list is not a missing wordlist when the caller brought its
    # own. A1d only gets here having mined a non-empty target vocabulary, and those words plus the bogus
    # baseline are enough to differentiate — refusing to run threw away work we had already paid for.
    vocab = {"lines": 0, "entries": 0, "valid_entries": 0, "usable": 0, "selected": 0, "withheld": 0,
             "accepted": 0, "undecodable": 0, "rejected": 0, "unreadable": False, "absent": wl is None}
    st["vocabulary"] = vocab
    generic: list = []
    if wl is not None:
        try:
            raw = Path(wl).read_bytes()
        except OSError:
            # review-B-audit-16#2: ABSENT and PRESENT-BUT-UNREADABLE are different facts and were both
            # becoming b"". The caller's own words still run; the loss is measured, not swallowed.
            raw = b""
            vocab["unreadable"] = True
        for chunk in raw.splitlines():
            vocab["lines"] += 1
            try:
                w = chunk.decode("utf-8").strip()  # strict: these labels are CONTACTED, like every other
            except UnicodeDecodeError:             # active vocabulary (review-B-audit-10#2)
                vocab["undecodable"] += 1
                continue
            if w and not w.startswith("#"):
                generic.append(w)
    # A1d: fold the target-specific words (mined from the crawl) IN FRONT so the target's own
    # naming vocabulary is tried first, then dedup + cap so brute load stays bounded.
    candidates = [w for w in (extra_words or []) if w] + generic
    # review-B-audit-16#1: a decodable line is not a LABEL. `https://outside.example/x` would build
    # `https://outside.example/x.<zone>`, whose AUTHORITY httpx resolves as `outside.example` — an active
    # request at a host nobody checked against scope or the contact guard. Every candidate is validated
    # STRUCTURALLY here, at the boundary that turns a word into a name we will contact.
    valid: list = []
    for w in candidates:
        if _DNS_LABEL_RX.fullmatch(w):
            valid.append(w.lower())            # canonicalised BEFORE dedup: API and api are ONE name
        else:
            vocab["rejected"] += 1
    # review-B-audit-19#1: PARSING is counted in ENTRIES (what the input offered), SELECTION in unique
    # NAMES. Mixing them made `API`, `api`, `bad/url` report eligible=2 for three entries. Deduplication
    # is not a loss — the two spellings are ONE name we would contact — so it is neither omitted nor
    # eligible twice; it is simply where one measure ends and the next begins.
    # review-B-audit-20#2: ENTRIES is everything the input offered, including the lines we could not even
    # decode — assigning `len(candidates)` counted them out while the coverage denominator counted them in.
    vocab["valid_entries"] = len(valid)
    vocab["entries"] = len(valid) + vocab["rejected"] + vocab["undecodable"]
    usable = list(dict.fromkeys(valid))
    # review-B-audit-17#1: the cap SILENTLY dropped valid labels and then reported the truncated count as
    # "accepted", so thousands of withheld words produced no omission at all. Usable, selected and withheld
    # are three separate facts, and the cap is reported as the POLICY bound it is.
    words = usable[:WILDCARD_WORD_CAP]
    vocab["usable"] = len(usable)
    vocab["accepted"] = vocab["selected"] = len(words)
    vocab["withheld"] = len(usable) - len(words)
    return words


def _wc_differentiate(ctx, _zones_all: list, *, words: list, phase: str, label: str, source: str,
                      st: dict, source_id: str, kept: set, novel: set) -> None:
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
    # review-B-audit-14: `stats` is the caller's OUT-parameter. Whether this pass actually RAN cannot be
    # inferred from "there were zones" — passive mode, a missing httpx, no wordlist and the self-contact
    # guard all return an empty set without probing anything, and a caller that reads that as "it ran"
    # reports work it never submitted.
    # review-B-audit-15#2: SNAPSHOT semantics, not `setdefault` — a reused dict could otherwise report
    # this call's `eligible_zones` beside a previous call's `probed_zones`.
    zones = _zones_all[:ZONE_CAP]

    def _gate(reason: str) -> None:
        """A hard exit that still REPORTS. review-B-audit-20#1: these returns happened before the `zones`
        event, so the A1d caller could reconstruct the omission from `stats` but the production vertical
        caller — which passes none — recorded nothing at all: eligible zones, zero differentiated, verdict
        `complete`."""
        st["blocked_reason"] = reason
        events.coverage_partial(source_id, kind=events.COVERAGE_TIMEOUT, measure="zones", unit=label,
                                eligible=len(_zones_all), tested=0, omitted=len(_zones_all),
                                reason=f"{label}: 0/{len(_zones_all)} wildcard zone(s) differentiated "
                                       f"({reason})")
        return None

    if not zones:
        # nothing eligible: still emit (0/0/0 is VALID and clears any earlier gap for this unit)
        return _gate("no in-scope wildcard zone")
    if scope.passive_only:
        # an intentional MODE, not a gap: passive runs make no active pass by design.
        st["blocked_reason"] = "passive-only mode"
        return None
    if not have("httpx"):
        ctx.run.record(phase, skipped("httpx", f"not installed — {len(_zones_all)} wildcard zone(s) "
                                               f"undifferentiated ({label})"))
        return _gate("httpx is not installed")
    vocab = st.get("vocabulary") or {}
    if not words:
        _wc_vocab_coverage(source_id, label, vocab)
        return _gate("no usable vocabulary")       # nothing to probe WITH -> zero zones attempted
    st["blocked"]["zone_cap"] = max(0, len(_zones_all) - ZONE_CAP)
    block_private = netguard._block_private(ctx)

    def _sig(o):
        return (o.get("status_code"), o.get("content_length"),
                (o.get("title") or "").strip(), o.get("favicon"))

    zones_probed = 0                       # zones we CONTACTED (an attempt, not an answer)
    st["zones_obtained"] = 0               # zones whose invocation came back usable
    st["invocation_classes"] = {}
    st["parse_errors"] = 0
    for zone in zones:
        # self-attack guard: if the wildcard resolves to the SCAN BOX / metadata, don't vhost-scan the zone
        # (record it as intel). A private wildcard is CONTACTED by default (recorded either way).
        _wstate, _wdeny, _wintel = netguard.contact_state(f"quarry-wc-guard-{_uuid.uuid4().hex[:8]}.{zone}",
                                                          block_private=block_private)
        if _wintel:
            netguard.record_internal(ctx, f"*.{zone}", _wintel)
        if _wstate in ("self", "private_blocked"):
            # review-B-audit-15#3: this omission used to raise the unsubmitted count with no reason, so a
            # capped run blamed the cap for zones the CONTACT GUARD had refused.
            st["blocked"]["self_or_private"] += 1
            continue
        zones_probed += 1
        st["probed_zones"] = zones_probed
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
        # v43#2: the terminal used to read only "did we contact this zone", so a FAILED, TIMED_OUT or
        # mid-run SKIPPED invocation left the source reporting a clean EMPTY over full zone coverage.
        # An ATTEMPT and an ANSWER are different facts and are counted separately.
        if r.status in (Status.SUCCESS, Status.EMPTY):
            st["zones_obtained"] += 1
        else:
            _k = str(getattr(r.status, "value", r.status))
            st["invocation_classes"][_k] = st["invocation_classes"].get(_k, 0) + 1
        if not (r.raw_path and r.raw_path.exists()):
            continue
        rows = []
        for line in r.raw_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = _json.loads(line)
            except _json.JSONDecodeError:
                # v43#3: a truncated or malformed artifact was silently a clean empty answer. The rows we
                # could not read are a PARSE GAP; the artifact stays on disk to be read again.
                st["parse_errors"] += 1
                continue
            if not isinstance(row, dict):
                st["parse_errors"] += 1
                continue
            rows.append(row)
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
                # `Run.add` answers "NEW entity", not "accepted observation" (v42#2): a host another
                # source had already found was differentiated here too, and the pass reported EMPTY with
                # nothing produced. Acceptance is the production fact; novelty is an echo detail.
                if ctx.run.add("subdomain", {"host": host, "sources": [source],
                                             "raw_ref": str(hx)}):
                    novel.add(host)
                # v43#4: the RESOLVED observation is this pass's own evidence about the host — it does not
                # depend on whether the subdomain entity happened to be new here.
                ctx.run.add("resolved", {"host": host, "a": o.get("a") or [],
                                         "sources": [source], "raw_ref": str(hx)})
                kept.add(host)
    _wc_vocab_coverage(source_id, label, vocab)
    _why = "; ".join(p for p in (
        f"{st['blocked']['zone_cap']} zone(s) over the {ZONE_CAP}-zone cap"
        if st["blocked"]["zone_cap"] else "",
        f"{st['blocked']['self_or_private']} zone(s) refused by the self/private contact guard"
        if st["blocked"]["self_or_private"] else "") if p)
    # review-B-audit-18#2: ZONE reasons only. The vocabulary facts live in `stats["vocabulary"]`, and a
    # caller that reported both used to print the word cap twice.
    st["blocked_reason"] = _why
    # coverage AFTER filtering (audit #5): `tested` = zones ACTUALLY probed (safe candidates existed), so a
    # zone skipped for being internal / dnsx-missing is honestly counted as omitted, not tested.
    # review-B-audit-15#4 / 16#3: the SOURCE and the UNIT are the caller's. Reconciliation keeps the
    # latest per (source, unit) and then aggregates per source — a hard-coded id let the A1d invocation
    # replace the vertical pass's coverage AND file its own work under the vertical lifecycle.
    events.coverage_partial(source_id, kind=events.COVERAGE_CAP, measure="zones",
                            unit=label,
                            eligible=len(_zones_all), tested=zones_probed,
                            omitted=max(0, len(_zones_all) - zones_probed),
                            reason=f"{label}: wildcard vhost zones {zones_probed}/{len(_zones_all)} probed"
                                   + (f" ({_why})" if _why else ""))
    if kept:
        ctx.echo(f"  wildcard: {len(kept)} distinct vhost(s) differentiated, {len(novel)} new ({label})")


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    roots_file = ctx.write_list("roots.txt", prof.apex_domains)

    # ── passive: subfinder (per APEX) ──
    _run_subfinder(ctx, prof, scope)

    # ── passive: CT-log sources (crt.sh free + certspotter) — coverage/resilience over subfinder ──
    # A `*.X.apex` wildcard cert name → register `X.apex` as a WILDCARD BRUTE-ZONE candidate (A1):
    # a DNS-gated pipeline resolves every `<word>.X.apex` to one IP and strips them as noise; A1
    # brutes the zone + HTTP-differentiates instead. wildcard_zones is fed by CT + censys below.
    wildcard_zones: set[str] = set()
    cs_token = secrets.certspotter()
    _max_pages = settings.concurrency("PROVIDER_MAX_PAGES", 5)   # C06: bounded cursor pagination (configurable)
    ct_new = 0
    def _provider_over_apexes(src_id, per_apex, acct=None):
        """review#2: run each (provider, apex) as its OWN work unit. A single apex's failure becomes a FAILED
        terminal for THAT unit only — every OTHER apex's successful discovery is still unioned (best-effort,
        no all-or-nothing). This also gives the providers a per-apex work_unit (the C10b resume key)."""
        h = set()
        for apex in prof.apex_domains:
            # review-r4#4: fold the coverage-affecting page budget; review-r5#5: fold non-secret ACCOUNT SCOPE +
            # a credential FINGERPRINT (never the credential) — a changed account/org sees different data, so it
            # must be a different resume identity.
            cfg = {"max_pages": _max_pages, **(acct or {})}
            wu = events.work_unit(src_id, inputs={"apex": apex}, config=cfg)
            r = run_provider(src_id, lambda a=apex: per_apex(a), work_unit=wu, input_total=1)
            if r:                                            # None on failure (that apex's terminal is FAILED)
                h |= r
        return h
    _cs_acct = {"cred_fp": secrets.fingerprint(cs_token)} if cs_token else None   # certspotter token identity
    for src, fn, acct in (("crtsh", lambda a: _crtsh(a), None),
                          ("certspotter", lambda a: _certspotter(a, cs_token, max_pages=_max_pages), _cs_acct)):
        # C07 inc5: bracket the in-process CT provider (native HTTP) with a per-apex source lifecycle.
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
        # review-r5#5: org id (non-secret) + a token FINGERPRINT (never the token) — a different account/org
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

    # ── passive: github-subdomains (optional, needs token) ──
    # C06 disposition: github-subdomains is an EXTERNAL tool that paginates the GitHub code-search API
    # INTERNALLY (walks all result pages, honors the token's rate limit) — pagination is the tool's
    # responsibility, not ours. It runs on the contract (exec_tool → recorded), so an auth/rate failure
    # surfaces as a FAILED tool_run (fail-closed), not a silent empty. No in-process pagination is owed here.
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
