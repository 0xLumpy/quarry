"""Recon-layer evidence extraction — fetch exposed, in-scope, UNAUTHENTICATED, NON-MUTATING
resources and extract secrets from them.

This is the map/attack boundary in code form (Lumpy, 2026-07-02): the rule is not "don't touch
anything," it's **"don't accidentally perform impact."** Recon MAY collect evidence from
unauthenticated, in-scope, non-mutating access — so an exposed `.env` / `.git/config` / config file
is GET-fetched and its secret read + recorded (redacted). Recon MUST NOT send attack payloads, use
the found credentials, change state, bypass controls, or prove exploit impact — that's quarry-attack.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.request

from . import normalize, secrets

# Exposed files worth fetching: secret/config stores, VCS metadata, key material, dumps.
SENSITIVE_FILE_RX = re.compile(r"""
    /(?:
        \.env(?:\.[\w.-]+)?                         # .env .env.local .env.production
      | \.git/config | \.git/HEAD | \.git/credentials
      | \.aws/credentials | \.s3cfg | \.netrc | \.htpasswd | \.dockercfg | \.npmrc | \.pypirc
      | config\.(?:json|ya?ml|php|inc) | settings\.py | secrets\.ya?ml | wp-config\.php
      | \.DS_Store
      | id_rsa | id_dsa | id_ecdsa | id_ed25519 | [\w.-]+\.pem
      | (?:db|database|dump|backup)\.sql
    )(?:$|\?)
""", re.IGNORECASE | re.VERBOSE)

# Provider-shaped / structured tokens. lastindex group (if any) is the value, else the whole match.
_TOKEN_RX = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws-secret-key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+]{40})")),
    ("github-pat",     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("stripe-secret",  re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("slack-token",    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt",            re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("private-key",    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

# dotenv / config assignment `KEY = value`; captures a secret-looking VALUE on a secret-looking KEY.
_DOTENV_RX = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[=:]\s*['"]?([^'"\r\n#]{6,}?)['"]?\s*$""")
_SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|pass|pwd|api|auth|cred|private|access)")

MAX_BODY = 2 * 1024 * 1024    # 2 MB cap per exposed resource (RAM/disk guard)
MAX_FETCHES = 50              # bound how many exposed resources we fetch


def mine(text: str) -> list[tuple[str, str, int]]:
    """(kind, raw_value, line) for each secret found in `text`. Read-only — no exploit.
    Provider-shaped tokens win over the generic dotenv catch for the same value (more specific)."""
    out: list[tuple[str, str, int]] = []
    seen_vals: set[str] = set()
    for kind, rx in _TOKEN_RX:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            out.append((kind, val, text.count("\n", 0, m.start()) + 1))
            seen_vals.add(val)
    for m in _DOTENV_RX.finditer(text):
        key, val = m.group(1), m.group(2).strip()
        if _SECRETISH_KEY.search(key) and val not in seen_vals:   # already caught as a typed token
            seen_vals.add(val)
            out.append((f"dotenv:{key}", val, text.count("\n", 0, m.start()) + 1))
    return out


def _read_scoped(ctx, req, origin_host):
    """Open `req`, then re-check the FINAL host after urlopen's silent redirect-follow. Single
    choke point for (a) the off-scope guard and (b) RATELIMIT.HTTP pacing — these direct urllib
    requests bypass the tool flags nuclei/httpx/ffuf get, so honor the profile's req/s here so a
    rate-capped target doesn't receive the bounded set as a burst. An in-scope URL can 30x
    OFF-scope, and we must never read such a body while thinking it's in-scope. Returns
    (data|None, final_url, status) — data is None when the final host is off-scope (caller records
    the redirect as context, extracts nothing)."""
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                     # RATELIMIT.HTTP set -> pace to rl req/s
        time.sleep(1.0 / rl)
    with urllib.request.urlopen(req, timeout=20) as resp:
        final = getattr(resp, "url", None) or req.full_url
        status = getattr(resp, "status", 200)
        if normalize.host_of_url(final) != origin_host and not ctx.scope.active_allowed(
                normalize.host_of_url(final)):
            return None, final, status
        return resp.read(MAX_BODY + 1), final, status


def fetch_exposed(ctx, urls: list[str]) -> int:
    """GET each exposed in-scope resource (non-mutating), save the body as evidence, extract +
    store secrets (redacted) with provenance. Returns count of NEW secret entities added."""
    added = 0
    for u in urls[:MAX_FETCHES]:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):     # in-scope + not-passive + not-OOS
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
            data, final, status = _read_scoped(ctx, req, host)
        except Exception:
            continue
        if data is None:                           # off-scope redirect — record, don't extract
            ctx.run.add("review", {
                "id": f"exposed-redirect:{u}", "klass": "exposure", "value": u, "host": host,
                "location": final,
                "note": f"redirected off-scope to {final} (status {status}); body NOT extracted",
                "sources": ["exposed-fetch"]})
            continue
        if status != 200 or len(data) > MAX_BODY:
            continue
        text = data.decode("utf-8", "replace")
        fname = f"{host}-{hashlib.md5(u.encode()).hexdigest()[:8]}"
        dest = ctx.run.raw_path("params", "exposed", fname)
        dest.write_bytes(data)
        hits = mine(text)
        for kind, val, ln in hits:
            basis = val or f"{kind}|{u}|{ln}"
            if ctx.run.add("secret", {
                    "id": f"exposed:{kind}:{secrets.fingerprint(basis)}",
                    "kind": kind, "preview": secrets.mask(val),
                    "file": str(dest), "location": u, "line": ln,
                    "sources": ["exposed-fetch"]}):
                added += 1
        # The exposure itself as reviewable evidence (raw_ref -> saved body). confirmed:false —
        # collected evidence, still human-reviewed; NO impact performed.
        ctx.run.add("review", {
            "id": f"exposed:{u}", "klass": "exposure", "value": u, "host": host,
            "raw_ref": str(dest),
            "note": f"{len(hits)} secret(s) extracted" if hits else "fetched; no secret pattern",
            "sources": ["exposed-fetch"]})
    return added


# Minimal introspection query — a READ (non-mutating) per the GraphQL spec. We ask only for the
# schema's type/field names (enough to prove introspection is enabled + dump the shape as evidence).
_GQL_INTROSPECTION = json.dumps({"query":
    "query{__schema{queryType{name} mutationType{name} "
    "types{name kind fields{name}}}}"})


def probe_graphql(ctx, endpoints: list[str]) -> int:
    """Send an introspection query to each discovered in-scope GraphQL endpoint. Introspection is a
    non-mutating READ (no attack payload, no mutation, no creds) — recon evidence. When enabled,
    the schema is dumped to raw + a review is raised (hand-off to the attack layer). Returns the
    count of endpoints with introspection ENABLED."""
    enabled_n = 0
    for u in endpoints[:MAX_FETCHES]:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):
            continue
        try:
            req = urllib.request.Request(
                u, data=_GQL_INTROSPECTION.encode(), method="POST",
                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json",
                         "Accept": "application/json"})
            data, final, status = _read_scoped(ctx, req, host)
        except Exception:
            continue
        if data is None:                           # off-scope redirect — record, don't read schema
            ctx.run.add("review", {
                "id": f"graphql-redirect:{u}", "klass": "graphql", "value": u, "host": host,
                "location": final,
                "note": f"redirected off-scope to {final} (status {status}); not introspected",
                "sources": ["graphql-introspect"]})
            continue
        if len(data) > MAX_BODY:
            continue
        try:
            obj = json.loads(data.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError):
            obj = None
        introspectable = bool(isinstance(obj, dict)
                              and isinstance(obj.get("data"), dict)
                              and obj["data"].get("__schema"))
        dest = ctx.run.raw_path("params", "graphql", f"{host}-{hashlib.md5(u.encode()).hexdigest()[:8]}.json")
        dest.write_bytes(data)
        if introspectable:
            enabled_n += 1
        ctx.run.add("review", {
            "id": f"graphql:{u}", "klass": "graphql", "value": u, "host": host, "raw_ref": str(dest),
            "note": ("introspection ENABLED — schema dumped (attack-layer target)"
                     if introspectable else f"graphql endpoint probed; introspection off/blocked (status {status})"),
            "sources": ["graphql-introspect"]})
    return enabled_n


# Spring Boot actuator sensitive READ endpoints that are CHEAP to GET (return immediately, generate
# no artifact) — safe to probe directly for reachability. `shutdown`/`restart` (mutating POSTs) are
# excluded (impact). `heapdump` is excluded too — see _ACTUATOR_HEAVY.
ACTUATOR_SENSITIVE = ("env", "configprops", "mappings", "beans", "httptrace", "threaddump",
                      "loggers", "metrics", "sessions")
# Config endpoints whose 200 body can leak credentials -> worth mining for secrets.
_ACTUATOR_MINE = ("env", "configprops")
# HEAVY endpoints where the mere GET forces server-side work: a GET to /actuator/heapdump makes the
# JVM run a full STW GC and write a multi-GB dump to disk BEFORE streaming — requesting it is itself
# impact. So we NEVER GET these in default recon; we detect exposure from the /actuator index
# `_links` (what the app advertises) and flag high-priority. Deep-evidence mode may download.
_ACTUATOR_HEAVY = ("heapdump",)


def _actuator_index_links(ctx, base: str, host: str) -> set[str]:
    """GET the actuator index (cheap) and return the set of endpoint names it advertises in
    `_links`. This is how we learn heavy endpoints are exposed WITHOUT requesting them."""
    try:
        req = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
        data, _final, status = _read_scoped(ctx, req, host)
    except Exception:
        return set()
    if data is None or status != 200 or len(data) > MAX_BODY:
        return set()
    try:
        obj = json.loads(data.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError):
        return set()
    links = obj.get("_links") if isinstance(obj, dict) else None
    return set(links.keys()) if isinstance(links, dict) else set()


def probe_actuator(ctx, bases: list[str]) -> int:
    """Interrogate a Spring Boot actuator base and classify real-vs-benign. Cheap sensitive READ
    endpoints (`/actuator/env` etc.) are GET-probed for reachability (200 = real exposure, mine
    env/configprops for secrets). HEAVY endpoints (heapdump) are detected from the index `_links`
    only — never requested, since the GET itself would trigger dump generation (impact). All locked
    / not advertised = benign (the Test-5 triage-precision case). Mutating endpoints never touched.
    Returns the count of bases with >=1 sensitive endpoint exposed."""
    found = 0
    for base in bases[:MAX_FETCHES]:
        host = normalize.host_of_url(base)
        if not ctx.scope.active_allowed(host):
            continue
        advertised = _actuator_index_links(ctx, base, host)
        # heavy endpoints: flag high-priority from the advertised link — NO request to the endpoint.
        heavy_exposed = [h for h in _ACTUATOR_HEAVY if h in advertised]
        for h in heavy_exposed:
            hu = base.rstrip("/") + "/" + h
            ctx.run.add("review", {
                "id": f"actuator-heavy:{hu}", "klass": "actuator", "value": hu, "host": host,
                "priority": "high",
                "note": (f"{h} advertised EXPOSED via /actuator _links — HIGH-priority evidence "
                         "target; NOT requested (the GET would trigger dump generation). Enable "
                         "deep-evidence mode to download."),
                "sources": ["actuator-probe"]})
        # cheap sensitive endpoints: direct GET reachability + mine env/configprops.
        exposed: list[str] = []
        for sp in ACTUATOR_SENSITIVE:
            u = base.rstrip("/") + "/" + sp
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
                data, _final, status = _read_scoped(ctx, req, host)
            except Exception:
                continue
            if data is None or status != 200 or len(data) > MAX_BODY:
                continue                               # off-scope / locked / oversized -> not exposed
            exposed.append(sp)
            if sp in _ACTUATOR_MINE:                   # env/configprops can leak creds -> extract
                dest = ctx.run.raw_path("params", "actuator",
                                        f"{host}-{sp}-{hashlib.md5(u.encode()).hexdigest()[:8]}")
                dest.write_bytes(data)
                for kind, val, ln in mine(data.decode("utf-8", "replace")):
                    ctx.run.add("secret", {
                        "id": f"exposed:{kind}:{secrets.fingerprint(val or f'{kind}|{u}|{ln}')}",
                        "kind": kind, "preview": secrets.mask(val),
                        "file": str(dest), "location": u, "line": ln,
                        "sources": ["actuator-probe"]})
        reachable = exposed + [f"{h}(advertised)" for h in heavy_exposed]
        if reachable:
            found += 1
        ctx.run.add("review", {
            "id": f"actuator:{base}", "klass": "actuator", "value": base, "host": host,
            "note": (f"actuator EXPOSED — sensitive endpoints: {', '.join(reachable)} (real)"
                     if reachable else
                     "actuator present; sensitive sub-paths locked/not-advertised — benign, not a vuln"),
            "sources": ["actuator-probe"]})
    return found
