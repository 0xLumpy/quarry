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
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from . import fetch, normalize, secrets

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

# JSON config assignment on a secret-looking KEY: `"x.password": "val"` and the actuator/env wrap
# `"x.password": {"value": "val"}`. Catches Spring actuator /env + /configprops style secrets that
# aren't provider-shaped tokens (a plain DB password, a signing key).
_JSON_SECRET_RX = re.compile(
    r'"([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|signing[_-]?key|api[_-]?key|apikey|'
    r'access[_-]?key|private[_-]?key|token|credential)[A-Za-z0-9_.\-]*)"'
    r'\s*:\s*(?:\{\s*"value"\s*:\s*)?"([^"]{4,})"', re.I)
_MASKED_RX = re.compile(r"^[*•]+$")             # actuator sanitizes sensitive values to ******

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
    for m in _JSON_SECRET_RX.finditer(text):                      # JSON config (actuator env/configprops)
        key, val = m.group(1), m.group(2)
        if (val not in seen_vals and not _MASKED_RX.match(val)
                and val.lower() not in ("null", "true", "false")):
            seen_vals.add(val)
            out.append((f"json:{key}", val, text.count("\n", 0, m.start()) + 1))
    return out


def fetch_and_extract(ctx, url: str, *, source: str, subdir: str) -> dict:
    """General recon fetch→parse→extract: GET an in-scope resource (bounded, guarded, non-mutating),
    save the body as evidence, and extract secrets + in-scope links into the store (redacted, with
    provenance + raw_ref). The reusable layer — exposed-file / config / debug fetches are instances;
    callers add their own review framing. Returns a result dict:
      {ok, off_scope, final, status, dest, secrets, links}.
    `ok` False = not fetched (out of scope / non-200 / oversized / error). `off_scope` = the FINAL
    host (after redirect) was off-scope, so nothing was read."""
    host = normalize.host_of_url(url)
    res = {"ok": False, "off_scope": False, "final": url, "status": None,
           "dest": None, "secrets": 0, "links": 0}
    if not ctx.scope.active_allowed(host):         # in-scope + not-passive + not-OOS
        return res
    try:
        data, final, status = fetch.scoped_get(ctx, url, host, max_body=MAX_BODY)
    except Exception:
        return res
    res["final"], res["status"] = final, status
    if data is None:                               # off-scope redirect — caller records context
        res["off_scope"] = True
        return res
    if status != 200 or len(data) > MAX_BODY:
        return res
    text = data.decode("utf-8", "replace")
    dest = ctx.run.raw_path("params", subdir,
                            f"{host}-{hashlib.md5(url.encode()).hexdigest()[:8]}")
    dest.write_bytes(data)
    res["dest"] = str(dest)
    res["ok"] = True
    for kind, val, ln in mine(text):               # secrets (redacted, provenance, raw_ref)
        if ctx.run.add("secret", {
                "id": f"exposed:{kind}:{secrets.fingerprint(val or f'{kind}|{url}|{ln}')}",
                "kind": kind, "preview": secrets.mask(val),
                "file": str(dest), "location": url, "line": ln, "sources": [source]}):
            res["secrets"] += 1
    for e in normalize.urls(text, source, str(dest)):   # in-scope absolute links → corpus
        lu = e.get("url", "")
        lh = normalize.host_of_url(lu)
        if lu and ctx.scope.in_scope(lh) and not ctx.scope.is_oos(lh):
            if ctx.run.add("url", e):                    # keep normalize's full provenance (raw_ref)
                res["links"] += 1
    return res


def fetch_exposed(ctx, urls: list[str]) -> int:
    """GET each exposed in-scope resource (an instance of fetch_and_extract), extract its secrets +
    links, and raise a reviewable exposure marker. Returns count of NEW secret entities added."""
    added = 0
    for u in urls[:MAX_FETCHES]:
        r = fetch_and_extract(ctx, u, source="exposed-fetch", subdir="exposed")
        if r["off_scope"]:                         # off-scope redirect — record, no extraction
            ctx.run.add("review", {
                "id": f"exposed-redirect:{u}", "klass": "exposure", "value": u,
                "host": normalize.host_of_url(u), "location": r["final"],
                "note": f"redirected off-scope to {r['final']} (status {r['status']}); body NOT extracted",
                "sources": ["exposed-fetch"]})
            continue
        if not r["ok"]:
            continue
        added += r["secrets"]
        note = f"{r['secrets']} secret(s) extracted" if r["secrets"] else "fetched; no secret pattern"
        if r["links"]:
            note += f", {r['links']} in-scope link(s)"
        # The exposure itself as reviewable evidence (raw_ref → saved body). confirmed:false —
        # collected evidence, still human-reviewed; NO impact performed.
        ctx.run.add("review", {
            "id": f"exposed:{u}", "klass": "exposure", "value": u,
            "host": normalize.host_of_url(u), "raw_ref": r["dest"],
            "note": note, "sources": ["exposed-fetch"]})
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
            data, final, status = fetch.scoped_get(
                ctx, u, host, max_body=MAX_BODY, method="POST", data=_GQL_INTROSPECTION.encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json"})
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
        data, _final, status = fetch.scoped_get(ctx, base, host, max_body=MAX_BODY)
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
                data, _final, status = fetch.scoped_get(ctx, u, host, max_body=MAX_BODY)
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


_OPENAPI_MAX_BODY = 5 * 1024 * 1024    # 5 MB cap per doc (specs get big, still bounded)
_OPENAPI_MAX_PATHS = 2000              # bound endpoints extracted from one doc


def _openapi_load(text: str):
    """Parse an OpenAPI/Swagger doc — JSON first, then YAML. Returns a dict or None."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        import yaml
        obj = yaml.safe_load(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _openapi_bases(doc: dict, doc_url: str) -> list[str]:
    """Resolve the API base URL(s) — OpenAPI v3 `servers`, Swagger v2 `host`+`basePath`, else the
    doc's own origin. Relative server URLs are joined against the doc origin."""
    sp = urlsplit(doc_url)
    origin = f"{sp.scheme}://{sp.netloc}"
    bases: list[str] = []
    for s in (doc.get("servers") or []):
        u = s.get("url") if isinstance(s, dict) else None
        if u:
            bases.append(u if u.startswith(("http://", "https://"))
                         else urljoin(origin + "/", u.lstrip("/")))
    if not bases and (doc.get("host") or doc.get("basePath")):     # swagger v2
        scheme = (doc.get("schemes") or [sp.scheme or "https"])[0]
        bases.append(f"{scheme}://{doc.get('host') or sp.netloc}{doc.get('basePath') or ''}")
    return bases or [origin]


def parse_openapi(ctx, urls: list[str]) -> int:
    """Fetch discovered OpenAPI/Swagger docs (unauth, in-scope, non-mutating GET) and extract the
    endpoint + query-param corpus into the store — recon evidence, no probing of the endpoints
    themselves. Only in-scope endpoints are kept (a doc can advertise other hosts). Returns the
    count of NEW endpoint entities added."""
    added_ep = 0
    for u in urls[:MAX_FETCHES]:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):
            continue
        try:
            data, final, status = fetch.scoped_get(ctx, u, host, max_body=_OPENAPI_MAX_BODY)
        except Exception:
            continue
        if data is None:                           # off-scope redirect — record, don't parse
            ctx.run.add("review", {
                "id": f"openapi-redirect:{u}", "klass": "api-doc", "value": u, "host": host,
                "location": final,
                "note": f"redirected off-scope to {final} (status {status}); not parsed",
                "sources": ["openapi"]})
            continue
        if status != 200 or len(data) > _OPENAPI_MAX_BODY:
            continue
        text = data.decode("utf-8", "replace")
        doc = _openapi_load(text)
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            continue
        dest = ctx.run.raw_path("params", "openapi",
                                f"{host}-{hashlib.md5(u.encode()).hexdigest()[:8]}.json")
        dest.write_bytes(data)
        bases = [b.rstrip("/") + "/" for b in _openapi_bases(doc, u)]
        n_ep = n_pa = 0
        for path, ops in list(doc["paths"].items())[:_OPENAPI_MAX_PATHS]:
            if not isinstance(ops, dict):
                continue
            # query params for this path (path-level + per-operation), computed once
            params = list(ops.get("parameters") or [])
            for op in ops.values():
                if isinstance(op, dict):
                    params += list(op.get("parameters") or [])
            qnames = [p["name"] for p in params
                      if isinstance(p, dict) and p.get("name") and p.get("in") == "query"]
            # build under EVERY declared base — a spec can list several servers and the real
            # in-scope API may not be the first (staging/off-scope first). in-scope filter per base.
            for base in bases:
                full = urljoin(base, str(path).lstrip("/"))
                if not ctx.scope.in_scope(normalize.host_of_url(full)):   # doc may list other hosts
                    continue
                if ctx.run.add("endpoint", {"value": full, "kind": "openapi",
                                            "sources": ["openapi"], "raw_ref": str(dest)}):
                    n_ep += 1
                ctx.run.add("url", {"url": full, "sources": ["openapi"]})   # feed the corpus
                for name in qnames:
                    if ctx.run.add("parameter", {"value": f"{full}?{name}=",
                                                 "sources": ["openapi"]}):
                        n_pa += 1
        for kind, val, ln in mine(text):           # specs sometimes embed example keys
            ctx.run.add("secret", {
                "id": f"exposed:{kind}:{secrets.fingerprint(val or f'{kind}|{u}|{ln}')}",
                "kind": kind, "preview": secrets.mask(val),
                "file": str(dest), "location": u, "line": ln, "sources": ["openapi"]})
        added_ep += n_ep
        ctx.run.add("review", {
            "id": f"api-doc:{u}", "klass": "api-doc", "value": u, "host": host, "raw_ref": str(dest),
            "note": f"OpenAPI/Swagger parsed: {n_ep} endpoint(s), {n_pa} query param(s)",
            "sources": ["openapi"]})
    return added_ep


# SSTI confirmation payload: a distinctive product across the common template syntaxes (Jinja2/Twig,
# FreeMarker/JSP-EL, Ruby/JSF, ERB). A benign math EVAL — non-mutating, no impact — that upgrades a
# gf name-match into a confirmed PRIMITIVE. `1234*5678` is distinctive enough that the computed value
# appearing (while the literal expression does NOT) means the template engine evaluated it.
_SSTI_PROBE = "{{1234*5678}}${1234*5678}#{1234*5678}<%=1234*5678%>"
_SSTI_EXPECT = "7006652"
_SSTI_LITERAL = "1234*5678"
_SSTI_MAX_PARAMS = 10          # bound params tested per URL


def probe_ssti(ctx, urls: list[str]) -> int:
    """Confirm the SSTI PRIMITIVE on gf ssti candidates: inject a benign `{{math}}` polyglot into each
    query param (GET, non-mutating) and check the template ENGINE evaluated it (computed value present,
    literal expression absent). A hit is a CANDIDATE ("manual validation required"), not proof of
    impact — payload tuning / exploitation is the attack layer. Returns count of confirmed primitives."""
    found = 0
    for u in urls[:MAX_FETCHES]:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):
            continue
        sp = urlsplit(u)
        qs = parse_qsl(sp.query, keep_blank_values=True)
        if not qs:
            continue
        for i, (k, _v) in enumerate(qs[:_SSTI_MAX_PARAMS]):
            newq = list(qs)
            newq[i] = (k, _SSTI_PROBE)
            tu = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(newq), ""))
            try:
                data, _final, status = fetch.scoped_get(ctx, tu, host, max_body=MAX_BODY)
            except Exception:
                continue
            if data is None or status != 200 or len(data) > MAX_BODY:
                continue
            body = data.decode("utf-8", "replace")
            if _SSTI_EXPECT in body and _SSTI_LITERAL not in body:   # engine evaluated it
                # save the response evidence (the body that contained the computed value) so the
                # candidate is auditable / manually validatable — same evidence-rich pattern as the
                # exposed/actuator/openapi probes.
                dest = ctx.run.raw_path("params", "ssti",
                                        f"{host}-{hashlib.md5(tu.encode()).hexdigest()[:8]}.http")
                dest.write_bytes(data)
                ctx.run.add("finding", {
                    "id": f"ssti:{tu[:80]}", "template": "ssti-candidate",
                    "name": (f"SSTI primitive confirmed — template expr evaluated to {_SSTI_EXPECT} "
                             f"on param '{k}' (manual validation required)"),
                    "severity": "high", "matched": tu, "raw_ref": str(dest),
                    "sources": ["ssti-probe"], "confirmed": False})
                found += 1
                break                                 # one confirmation per URL is enough
    return found
