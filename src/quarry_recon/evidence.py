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

from . import events, fetch, normalize, secrets

# Exposed files worth fetching: secret/config stores, VCS metadata, key material, dumps.
SENSITIVE_FILE_RX = re.compile(r"""
    /(?:
        \.env(?:\.[\w.-]+)?                         # .env .env.local .env.production
      | \.git/config | \.git/HEAD | \.git/credentials
      | \.aws/credentials | \.s3cfg | \.netrc | \.htpasswd | \.dockercfg | \.npmrc | \.pypirc
      | config\.(?:json|ya?ml|php|inc) | settings\.py | secrets\.ya?ml | wp-config\.php
      | master\.key                                # Rails: decrypts credentials.yml.enc outright
      | credentials\.yml\.enc
      | appsettings(?:\.[\w-]+)?\.json            # .NET: connection strings + signing keys
      | web\.config
      | \.DS_Store
      | id_rsa | id_dsa | id_ecdsa | id_ed25519 | [\w.-]+\.pem
      | (?:db|database|dump|backup)\.sql
    )(?:$|\?)
""", re.IGNORECASE | re.VERBOSE)

#: Files that ARE credential stores but hold ciphertext. Fetching one is worth it — it is exposed, it is
#: the real store, and it becomes plaintext the moment its key leaks (Rails ships exactly that pairing).
#: But nothing was MINED from it, and "fetched; no secret pattern" reads as "nothing here" (review#4,
#: Lumpy). It is reported as what it is: an exposed encrypted credential store.
ENCRYPTED_STORE_RX = re.compile(r"(?:^|/)(?:credentials(?:\.[\w-]+)?\.yml\.enc|secrets\.yml\.enc)$",
                                re.IGNORECASE)

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

#: .NET / ADO connection strings carry the password INSIDE the value, under a key like
#: `DefaultConnection` that no secret-ish key pattern will ever match (measured 2026-08-05). The match
#: requires CONNECTION-STRING STRUCTURE around it — a `Server=`/`Data Source=`/`Host=` style field in the
#: same value — because `password=` on its own appears in documentation, examples, query strings and
#: ordinary prose, and calling those database credentials is a claim we cannot support (review#6, Lumpy).
#: one candidate value: a semicolon-delimited run of `field=value` pairs. Which pairs it holds is
#: decided AFTER splitting, because requiring the anchor to come first missed
#: `Password=x;User ID=sa;Server=db` — a perfectly ordinary connection string (review#4, Lumpy).
_CONNSTR_CANDIDATE_RX = re.compile(r"[^\"'\r\n]{0,400}?=[^\"'\r\n]{0,400}")
_CONNSTR_ANCHOR = re.compile(r"(?i)\A\s*(?:data\s+source|server|host|initial\s+catalog|database|dsn|"
                             r"user\s*id|uid|integrated\s+security|provider)\s*\Z")
_CONNSTR_PASSWORD = re.compile(r"(?i)\A\s*(?:password|pwd)\s*\Z")


def _connstring_passwords(text: str):
    """(password, offset) for every value that is REALLY a connection string.

    A `password=` on its own appears in documentation, examples, query strings and prose; the claim
    "database credential" needs an ANCHOR field beside it (`Server`, `Data Source`, `User ID`…). Fields
    are split first, so the two may appear in any order."""
    for m in _CONNSTR_CANDIDATE_RX.finditer(text):
        chunk = m.group(0)
        if ";" not in chunk:
            continue
        fields = [f.split("=", 1) for f in chunk.split(";") if "=" in f]
        if not any(_CONNSTR_ANCHOR.match(k) for k, _v in fields):
            continue
        for k, v in fields:
            if _CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                yield v.strip(), m.start()

#: password VERIFIERS. A hash is not a credential value: it proves the store leaked and it is
#: offline-crackable, which is worth reporting as its own thing rather than as a recovered secret
#: (review#2, Lumpy). Kinds listed here are published as `credential-hash` review evidence.
HASH_KINDS = frozenset({"bcrypt-hash"})
#: kinds that are SIGNING CONTEXT, not proven secrets. review#9 (Lumpy): `kid`, `issuer`, `audience`,
#: `algorithm` and `expiry` accompany PUBLIC verification keys as readily as private ones — a JWKS entry
#: (`{"key": …, "kid": "k1", "algorithm": "RS256"}`) is published material by design. The value is worth
#: keeping and is not evidence of a leaked secret, so it is routed as an observation.
OBSERVATION_KINDS = frozenset({"signing-key"})
#: what DOES establish secret material in that context: a symmetric algorithm means the signing key and
#: the verifying key are the same string, so publishing it would be the leak.
_SYMMETRIC_ALG_RX = re.compile(r'"(?:alg|algorithm)"\s*:\s*"(?:HS(?:256|384|512)|A\d{3}(?:GCM)?KW|'
                               r'dir|symmetric)"', re.I)
_HASH_RX = [
    ("bcrypt-hash", re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}")),
]

#: FORMAT rules: (path pattern, kind, body pattern). A Rails `master.key` is 32 hex characters and
#: nothing else — no assignment, no key name, nothing for a `KEY=value` or JSON rule to catch, so it was
#: fetched, saved and mined for nothing (measured 2026-08-05).
#:
#: They are gated on the SOURCE PATH, because the body alone cannot carry the claim: 32 lowercase hex is
#: also every MD5, every git blob id and half the ETags on the internet (review#1, Lumpy). A rule with no
#: named file format behind it does not belong here at all — a generic 64-hex "key" was exactly that and
#: is gone (review#3).
_FORMAT_RULES = [
    (re.compile(r"(?:^|/)master\.key$", re.I), "rails-master-key", re.compile(r"\A[0-9a-f]{32}\Z")),
]

# dotenv / config assignment `KEY = value`; captures a secret-looking VALUE on a secret-looking KEY.
#
# The value is read in three shapes, because the previous single pattern excluded `#` from the value and
# therefore DROPPED — not truncated, dropped — every password containing one, quoted or not (measured
# 2026-08-05: `DB_PASSWORD='P@ss...!#$%'` yielded nothing at all). A quoted value is taken whole, `#`
# included; an unquoted one keeps its `#` unless it starts an inline comment, which by dotenv convention
# needs preceding whitespace.
_DOTENV_RX = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[=:]\s*(?:
      '([^'\r\n]{4,})'                      # 'single quoted, # and " allowed'
    | "([^"\r\n]{4,})"                      # "double quoted"
    | ([^'"\r\n]{6,}?)                      # bare, inline comment stripped below
    )\s*$""", re.VERBOSE)
_INLINE_COMMENT_RX = re.compile(r"\s+#.*$")
_SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|pass|pwd|api|auth|cred|private|access)")

# JSON config assignment on a secret-looking KEY: `"x.password": "val"` and the actuator/env wrap
# `"x.password": {"value": "val"}`. Catches Spring actuator /env + /configprops style secrets that
# aren't provider-shaped tokens (a plain DB password, a signing key).
_JSON_SECRET_RX = re.compile(
    r'"([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|signing[_-]?key|api[_-]?key|apikey|'
    r'access[_-]?key|private[_-]?key|token|credential)[A-Za-z0-9_.\-]*)"'
    r'\s*:\s*(?:\{\s*"value"\s*:\s*)?"([^"]{4,})"', re.I)
#: A bare `"Key"` is how .NET writes a JWT signing secret and how a thousand harmless config blocks
#: write an identifier — an OpenAPI example, a package manifest, a public id, an ordinary API response.
#: Length alone is not a claim (review#1, Lumpy), so this needs one of two contexts: the FILE FORMAT that
#: writes signing keys that way, or a JWT/signing parent right beside it.
_JSON_BARE_KEY_RX = re.compile(r'"(key)"\s*:\s*"([^"]{20,})"', re.I)
_JSON_BARE_KEY_PATHS = re.compile(r"(?:^|/)(?:appsettings(?:\.[\w-]+)?\.json|web\.config)$", re.I)
#: `"Jwt": { … "Key": "…" }` / `"TokenSigning": {"key": …}` — the parent names what the key is FOR.
#: `auth`, `token` and `bearer` are NOT enough on their own: `{"authorization": {"key": "public-id…"}}`
#: is an ordinary API response (review#2, Lumpy). Either the parent explicitly says JWT/signing, or the
#: object carries a companion signing field — an algorithm, an issuer, an audience, a key id.
_JSON_SIGNING_CONTEXT_RX = re.compile(
    r'"[A-Za-z0-9_.\-]*(?:jwt|jws|signing|signature)[A-Za-z0-9_.\-]*"\s*:\s*\{[^{}]{0,300}?'
    r'"(key)"\s*:\s*"([^"]{20,})"', re.I)
#: STRUCTURAL scan: parse the document and look at the object a key actually lives in. Text proximity
#: does not establish a relationship — a ±200-char window promoted a PUBLIC key to a secret because a
#: NEIGHBOURING object mentioned HS256 (review#1, Lumpy). The regexes below remain for bodies that do not
#: parse as JSON (XML `web.config`, truncated or templated config), where they stay observations only.
_SIGNING_FIELDS = {"alg", "algorithm", "iss", "issuer", "aud", "audience", "kid",
                   "expiry", "expires_in", "lifetime"}
_SYMMETRIC_ALGS = re.compile(r"\A(?:HS(?:256|384|512)|A\d{3}(?:GCM)?KW|dir|symmetric)\Z", re.I)
_SIGNING_PARENT = re.compile(r"(?:jwt|jws|signing|signature)", re.I)


def _json_key_findings(doc, *, parent_key: str = "", by_format: bool = False):
    """Walk a parsed document and classify every bare `key` by the OBJECT it lives in.

    Yields (kind, value). Three answers, and the object decides all three:

      symmetric algorithm in the SAME object  -> a secret (signing and verifying key are one string)
      signing PARENT + the format that stores signing secrets -> a secret (.NET writes it there)
      signing context otherwise               -> an observation (a JWKS entry looks exactly like this)
    """
    if isinstance(doc, list):
        for item in doc:
            yield from _json_key_findings(item, parent_key=parent_key, by_format=by_format)
        return
    if not isinstance(doc, dict):
        return
    lower = {str(k).lower(): v for k, v in doc.items()}
    companions = {k for k in lower if k in _SIGNING_FIELDS}
    symmetric = any(isinstance(lower.get(a), str) and _SYMMETRIC_ALGS.match(lower[a].strip())
                    for a in ("alg", "algorithm"))
    signing_parent = bool(_SIGNING_PARENT.search(parent_key))
    for k, v in doc.items():
        if str(k).lower() == "key" and isinstance(v, str) and len(v) >= 20:
            if symmetric:
                yield f"json:{k}", v
            elif by_format and (signing_parent or companions):
                # the FORMAT stores signing secrets AND this object is a signing config. `appsettings`
                # also holds cache keys, public ids and nested app config, so the format alone is not
                # the claim (review#2, Lumpy).
                yield f"json:{k}", v
            elif signing_parent or companions:
                yield "signing-key", v
    for k, v in doc.items():
        if isinstance(v, (dict, list)):
            yield from _json_key_findings(v, parent_key=str(k), by_format=by_format)


#: the same object naming HOW the key is used: `{"key": "…", "algorithm": "HS256", "issuer": "…"}`.
#: TWO patterns rather than one alternation: every rule in this list must yield (key, value) as groups
#: 1 and 2, and an alternation renumbers them — the first version handed `None` to the loop.
_SIGNING_COMPANION = (r"alg|algorithm|iss|issuer|aud|audience|kid|expiry|expires_in|lifetime")
_JSON_SIGNING_COMPANION_AFTER_RX = re.compile(
    r'\{[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"', re.I)
_JSON_SIGNING_COMPANION_BEFORE_RX = re.compile(
    r'\{[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"', re.I)
_MASKED_RX = re.compile(r"^[*•]+$")             # actuator sanitizes sensitive values to ******

MAX_BODY = 2 * 1024 * 1024    # 2 MB cap per exposed resource (RAM/disk guard)
#: REMOVED as a membership bound (Lumpy, 2026-08-05). `urls[:50]` silently dropped the 51st exposed
#: file, GraphQL endpoint, actuator base, OpenAPI document and framework candidate — never fetched,
#: never reported, and directly capable of hiding a secret-bearing file. Membership is not the control:
#: request PRESSURE is `RATELIMIT.HTTP`, which every fetch already goes through. What each lane owes is
#: an honest count of what it looked at, which `_fetched()` emits.


def _fetched(sid: str, eligible: int, tested: int, what: str) -> None:
    """Say how much of the candidate set was actually fetched.

    MEASURED, never intended (review#11, Lumpy): the first version emitted `tested=len(urls)` BEFORE the
    loop, so a run whose every candidate was out of scope, refused or threw still published `60/60
    fetched`. `eligible` is counted AFTER scope gating, `tested` at the point a request was really
    issued, and the record is emitted when the loop is done."""
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="evidence_fetches",
                            unit=f"{sid}.candidates", eligible=eligible, tested=tested,
                            omitted=max(0, eligible - tested),
                            reason=(f"{tested}/{eligible} {what} fetched"
                                    + ("" if tested >= eligible else " — the rest were NOT looked at")))


def mine(text: str, *, source_path: str | None = None) -> list[tuple[str, str, int]]:
    """(kind, raw_value, line) for each secret found in `text`. Read-only — no exploit.

    Provider-shaped tokens win over the generic dotenv catch for the same value (more specific).

    `source_path` is the URL or path the body came from. Generic token rules run everywhere; FORMAT
    rules run only against the file format they describe, because a body alone cannot carry that claim —
    32 lowercase hex is a Rails master key in `config/master.key` and an MD5 everywhere else (review#1,
    Lumpy). Without a path, format rules simply do not fire: an unclassified body is not a Rails secret.
    """
    out: list[tuple[str, str, int]] = []
    seen_vals: set[str] = set()
    path = urlsplit(source_path).path if source_path else ""
    for kind, rx in _TOKEN_RX:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            out.append((kind, val, text.count("\n", 0, m.start()) + 1))
            seen_vals.add(val)
    for m in _DOTENV_RX.finditer(text):
        key = m.group(1)
        quoted, val = (m.group(2) or m.group(3)), (m.group(2) or m.group(3) or m.group(4) or "")
        if quoted is None:
            val = _INLINE_COMMENT_RX.sub("", val)
        val = val.strip() if quoted is None else val
        if _SECRETISH_KEY.search(key) and val not in seen_vals:   # already caught as a typed token
            seen_vals.add(val)
            out.append((f"dotenv:{key}", val, text.count("\n", 0, m.start()) + 1))
    by_format = bool(path and _JSON_BARE_KEY_PATHS.search(path))
    for rx_set in (_JSON_SECRET_RX,):
        for m in rx_set.finditer(text):                           # JSON config (actuator env, .NET…)
            key, val = m.group(1), m.group(2)
            if (val not in seen_vals and not _MASKED_RX.match(val)
                    and val.lower() not in ("null", "true", "false")):
                seen_vals.add(val)
                out.append((f"json:{key}", val, text.count("\n", 0, m.start()) + 1))
    # bare `"key"` fields, decided STRUCTURALLY where the body parses. Text proximity does not
    # establish a relationship: a ±200-char window promoted a PUBLIC key to a secret because a
    # NEIGHBOURING object mentioned HS256 (review#1, Lumpy).
    parsed = None
    if text.lstrip()[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    if parsed is not None:
        for kind, val in _json_key_findings(parsed, by_format=by_format):
            if val in seen_vals or _MASKED_RX.match(val):
                continue
            seen_vals.add(val)
            at = text.find(val)
            out.append((kind, val, text.count("\n", 0, at) + 1 if at >= 0 else 1))
    else:
        # a body whose object boundaries we cannot read (XML `web.config`, a template, a truncated
        # dump) never promotes: observation only.
        for rx_set in (_JSON_SIGNING_CONTEXT_RX, _JSON_SIGNING_COMPANION_AFTER_RX,
                       _JSON_SIGNING_COMPANION_BEFORE_RX):
            for m in rx_set.finditer(text):
                val = m.group(2)
                if val in seen_vals or _MASKED_RX.match(val):
                    continue
                seen_vals.add(val)
                out.append(("signing-key", val, text.count("\n", 0, m.start()) + 1))
    for val, at in _connstring_passwords(text):                    # a password inside a connection string
        if val and val not in seen_vals:
            seen_vals.add(val)
            out.append(("connection-string-password", val, text.count("\n", 0, at) + 1))
    for kind, rx in _HASH_RX:                                      # verifiers, not credential values
        for m in rx.finditer(text):
            val = m.group(0)
            if val not in seen_vals:
                seen_vals.add(val)
                out.append((kind, val, text.count("\n", 0, m.start()) + 1))
    # …and the file that IS a secret, with no key to hang it on. FORMAT-gated: see the docstring.
    body = text.strip()
    if body and path and body not in seen_vals:
        for path_rx, kind, body_rx in _FORMAT_RULES:
            if path_rx.search(path) and body_rx.match(body):
                out.append((kind, body, 1))
                break
    return out


def publish_finding(ctx, kind: str, val: str, line, *, url: str, dest, source: str,
                    host: str | None = None, final_url: str | None = None) -> str:
    """Route ONE mined finding to the entity that describes it. Returns "secret", "hash" or "".

    One place decides what a kind IS, because five call sites deciding separately is how a password
    VERIFIER ends up in the secret queue on four of them. A hash proves the store leaked and is
    offline-crackable; it is not a recovered credential and must not be counted as one.

    The COMPLETE value is stored on the entity (`value`), and `preview` stays masked for every prose
    channel — report lines, digests, messenger. The entity is local project data next to the raw
    artifact it came from; the preview is what travels. Storing only a preview was the older behaviour
    and it lost the finding itself: one artifact can hold many values, and "grep the raw file" is not
    the same as reporting the secret you found (review#3, Lumpy)."""
    # the host that ANSWERED owns the finding. An in-scope redirect from `a.example.com/.env` to
    # `b.example.com/real.env` puts the credential on b, and recording it against a points the report at
    # the wrong asset (review#1, Lumpy). The requested URL stays in `location` as provenance.
    where = normalize.host_of_url(final_url or url) or host or normalize.host_of_url(url)
    if kind in OBSERVATION_KINDS:
        # signing CONTEXT, not a proven secret: a JWKS entry publishes exactly this shape. Kept whole,
        # with its provenance, in the review queue — where an operator decides whether the material is
        # private (review#9, Lumpy).
        ok = ctx.run.add("review", {
            "id": f"signing-key:{secrets.fingerprint(val)}", "klass": "signing-key",
            "value": val, "host": where, "raw_ref": str(dest) if dest else None, "location": url,
            **({"final": final_url} if final_url and final_url != url else {}),
            "line": line,
            "note": "a key in a SIGNING context (kid/issuer/audience/algorithm). Public verification "
                    "material has this shape too — not evidence of a leaked secret on its own.",
            "sources": [source]})
        return "observation" if ok else ""
    if kind in HASH_KINDS:
        ok = ctx.run.add("review", {
            "id": f"credential-hash:{secrets.fingerprint(val)}", "klass": "credential-hash",
            "value": val, "host": where, "raw_ref": str(dest) if dest else None, "location": url,
            **({"final": final_url} if final_url and final_url != url else {}),
            "line": line,
            "note": f"{kind}: a password verifier, offline-crackable — NOT the password. Its presence "
                    f"proves the credential store leaked.",
            "sources": [source]})
        return "hash" if ok else ""
    ok = ctx.run.add("secret", {
        "id": f"exposed:{kind}:{secrets.fingerprint(val or f'{kind}|{url}|{line}')}",
        "kind": kind, "value": val, "preview": secrets.mask(val), "host": where,
        "file": str(dest) if dest else None, "location": url,
        **({"final": final_url} if final_url and final_url != url else {}),
        "line": line, "sources": [source]})
    return "secret" if ok else ""


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
    # CLASSIFY BY WHAT ANSWERED. `scoped_get` follows redirects per hop, so a request for
    # `/config/master.key` can be answered by `/checksums.txt` — and a format rule keyed on the
    # REQUESTED path would call that body a Rails master key (review#2, Lumpy). Provenance keeps both:
    # `location` is what we asked for, `final` is what replied.
    final_url = res["final"] or url
    for kind, val, ln in mine(text, source_path=final_url):   # secrets (provenance, raw_ref)
        got = publish_finding(ctx, kind, val, ln, url=url, dest=dest, source=source, host=host,
                              final_url=final_url)
        if got == "secret":
            res["secrets"] += 1
        elif got == "hash":
            res["hashes"] = res.get("hashes", 0) + 1
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
    added = eligible = tested = 0
    for u in urls:
        if not ctx.scope.active_allowed(normalize.host_of_url(u)):
            continue                               # not ours to request: never part of the denominator
        eligible += 1
        r = fetch_and_extract(ctx, u, source="exposed-fetch", subdir="exposed")
        if r["status"] is not None or r["off_scope"]:
            tested += 1                            # a request was actually issued
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
        if ENCRYPTED_STORE_RX.search(urlsplit(r["final"] or u).path):
            note = ("exposed ENCRYPTED credential store — ciphertext, nothing decrypted here. It becomes "
                    "plaintext with its key (Rails: config/master.key), so the two together are the "
                    "finding")
        elif r["secrets"]:
            note = f"{r['secrets']} secret(s) extracted"
        else:
            note = "fetched; no secret pattern"
        if r.get("hashes"):
            note += f", {r['hashes']} password hash(es) — verifiers, not credentials"
        if r["links"]:
            note += f", {r['links']} in-scope link(s)"
        # The exposure itself as reviewable evidence (raw_ref → saved body). confirmed:false —
        # collected evidence, still human-reviewed; NO impact performed.
        ctx.run.add("review", {
            "id": f"exposed:{u}", "klass": "exposure", "value": u,
            "host": normalize.host_of_url(u), "raw_ref": r["dest"],
            "note": note, "sources": ["exposed-fetch"]})
    _fetched("evidence.exposed", eligible, tested, "in-scope exposed resource(s)")
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
    for u in endpoints:
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
_DEEP_MAX_BODY = 64 * 1024 * 1024          # 64 MB cap when deep-evidence downloads a heavy artifact


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


def _deep_download(ctx, url: str, host: str, kind: str) -> bool:
    """Deep-evidence (opt-in): download a heavy artifact (bounded), save the raw bytes, and mine it
    for secrets (ASCII secrets survive inside a binary heap dump). Adds its own high-priority review.
    Returns True on a recorded download, False on failure (caller falls back to detect-only)."""
    try:
        data, _final, status = fetch.scoped_get(ctx, url, host, max_body=_DEEP_MAX_BODY)
    except Exception:
        return False
    if data is None or status != 200:
        return False                               # off-scope/absent → caller does detect-only fallback
    if len(data) > _DEEP_MAX_BODY:
        # fetched (so NOT "not requested") but over the cap — don't save a truncated/partial dump.
        ctx.run.add("review", {
            "id": f"actuator-heavy:{url}", "klass": "actuator", "value": url, "host": host,
            "priority": "high",
            "note": (f"{kind} exposed + fetched but exceeds the {_DEEP_MAX_BODY // 1024 // 1024} MB "
                     "deep-evidence cap — not saved/mined (raise the cap to pull it)"),
            "sources": ["deep-evidence"]})
        return True                                # handled — skip the misleading "NOT requested" review
    dest = ctx.run.raw_path("params", "actuator",
                            f"{host}-{kind}-{hashlib.md5(url.encode()).hexdigest()[:8]}.bin")
    dest.write_bytes(data)
    nsec = 0
    for k, val, ln in mine(data.decode("utf-8", "replace"), source_path=url):
        if publish_finding(ctx, k, val, ln, url=url, dest=dest, source="deep-evidence") == "secret":
            nsec += 1
    ctx.run.add("review", {
        "id": f"actuator-heavy:{url}", "klass": "actuator", "value": url, "host": host,
        "priority": "high", "raw_ref": str(dest),
        "note": f"{kind} DOWNLOADED via deep-evidence ({len(data) // 1024} KB) — {nsec} secret(s) mined",
        "sources": ["deep-evidence"]})
    return True


def probe_actuator(ctx, bases: list[str]) -> int:
    """Interrogate a Spring Boot actuator base and classify real-vs-benign. Cheap sensitive READ
    endpoints (`/actuator/env` etc.) are GET-probed for reachability (200 = real exposure, mine
    env/configprops for secrets). HEAVY endpoints (heapdump) are detected from the index `_links`
    only — never requested, since the GET itself would trigger dump generation (impact). All locked
    / not advertised = benign (the Test-5 triage-precision case). Mutating endpoints never touched.
    Returns the count of bases with >=1 sensitive endpoint exposed."""
    found = 0
    for base in bases:
        host = normalize.host_of_url(base)
        if not ctx.scope.active_allowed(host):
            continue
        advertised = _actuator_index_links(ctx, base, host)
        deep = getattr(getattr(ctx, "profile", None), "deep_evidence", False)
        # heavy endpoints: default = flag high-priority from the advertised link, NO request. Deep-
        # evidence mode (opt-in) = download + mine the artifact (a GET to /actuator/heapdump forces
        # server-side dump generation — done only because the operator turned DEEP_EVIDENCE on).
        heavy_exposed = [h for h in _ACTUATOR_HEAVY if h in advertised]
        for h in heavy_exposed:
            hu = base.rstrip("/") + "/" + h
            if deep and _deep_download(ctx, hu, host, h):
                continue                               # downloaded + mined; review added inside
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
                for kind, val, ln in mine(data.decode("utf-8", "replace"), source_path=u):
                    publish_finding(ctx, kind, val, ln, url=u, dest=dest, source="actuator-probe",
                                    host=host)
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
    for u in urls:
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
        for kind, val, ln in mine(text, source_path=u):     # specs sometimes embed example keys
            publish_finding(ctx, kind, val, ln, url=u, dest=dest, source="openapi", host=host)
        added_ep += n_ep
        ctx.run.add("review", {
            "id": f"api-doc:{u}", "klass": "api-doc", "value": u, "host": host, "raw_ref": str(dest),
            "note": f"OpenAPI/Swagger parsed: {n_ep} endpoint(s), {n_pa} query param(s)",
            "sources": ["openapi"]})
    return added_ep


_FW_ENDPOINTS: dict | None = None


def _framework_endpoints() -> dict:
    """Load + cache the framework → recon-endpoint map (data/framework-endpoints.yaml). Best-effort:
    a malformed/missing file yields {} (the probe simply produces no candidates)."""
    global _FW_ENDPOINTS
    if _FW_ENDPOINTS is None:
        import yaml
        from pathlib import Path
        p = Path(__file__).resolve().parent / "data" / "framework-endpoints.yaml"
        try:
            _FW_ENDPOINTS = yaml.safe_load(p.read_text()) or {}
        except Exception:
            _FW_ENDPOINTS = {}
    return _FW_ENDPOINTS


def probe_framework_endpoints(ctx, candidates: list[dict]) -> int:
    """GET framework-specific recon endpoints on hosts whose httpx tech matched a framework in
    framework-endpoints.yaml. These are NON-MUTATING reads of exposed debug/admin dashboards + info
    endpoints (same boundary as the Spring /actuator probe): 200 = EXPOSED (tagged high-priority +
    body mined for secrets), 401/403/redirect = present-but-protected (tagged, lower). Recon evidence
    only — no payloads/creds/state change; exploitation (Werkzeug PIN, CFIDE/H2/Jolokia/Ignition RCE)
    is the attack layer. `candidates` = [{url, framework, note}]. Returns the count of EXPOSED (200)."""
    exposed_n = 0
    for c in candidates:
        u = c.get("url", "")
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):
            continue
        try:
            data, final, status = fetch.scoped_get(ctx, u, host, max_body=MAX_BODY)
        except Exception:
            continue
        if data is None:                               # off-scope redirect — don't read
            continue
        if status == 200 and len(data) <= MAX_BODY:
            dest = ctx.run.raw_path("params", "framework",
                                    f"{host}-{hashlib.md5(u.encode()).hexdigest()[:8]}")
            dest.write_bytes(data)
            nsec = 0
            for kind, val, ln in mine(data.decode("utf-8", "replace"), source_path=u):
                if publish_finding(ctx, kind, val, ln, url=u, dest=dest,
                                   source="framework-probe", host=host) == "secret":
                    nsec += 1
            exposed_n += 1
            ctx.run.add("review", {
                "id": f"debug:{u}", "klass": "debug", "value": u, "host": host, "priority": "high",
                "framework": c.get("framework"), "raw_ref": str(dest),
                "note": f"EXPOSED (200): {c.get('note') or 'framework debug/admin endpoint'}"
                        + (f" — {nsec} secret(s) mined" if nsec else ""),
                "sources": ["framework-probe"]})
        elif status in (301, 302, 303, 307, 308, 401, 403):
            ctx.run.add("review", {
                "id": f"debug:{u}", "klass": "debug", "value": u, "host": host,
                "framework": c.get("framework"),
                "note": f"present but protected (status {status}): "
                        f"{c.get('note') or 'framework debug/admin endpoint'}",
                "sources": ["framework-probe"]})
    return exposed_n


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
    for u in urls:
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
