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
from pathlib import Path
from types import SimpleNamespace
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
#: MEASURED 2026-08-06, once the 2 MiB cap stopped hiding it: the old candidate pattern was
#: `[^"'\r\n]{0,400}?=[^"'\r\n]{0,400}` — a LAZY 400-char prefix tried at every offset, so a long line
#: with no `=` in it cost ~400 character tests per position. 3.7 s per MiB, and `mine()` spent 99% of
#: its time here. `=` is the anchor, so find the anchors and expand a bounded window around each.
_CONNSTR_EQ_RX = re.compile(r"=")
_CONNSTR_BREAK = frozenset('"\'\r\n')
_CONNSTR_SPAN = 400
_CONNSTR_ANCHOR = re.compile(r"(?i)\A\s*(?:data\s+source|server|host|initial\s+catalog|database|dsn|"
                             r"user\s*id|uid|integrated\s+security|provider)\s*\Z")
_CONNSTR_PASSWORD = re.compile(r"(?i)\A\s*(?:password|pwd)\s*\Z")


class _JSONPath(str):
    """Structural provenance: WHERE in the document a finding lives (`auth.jwt.key`, `[2].key`).

    A `str` subclass so it can travel in the same slot as a line number without changing `mine()`'s
    tuple shape, and be told apart from one at publication. review#23 (Lumpy): the immediate parent
    alone is ambiguous in a nested document, so the FULL chain is carried."""


def _json_path(trail, key) -> _JSONPath:
    """`auth.jwt.key` — the whole chain, list indices included."""
    return _JSONPath(".".join([*(str(t) for t in (trail or ())), str(key)]))


class _OFFSET(int):
    """A byte OFFSET into the body, not a line number. `mine()` resolves it; publishing it raw would
    put a character position in a field an operator reads as a line."""


def _connstring_passwords(text: str, rejected=None):
    """(password, offset) for every value that is REALLY a connection string.

    A `password=` on its own appears in documentation, examples, query strings and prose; the claim
    "database credential" needs an ANCHOR field beside it (`Server`, `Data Source`, `User ID`…). Fields
    are split first, so the two may appear in any order."""
    covered = -1
    for m in _CONNSTR_EQ_RX.finditer(text):
        if m.start() <= covered:
            continue                          # already inside a window we examined
        lo = m.start()
        while lo > 0 and m.start() - lo < _CONNSTR_SPAN and text[lo - 1] not in _CONNSTR_BREAK:
            lo -= 1
        hi = m.end()
        while hi < len(text) and hi - m.end() < _CONNSTR_SPAN and text[hi] not in _CONNSTR_BREAK:
            hi += 1
        covered = hi - 1
        chunk = text[lo:hi]
        if ";" not in chunk:
            continue
        fields = [f.split("=", 1) for f in chunk.split(";") if "=" in f]
        if not any(_CONNSTR_ANCHOR.match(k) for k, _v in fields):
            if rejected is not None:
                # `password=` with no `Server=`/`Data Source=` beside it. Calling that a database
                # credential is a claim we cannot support — but the value is still there.
                for k, v in fields:
                    if _CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                        # the window's start offset, resolved to a line by the caller. It was hardcoded
                        # to 1 — false precision pointing an operator at the wrong line (review#22).
                        rejected.append(("password= without connection-string structure", k.strip(),
                                         v.strip(), _OFFSET(lo)))
            continue
        for k, v in fields:
            if _CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                yield v.strip(), lo

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


def _json_key_findings(doc, *, trail=(), by_format: bool = False, rejected=None):
    """Walk a parsed document and classify every bare `key` by the OBJECT it lives in.

    Yields (kind, value). Three answers, and the object decides all three:

      symmetric algorithm in the SAME object  -> a secret (signing and verifying key are one string)
      signing PARENT + the format that stores signing secrets -> a secret (.NET writes it there)
      signing context otherwise               -> an observation (a JWKS entry looks exactly like this)
    """
    if isinstance(doc, list):
        for i, item in enumerate(doc):
            yield from _json_key_findings(item, trail=(*trail, f"[{i}]"), by_format=by_format,
                                          rejected=rejected)
        return
    if not isinstance(doc, dict):
        return
    lower = {str(k).lower(): v for k, v in doc.items()}
    companions = {k for k in lower if k in _SIGNING_FIELDS}
    symmetric = any(isinstance(lower.get(a), str) and _SYMMETRIC_ALGS.match(lower[a].strip())
                    for a in ("alg", "algorithm"))
    # the nearest NAMED ancestor, not simply the previous path component (review#24, Lumpy):
    # `{"Jwt": {"key": …}}` classified and `{"Jwt": [{"key": …}]}` did not, because the component
    # before the object was the list index `[0]`. An array of signing configs is still signing config.
    _named = next((t for t in reversed(trail) if not str(t).startswith("[")), "")
    signing_parent = bool(_SIGNING_PARENT.search(str(_named)))
    for k, v in doc.items():
        if str(k).lower() == "key" and isinstance(v, str) and len(v) >= 20:
            here = _json_path(trail, k)
            if symmetric:
                yield f"json:{k}", v, here
            elif by_format and (signing_parent or companions):
                # the FORMAT stores signing secrets AND this object is a signing config. `appsettings`
                # also holds cache keys, public ids and nested app config, so the format alone is not
                # the claim (review#2, Lumpy).
                yield f"json:{k}", v, here
            elif signing_parent or companions:
                yield "signing-key", v, here
            elif rejected is not None:
                # a 20+ character `key` in an object that establishes NOTHING about it. Not a secret
                # claim and not nothing either — kept, with the reason it was not promoted.
                # no offset exists here: this walks a PARSED object, not the text. `text.find(val)` was
                # the wrong repair — the same string under `"name"` on line 2 and the rejected `"key"`
                # on line 4 reported line 2, which is provenance pointing at a different field
                # (review#22, Lumpy). A STRUCTURAL finding gets structural provenance: the key path it
                # actually lives at, and NO line at all.
                rejected.append((f"bare `key` field with no signing or symmetric context "
                                 f"[at {here}]", str(k), v, here))
    for k, v in doc.items():
        if isinstance(v, (dict, list)):
            yield from _json_key_findings(v, trail=(*trail, str(k)), by_format=by_format,
                                          rejected=rejected)


#: the same object naming HOW the key is used: `{"key": "…", "algorithm": "HS256", "issuer": "…"}`.
#: TWO patterns rather than one alternation: every rule in this list must yield (key, value) as groups
#: 1 and 2, and an alternation renumbers them — the first version handed `None` to the loop.
_SIGNING_COMPANION = (r"alg|algorithm|iss|issuer|aud|audience|kid|expiry|expires_in|lifetime")
_JSON_SIGNING_COMPANION_AFTER_RX = re.compile(
    r'\{[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"', re.I)
_JSON_SIGNING_COMPANION_BEFORE_RX = re.compile(
    r'\{[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"', re.I)
_MASKED_RX = re.compile(r"^[*•]+$")             # actuator sanitizes sensitive values to ******

#: REPLACED as an acquisition bound (Lumpy, 2026-08-06). `MAX_BODY = 2 MiB` dropped an over-cap response
#: ENTIRELY — not truncated, not saved, not reported — and `evidence_fetches` still counted it completed,
#: so the counter claimed we had read something we threw away. The request had already happened: the cap
#: prevented no cost, it only converted a fetched body into no evidence.
#:
#: Acquisition is now unbounded in bytes and bounded in MEMORY and TIME (`fetch.scoped_get_file` streams
#: in fixed chunks). What remains bounded is INTERPRETATION: the regex/JSON pass below holds the whole
#: body as text, so `MAX_PARSE` is the memory ceiling on THAT pass. Over it, the artifact is published
#: whole and interpretation is DEFERRED — recorded, re-runnable from the artifact, no second request.
MAX_PARSE = 64 * 1024 * 1024
#: one chunk in RAM while streaming, and the wall-clock bound on a socket that never reaches EOF.
STREAM_CHUNK = 1024 * 1024
STREAM_DEADLINE_S = 300.0
#: REMOVED as a membership bound (Lumpy, 2026-08-05). `urls[:50]` silently dropped the 51st exposed
#: file, GraphQL endpoint, actuator base, OpenAPI document and framework candidate — never fetched,
#: never reported, and directly capable of hiding a secret-bearing file. Membership is not the control:
#: request PRESSURE is `RATELIMIT.HTTP`, which every fetch already goes through. What each lane owes is
#: an honest count of what it looked at, which `_fetched()` emits.


#: an unclassified candidate is RETAINED whatever it looks like; shape only decides WHERE it is shown.
#: review#21 (Lumpy): "classification changes placement, never retention". `LOG_LEVEL=verbose` and a
#: 40-character random string are both kept, and only one of them belongs at the top of a HOTLIST.
_SHAPE_HIGH_MIN = 16                    # shorter than this is rarely a credential on shape alone


def _shape_interest(value: str) -> str:
    """"high" | "low", from LENGTH and CHARACTER DIVERSITY only — never from the key's name.

    This makes no claim about secrecy. It is the same job `sink_observation` does with roles: the
    operator gets a short list first and the full set behind it."""
    v = (value or "").strip()
    if len(v) < _SHAPE_HIGH_MIN:
        return "low"
    if v.lower().startswith(("http://", "https://")) and "@" not in v:
        return "low"                    # a plain URL is configuration; a URL with credentials is not
    classes = sum((any(c.islower() for c in v), any(c.isupper() for c in v),
                   any(c.isdigit() for c in v), any(not c.isalnum() for c in v)))
    if classes >= 3:
        return "high"
    distinct = len(set(v))
    return "high" if distinct >= 12 and classes >= 2 else "low"


def _artifact_id(value: str) -> str:
    """A collision-RESISTANT stem for an artifact filename.

    review#22 (Lumpy) found a real collision in the old `md5(url)[:8]`: `https://t/item/46327` and
    `https://t/item/69781` both produce `af1f2617`. Two different URLs writing the same artifact path
    mixes their evidence, and — once acquisition receipts existed — let one URL's failure speak for
    another's. 8 hex is 32 bits; a few tens of thousands of URLs make a birthday collision likely, and a
    recon corpus is much larger than that. The receipt is still the authority on identity; this just
    stops the filename from being the weak link."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _discard_artifact(dest) -> None:
    """Remove a probe response we are NOT keeping — and its acquisition receipt with it.

    review#23 (Lumpy): a complete acquisition is now bound by a receipt. Deleting the artifact alone
    would leave a receipt describing a file that is gone, which the next call correctly refuses as
    `evidence-lost`. The two are one state; they are removed together."""
    dest = Path(dest)
    dest.unlink(missing_ok=True)
    dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).unlink(missing_ok=True)


def _text_of(acq, *, limit: int | None = None) -> str | None:
    """The artifact as text for an IN-PROCESS pass, or None when it is complete but too large to hold.

    None is not a failure and never means empty: `acq.path` is the whole body on disk. It means this
    process declines to materialise it as a str, which is a MEMORY decision about interpretation and
    says nothing about what was acquired (review#21, Lumpy)."""
    if acq is None or not acq.complete or acq.path is None:
        return None
    # read at CALL time, not as a default argument: a default binds `MAX_PARSE` once at import, so the
    # module constant could be changed and this would keep using the value it was born with.
    if acq.bytes > (MAX_PARSE if limit is None else limit):
        return None
    return acq.path.read_bytes().decode("utf-8", "replace")


def acquire(ctx, url: str, dest, host: str, *, source: str, **kw):
    """THE acquisition entry point for every evidence lane. Returns `(acq|None, final, status)`.

    review#26 (Lumpy): `_durability()` and the refusal/transport split were wired into
    `fetch_and_extract` only, so six lanes that call the primitive directly — graphql, openapi, the
    actuator index, deep evidence, framework probes, ssti — kept the old behaviour. A forced receipt
    failure through `probe_graphql` reported nothing at all. Per-lane reporting of a SHARED mechanism is
    six chances to miss one; this is the one place it happens, and a new lane gets it by construction.

    What every lane gets here, whatever it does with the body afterwards:

      * `complete-unowned` -> a gating `evidence_durability` record + an `unowned-artifact` row;
      * any REFUSAL (`acq.contacted is False`) -> a gating `evidence_ownership` record + a row that
        says nothing was requested, instead of a transport story about a partial that may not exist.

    Refusal is read off `contacted`, not off a list of disposition names (review#26): the result already
    carries the fact, and a list has to be updated by hand every time acquisition learns a new one —
    which would silently turn the new refusal back into "incomplete transport"."""
    acq, final, status = fetch.scoped_get_file(ctx, url, dest, host, chunk=STREAM_CHUNK,
                                               deadline_s=STREAM_DEADLINE_S, **kw)
    if acq is None:
        return acq, final, status
    if acq.disposition in ("complete-unowned", "incomplete-unowned"):
        # the OWNERSHIP failed either way. When the body was also incomplete the lane records its own
        # transport gap; this one is about not being able to prove what we hold (review#28, Lumpy).
        _durability(ctx, source, url, host, acq, dest)
    elif acq.contacted is False and not acq.complete:
        # NO CONTACT and NO USABLE EVIDENCE are different facts (review#27, Lumpy). A
        # `replayed-complete` also has `contacted=False` — and it is the verified artifact, which is
        # exactly what a crash between publication and interpretation leaves behind. Refusing it would
        # throw away the recovery this mechanism exists to provide.
        _refused(ctx, source, url, host, acq, dest)
    else:
        _ownership_ok(ctx, source, url, dest, acq)
    return acq, final, status


#: an ownership problem OPENS, is RESOLVED, and can OPEN AGAIN. review#29 (Lumpy): a mutable
#: `resolved` boolean on a merged review entity cannot express that — the store never overwrites a
#: non-empty scalar (`store._merge_record`), so once True it stayed True, and a reopened refusal still
#: rendered `[RESOLVED]`. Each transition is its own APPEND-ONLY observation instead, keyed by the path
#: it is about; the CURRENT state is the latest one, derived at read time. It lives in the STORE, not in
#: memory, so a repair in a NEW lifecycle still resolves a row an earlier one left open (finding 1).
OWNERSHIP_STATES = ("refused", "unowned", "ok")
#: its OWN log. review#34 (Lumpy): these rows lived in `review`, next to unclassified matches, source
#: maps, debug endpoints and API documents — so a single unreadable line anywhere in that file froze
#: ownership transitions globally, and the report could not say whether the dropped row had been an
#: ownership transition or a finding. It could not honestly claim other findings were unaffected either.
#: A dedicated entity makes the blast radius the thing that was actually damaged.
OWNERSHIP_ENTITY = "ownership_transition"


def _state_key(source: str, path) -> str:
    """Identifies the THING whose ownership state we track: one artifact path, per lane."""
    return secrets.fingerprint(f"{source}|{path}")


def _held_path(acq, dest):
    """WHERE the bytes this acquisition is about actually are.

    review#29/#30 (Lumpy): an incomplete acquisition holds them at `<dest>.part`, and every channel that
    points an operator at `dest` instead names a file that does not exist. One helper, so the durability
    row, the refusal row and the resolution row cannot disagree about it."""
    if acq is not None and not acq.complete and getattr(acq, "partial", None):
        return Path(acq.partial)
    return Path(getattr(acq, "path", None) or dest)


def _material(state: str, fields: dict) -> str:
    """What makes two transitions THE SAME event, as a FULL sha256 over canonical JSON.

    review#31 (Lumpy): joining fields with `|` and paths with `,` made distinct structured states
    serialize identically (`disposition="a|b", raw_ref="c"` collides with `disposition="a",
    raw_ref="b|c"`), and a truncated digest narrows it further. A typed object with separators the
    encoder escapes cannot be forged by choosing a value that contains the delimiter."""
    doc = {"state": state, "disposition": fields.get("disposition") or "",
           "raw_ref": fields.get("raw_ref") or "",
           "state_paths": [str(x) for x in (fields.get("state_paths") or [])]}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _valid_transition(r) -> bool:
    """A persisted transition we can act on. review#30 (Lumpy): these rows come off DISK, so an
    arbitrary `state`, a string `state_seq` or a missing key is input, not an invariant — `int()` on a
    corrupt sequence raised, and mixed types broke the sort before that.

    review#31: the ID must agree with the key and sequence it claims, and `state_fp` must agree with the
    row's own material fields — a row whose identity or fingerprint was rewritten is not evidence of
    the transition it describes."""
    if not (isinstance(r, dict)
            and isinstance(r.get("state_key"), str) and r["state_key"]
            and r.get("state") in OWNERSHIP_STATES
            and type(r.get("state_seq")) is int and r["state_seq"] > 0):
        return False
    if r.get("id") != f"ownership:{r['state_key']}:{r['state_seq']}":
        return False
    fp = r.get("state_fp")
    return isinstance(fp, str) and fp == _material(r["state"], r)


#: fields whose value IS the transition. review#32 (Lumpy): the store MERGES observations sharing a
#: canonical key, and two transitions with the same (key, seq) share an id — so production folded them
#: into ONE row with the conflicting value parked in `_alt`, and the duplicate detection never fired. A
#: conflict logged on any of these is the same ambiguity by another route.
_PROTECTED_TRANSITION_FIELDS = ("state", "state_seq", "state_key", "state_fp", "id")


def _has_conflict(r) -> bool:
    alt = r.get("_alt")
    return isinstance(alt, dict) and any(alt.get(f) for f in _PROTECTED_TRANSITION_FIELDS)


def _ownership_index(ctx) -> tuple:
    """`({state_key: [transition, …]}, ambiguous_keys)` — built ONCE per context, with its trust.

    review#31 (Lumpy). Three separate ways this log stops being authoritative, and all three used to
    read as "nothing ever happened":

      * the store could not read it, or dropped rows while folding it — `read()` throws that status
        away, so `read_folded()` is used here and a non-`valid` status is a gap;
      * a row does not validate (bad type, bad id, bad fingerprint);
      * a KEY holds two transitions with the same sequence. That is AMBIGUITY, not an ordering problem:
        picking a winner by id would let lexicographic order decide whether a path is refused or ok.
        Such a key has NO current state, so nothing resolves against it and nothing is claimed.

    Whatever we find, the finding is reported — including the healthy case, so a repaired log CLEARS the
    unknown rather than leaving it standing for ever (review#31 finding 1)."""
    idx = getattr(ctx, "_ownership_idx", None)
    if idx is not None:
        return (idx, getattr(ctx, "_ownership_ambiguous", set()),
                getattr(ctx, "_ownership_authoritative", True))
    idx, ambiguous, corrupt, trust = {}, set(), 0, "valid"
    folded = None
    try:
        folded = ctx.run.read_folded(OWNERSHIP_ENTITY)
        rows, status, dropped = list(folded.records.values()), folded.status, folded.dropped
    except AttributeError:                      # a store/fake without the trust-aware read
        try:
            rows, status, dropped = list(ctx.run.read(OWNERSHIP_ENTITY)), "valid", 0
        except Exception as e:
            rows, status, dropped = [], "unusable", 0
            trust = f"the ownership-transition log could not be read ({type(e).__name__})"
    except Exception as e:
        rows, status, dropped = [], "unusable", 0
        trust = f"the ownership-transition log could not be read ({type(e).__name__})"
    if folded is not None and status in ("degraded", "unusable"):
        trust = (f"the ownership-transition log folded as {status} ({dropped} row(s) dropped: "
                 f"{getattr(folded, 'reason', '') or 'unreadable'})")
    for r in rows:
        if not isinstance(r, dict) or not r.get("state_key"):
            continue                            # not a transition row at all
        if not _valid_transition(r):
            corrupt += 1
            continue
        idx.setdefault(r["state_key"], []).append(r)
        if _has_conflict(r):
            # a MERGED conflict on a transition field: two observations claimed the same identity with
            # different content, and the store kept the loser in `_alt`. Which one is current is exactly
            # what we cannot decide (review#32, Lumpy).
            ambiguous.add(r["state_key"])
    for k, v in idx.items():
        v.sort(key=lambda r: (r["state_seq"], str(r.get("id", ""))))
        if len({r["state_seq"] for r in v}) != len(v):
            ambiguous.add(k)
    # AUTHORITY IS GLOBAL. review#32 (Lumpy): a degraded fold still returned its surviving rows, and a
    # dropped row could have been a NEWER refusal for a key whose surviving `ok` then read as current.
    # When the log is not trustworthy as a whole, no key has a current state and nothing may be
    # appended — the history would be written on top of a sequence we know is incomplete.
    authoritative = (trust == "valid" and not corrupt)
    if authoritative and not ambiguous:
        events.coverage_partial("evidence.ownership", kind=events.COVERAGE_OWNERSHIP,
                                measure="ownership_state", unit="evidence.ownership.log",
                                eligible=len(idx), tested=len(idx), omitted=0,
                                reason=f"ownership transition log read cleanly ({len(idx)} path(s))")
    else:
        detail = [] if trust == "valid" else [trust]
        if corrupt:
            detail.append(f"{corrupt} ownership transition row(s) are malformed and were ignored")
        if ambiguous:
            detail.append(f"{len(ambiguous)} path(s) hold DUPLICATE sequence numbers, so their current "
                          f"state is undecidable and nothing is claimed for them")
        events.coverage_partial("evidence.ownership", kind=events.COVERAGE_UNKNOWN,
                                measure="ownership_state", unit="evidence.ownership.log",
                                reason="; ".join(detail) + " — the lifecycle of those paths is UNKNOWN, "
                                                           "not clean")
    try:
        ctx._ownership_idx, ctx._ownership_ambiguous = idx, ambiguous
        ctx._ownership_authoritative = authoritative
    except Exception:
        pass                                    # a frozen ctx simply pays the scan each time
    return idx, ambiguous, authoritative


def _ownership_log(ctx, key: str) -> list:
    """Every VALID transition for this key, oldest first."""
    idx, _amb, _auth = _ownership_index(ctx)
    return idx.get(key, [])


def _ownership_state(ctx, key: str) -> str:
    """The CURRENT state, or `unknown` when the log cannot decide it."""
    idx, ambiguous, authoritative = _ownership_index(ctx)
    if not authoritative or key in ambiguous:
        return "unknown"
    log = idx.get(key, [])
    return str(log[-1].get("state", "")) if log else ""


def _publish_state(ctx, key: str, state: str, *, klass: str, value: str, source: str, **fields) -> bool:
    """Append ONE transition. A repeat of the CURRENT state is a no-op ONLY when nothing material
    changed, so a steady stream of identical refusals does not grow the log while a changed one does."""
    if state not in OWNERSHIP_STATES:
        raise ValueError(f"unknown ownership state {state!r}")
    idx, ambiguous, authoritative = _ownership_index(ctx)
    if not authoritative or key in ambiguous:
        # READ-ONLY until repaired: appending a transition onto a sequence we know is incomplete would
        # manufacture a history. The coverage gap for this acquisition is already published either way.
        #
        # review#33 (Lumpy): the AMBIGUOUS case was writable because the no-op guard is disabled for it,
        # so an unresolvable key grew a row on every single refusal while its state stayed `unknown` —
        # a log that cannot say what the state is has no business recording new ones for that path.
        return False
    log = idx.get(key, [])
    fp = _material(state, fields)
    if log and str(log[-1].get("state", "")) == state and log[-1].get("state_fp") == fp:
        return False
    seq = max(r["state_seq"] for r in log) + 1 if log else 1
    row = {"id": f"ownership:{key}:{seq}", "klass": klass, "state_key": key, "state": state,
           "state_seq": seq, "state_fp": fp, "value": value, "sources": [source], **fields}
    ctx.run.add(OWNERSHIP_ENTITY, row)
    idx.setdefault(key, []).append(row)          # the only writer keeps its own index honest
    return True


def current_ownership_rows(run) -> tuple:
    """`(rows, authoritative)` for a REPORT: the transition that is current for each path.

    review#32 (Lumpy): triage was picking a current row through the trust-blind `run.read()` while the lane
    used the trust-aware resolver — two answers to one question. This is the single resolver, so a log
    the lane refuses to act on is not rendered as fact either. When it is not authoritative the rows are
    returned WITH that flag and the caller says so rather than showing one of them as the state."""
    ctx = SimpleNamespace(run=run)
    idx, ambiguous, authoritative = _ownership_index(ctx)
    rows = []
    for key, log in idx.items():
        if not log:
            continue
        row = dict(log[-1])
        if not authoritative or key in ambiguous:
            row["state"] = "unknown"
            row["undecidable"] = True
        rows.append(row)
    return rows, authoritative


def _ownership_ok(ctx, source: str, url: str, dest, acq) -> None:
    """The healthy counterpart of `_refused`/`_durability`, on the SAME units.

    review#27 (Lumpy): a gap was emitted when ownership withheld a URL and NOTHING when the operator
    repaired it and the fetch then succeeded. Reconciliation keeps the latest record per (source, unit),
    so with no later record the old gap stood for ever."""
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_ownership",
                            unit=f"{source}.url:{url}", eligible=1, tested=1, omitted=0,
                            reason=f"acquisition owned and readable ({acq.disposition})")
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_durability",
                            unit=f"{source}.artifact:{Path(dest).name}", eligible=1, tested=1,
                            omitted=0, reason=f"ownership receipt in place ({acq.disposition})")
    # …and the OPERATOR ROW — only when the last recorded state was a PROBLEM. A resolution for a path
    # that was never refused is a history that did not happen (review#28).
    key = _state_key(source, dest)
    if _ownership_state(ctx, key) in ("refused", "unowned"):
        held = _held_path(acq, dest)
        _publish_state(ctx, key, "ok", klass="ownership-resolved", value=str(held), source=source,
                       location=url, raw_ref=str(held), state_paths=[str(held)],
                       note=(f"RESOLVED: acquired and owned on a later attempt ({acq.disposition}). "
                             f"The earlier ownership problem no longer applies"))


def _durability(ctx, source: str, url: str, host: str, acq, dest) -> None:
    """A COMPLETE body whose OWNERSHIP could not be recorded.

    review#25 (Lumpy): `complete-unowned` lived only in a result dict that the caller discarded, so the
    run's own output said nothing at all. The evidence is readable and `ok` stays True — but the run
    cannot prove it owns it, the path is refused from here on, and that belongs in the verdict, not in
    a variable. Two channels, as everywhere else: the gating coverage record and the operator row."""
    whole = acq.disposition == "complete-unowned"
    # review#29 finding 3 (Lumpy): the bytes of an INCOMPLETE acquisition are at `acq.partial`, not at
    # `dest` — pointing an operator at a path that does not exist is the same defect as "KEPT at None".
    # The state KEY stays `dest` so the lifecycle of one artifact path is one log.
    held = _held_path(acq, dest)
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_durability",
                            unit=f"{source}.artifact:{Path(dest).name}", eligible=1, tested=0,
                            omitted=1,
                            reason=((f"acquired {'complete' if whole else 'PARTIAL'} ({acq.bytes} "
                                     f"bytes) but its OWNERSHIP RECEIPT could not be written: "
                                     f"{acq.error}. ")
                                    + (f"The artifact is readable at {held}; " if whole else
                                       f"The partial bytes are on disk at {held}; ")
                                    + "the run cannot prove it owns it and will refuse this path"))
    _publish_state(ctx, _state_key(source, dest), "unowned", klass="unowned-artifact",
                   value=str(held), source=source, host=host, location=url, raw_ref=str(held),
                   state_paths=[str(held)], bytes=acq.bytes,
                   note=(f"body fetched {'WHOLE' if whole else 'PARTIALLY'} and stored at {held}, but "
                         f"its acquisition receipt could not be written ({acq.error}). Nothing is lost "
                         f"— this path is now REFUSED rather than re-fetched, so clear the artifact if "
                         f"you want it acquired again"))


def _refused(ctx, source: str, url: str, host: str, acq, dest) -> None:
    """The acquisition state on disk withheld this URL. NOTHING was requested.

    Its own measure and its own kind: this is not the target costing us an item (`timeout`) and not a
    ceiling of ours (`cap`) — it is our own storage state, and only an operator clears it."""
    if acq.disposition == "replayed-complete":
        return                              # not a shortfall: the evidence is here and was not re-bought
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_ownership",
                            unit=f"{source}.url:{url}", eligible=1, tested=0, omitted=1,
                            reason=(f"acquisition refused by the ownership state on disk "
                                    f"({acq.disposition}); nothing was requested: {acq.error}"))
    # every file that EXISTS, not just the partial (review#27, Lumpy): `orphan-complete` is caused by
    # `dest`, and a conflict is caused by two of them at once — a row naming none of those sends the
    # operator looking for a file the note does not mention.
    # GUARDED, and with `lstat` (review#28, Lumpy): `exists()` raises on an unreadable directory —
    # re-introducing the very bug `_reconcile` fixed, because the caller's blanket `except` then counted
    # a network attempt — and it answers False for a DANGLING symlink, which is state that exists.
    d = Path(dest)

    def _present(x):
        try:
            x.lstat()
            return True
        except OSError:
            return False                       # missing, or unreadable — either way, not something to
                                               # report as present, and never something to raise about
    state = [str(x) for x in (d, d.with_name(d.name + ".part"),
                              d.with_name(d.name + fetch._RECEIPT_SUFFIX)) if _present(x)]
    _publish_state(ctx, _state_key(source, dest), "refused", klass="acquisition-refused", value=url,
                   source=source, host=host, location=url,
                   raw_ref=str(acq.partial) if acq.partial else (state[0] if state else None),
                   state_paths=state, bytes=acq.bytes, disposition=acq.disposition,
                   note=(f"acquisition REFUSED by the ownership state ({acq.disposition}): {acq.error}. "
                         + (f"The partial body is KEPT at {acq.partial}."
                            if acq.partial else "There is no partial body for this one.")
                         + (f" State on disk: {', '.join(state)}." if state else "")
                         + " Nothing was requested and nothing is retried automatically"))


def _deferred(ctx, source: str, url: str, host: str, acq, klass: str, note: str) -> None:
    """Record an artifact that was acquired WHOLE and not interpreted in process.

    Two channels on purpose: a coverage record so the run's own accounting shows the omission, and a
    review entity so the operator sees the file without reading a coverage log. Neither claims the body
    was empty, oversized-and-dropped, or failed."""
    # NOT `sample` (review#22 reasoning applied consistently): nobody CHOSE this subset, and the run
    # genuinely did not extract from that artifact. A soft limit would let the verdict certify coverage
    # the run does not have. The artifact is kept and re-runnable, which is what makes it recoverable —
    # not clean.
    events.coverage_partial(source, kind=events.COVERAGE_CAP, measure="evidence_interpretation",
                            unit=f"{source}.artifact:{acq.path.name}", eligible=1, tested=0, omitted=1,
                            reason=(f"acquired complete ({acq.bytes} bytes, sha256 {acq.sha256[:16]}) "
                                    f"and stored at {acq.path}; in-process interpretation deferred "
                                    f"above {MAX_PARSE} bytes — re-runnable from the artifact"))
    ctx.run.add("review", {
        "id": f"deferred-interpretation:{secrets.fingerprint(str(acq.path))}",
        "klass": klass, "value": str(acq.path), "host": host, "location": url,
        "raw_ref": str(acq.path), "bytes": acq.bytes, "sha256": acq.sha256,
        "note": f"{note} Nothing was discarded — run the extractors against the stored artifact; it "
                f"needs no further request to the target.",
        "sources": [source]})


def _fetched(sid: str, eligible: int, attempted: int, completed: int, what: str,
             replayed: int = 0) -> None:
    """Say what the lane actually got, in the three dispositions that differ.

    MEASURED, never intended (review#11): the first version emitted `tested=len(urls)` BEFORE the loop,
    so a run whose every candidate was out of scope still published `60/60 fetched`.

    And ATTEMPTED is not COMPLETED (review#12): a refused connection, a TLS error or a timeout happened
    after contact was made. The coverage number is the readable responses; the remainder is split into
    what we asked for and could not read, and what we never requested at all."""
    unreadable = max(0, attempted - completed)
    # review#28 (Lumpy): a REPLAY was satisfied from verified evidence without a request this
    # lifecycle. Deriving the remainder from `eligible - attempted` called that "never requested",
    # which is the opposite of what happened — the answer was already in hand.
    unrequested = max(0, eligible - attempted - replayed)
    detail = []
    if replayed:
        detail.append(f"{replayed} replayed from verified evidence (not re-requested)")
    if unreadable:
        detail.append(f"{unreadable} attempted without a readable response")
    if unrequested:
        detail.append(f"{unrequested} never requested")
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="evidence_fetches",
                            unit=f"{sid}.candidates", eligible=eligible, tested=completed,
                            omitted=max(0, eligible - completed),
                            reason=(f"{completed}/{eligible} {what} returned a readable response"
                                    + (" — " + "; ".join(detail) if detail else "")))


def mine(text: str, *, source_path: str | None = None,
         rejected: list | None = None) -> list[tuple[str, str, int]]:
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
        elif rejected is not None and val and val not in seen_vals:
            # an assignment we FOUND and did not claim. `MAILER_DSN=smtp://u:p@h` and `SESSION_SALT=…`
            # carry credentials under keys no secret-ish pattern matches.
            rejected.append(("key is not secret-shaped", key, val,
                             text.count("\n", 0, m.start()) + 1))
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
        for kind, val, where in _json_key_findings(parsed, by_format=by_format, rejected=rejected):
            if val in seen_vals or _MASKED_RX.match(val):
                continue
            seen_vals.add(val)
            # `text.find(val)` reported the FIRST occurrence: the same string under `"name"` on line 2
            # and the promoted HS256 `"key"` on line 4 sent an operator to line 2. A structural finding
            # travels with its structural position, and no line (review#23, Lumpy).
            out.append((kind, val, where))
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
    for val, at in _connstring_passwords(text, rejected):          # a password inside a connection string
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
    if rejected is not None:
        # ONE place resolves provenance: a byte offset becomes a line, an unlocatable value keeps no
        # line at all, and a value we can find in the text gets its real one.
        for i, (reason, key, val, line) in enumerate(rejected):
            if isinstance(line, _JSONPath):
                continue
            if isinstance(line, _OFFSET):
                rejected[i] = (reason, key, val, text.count("\n", 0, int(line)) + 1)
            # `line is None` stays None: a structural finding carries its JSON PATH in the reason and
            # no line. Locating the value by text search reports the FIRST occurrence, which is not
            # where the finding is (review#22, Lumpy).
    if body and path and body not in seen_vals:
        for path_rx, kind, body_rx in _FORMAT_RULES:
            if path_rx.search(path) and body_rx.match(body):
                out.append((kind, body, 1))
                break
    return out


def _provenance(line) -> dict:
    """`{"line": 4}` or `{"json_path": "auth.jwt.key"}` or `{}` — never a line we did not measure.

    review#23 (Lumpy): a structural finding walks a PARSED object and has no text offset. Publishing
    the first line that happens to contain the same string is provenance pointing at another field."""
    if isinstance(line, _JSONPath):
        return {"json_path": str(line)}
    return {"line": line} if isinstance(line, int) and not isinstance(line, bool) else {}


def publish_finding(ctx, kind: str, val: str, line, *, url: str, dest, source: str,
                    host: str | None = None, final_url: str | None = None) -> str:
    """Route ONE mined finding to the entity that describes it. Returns "secret", "hash" or "".

    One place decides what a kind IS, because five call sites deciding separately is how a password
    VERIFIER ends up in the secret queue on four of them. A hash proves the store leaked and is
    offline-crackable; it is not a recovered credential and must not be counted as one.

    The COMPLETE value is stored on the entity (`value`) AND shown in full by every LOCAL artifact —
    HOTLIST, digest, exports. Only Quarry's own configured credentials are redacted, and `secrets.mask`
    is for output that LEAVES the box (notify/messenger). An earlier version of this docstring claimed
    reports render the masked `preview`; that was the behaviour Lumpy removed on 2026-08-05 ("if you
    put caps on everything, and redact everything, I may just as well stop and go fishing"), and the
    stale wording is corrected here (review#24). Storing only a preview lost the finding itself: one
    artifact can hold many values, and "grep the raw file" is not the same as reporting the secret you
    found (review#3, Lumpy)."""
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
            **_provenance(line),
            "note": "a key in a SIGNING context (kid/issuer/audience/algorithm). Public verification "
                    "material has this shape too — not evidence of a leaked secret on its own.",
            "sources": [source]})
        return "observation" if ok else ""
    if kind in HASH_KINDS:
        ok = ctx.run.add("review", {
            "id": f"credential-hash:{secrets.fingerprint(val)}", "klass": "credential-hash",
            "value": val, "host": where, "raw_ref": str(dest) if dest else None, "location": url,
            **({"final": final_url} if final_url and final_url != url else {}),
            **_provenance(line),
            "note": f"{kind}: a password verifier, offline-crackable — NOT the password. Its presence "
                    f"proves the credential store leaked.",
            "sources": [source]})
        return "hash" if ok else ""
    ok = ctx.run.add("secret", {
        "id": f"exposed:{kind}:{secrets.fingerprint(val or f'{kind}|{url}|{line}')}",
        "kind": kind, "value": val, "preview": secrets.mask(val), "host": where,
        "file": str(dest) if dest else None, "location": url,
        **({"final": final_url} if final_url and final_url != url else {}),
        **_provenance(line), "sources": [source]})
    return "secret" if ok else ""


def publish_unclassified(ctx, rejected, *, url: str, dest, source: str, host: str | None = None,
                         final_url: str | None = None) -> int:
    """Route every DETECTOR-MATCHED, RULE-DECLINED candidate to the observation queue. Returns the count.

    review#21 (Lumpy): "classification changes placement, never retention". A match that fits no rule
    used to produce NOTHING — the bytes sat in the raw artifact and an operator found them by reading
    it. These are kept WHOLE, with the reason they were not promoted, and they make no claim: not
    `secret`, not `credential-hash`, not `signing-key`. The v0.4 skill layer can promote one later; that
    is a change of queue, not a change of what we kept.

    `interest` is SHAPE only (length + character diversity) and exists so the report shows a short list
    first. Nothing is dropped for being low-interest."""
    where = normalize.host_of_url(final_url or url) or host or normalize.host_of_url(url)
    n = 0
    for reason, key, val, line in rejected or ():
        if not val:
            continue
        if ctx.run.add("review", {
                "id": f"unclassified:{secrets.fingerprint(f'{key}|{val}')}", "klass": "unclassified",
                "value": val, "key": key, "reason": reason, "interest": _shape_interest(val),
                "host": where, "location": url, "raw_ref": str(dest) if dest else None,
                **_provenance(line),
                **({"final": final_url} if final_url and final_url != url else {}),
                "note": f"matched by a detector under `{key}` and NOT classified: {reason}. No secrecy "
                        f"or impact claim — kept complete for review/promotion.",
                "sources": [source]}):
            n += 1
    return n


def fetch_and_extract(ctx, url: str, *, source: str, subdir: str) -> dict:
    """General recon fetch→parse→extract: GET an in-scope resource (guarded, non-mutating), save the
    body as evidence, and extract secrets + in-scope links into the store IN FULL, with provenance +
    raw_ref. (This said "redacted" until review#25 — stale wording from before local artifacts stopped
    masking discovered values; only Quarry's OWN credentials are redacted, and `secrets.mask` is for
    output that leaves the box.) The reusable layer — exposed-file / config / debug fetches are instances;
    callers add their own review framing. Returns a result dict:
      {ok, off_scope, final, status, dest, bytes, sha256, secrets, links} (+ `deferred`, `partial`).
    `ok` False = not the resource we asked for (out of scope / non-200 / incomplete transport / error).
    `off_scope` = the FINAL host (after redirect) was off-scope, so nothing was read.

    ACQUISITION AND INTERPRETATION ARE SEPARATE (review#21, Lumpy). The body is streamed to disk with no
    byte ceiling and published atomically, so `dest` holds whatever arrived — including a body far past
    what this process will mine, and including the partial bytes of a broken transport. `deferred` True
    means the artifact is COMPLETE and only the in-process extraction was declined; it is re-runnable
    from the stored file without contacting the target again."""
    host = normalize.host_of_url(url)
    res = {"ok": False, "off_scope": False, "final": url, "status": None, "attempted": False,
           "error": None, "dest": None, "secrets": 0, "links": 0}
    if not ctx.scope.active_allowed(host):         # in-scope + not-passive + not-OOS
        return res
    dest = ctx.run.raw_path("params", subdir,
                            f"{host}-{_artifact_id(url)}")
    try:
        acq, final, status = acquire(ctx, url, dest, host, source=source)
    except Exception as e:
        # a refused connection, a TLS failure or a timeout happened AFTER contact was made — the body
        # just never arrived. That IS an attempt (review#12, Lumpy), and it must not be re-classified as
        # "never requested" by the receipt work below.
        res["attempted"], res["error"] = True, type(e).__name__
        return res
    # ATTEMPTED is its own fact — a refused connection, a TLS failure or a timeout happened AFTER we
    # made contact, and calling that "never looked at" describes the run wrongly (review#12, Lumpy).
    # But it is CONTACT, not a call: a REPLAYED receipt requests nothing, and setting this before the
    # fetch reported "1 attempted without a readable response" for a run that touched the network zero
    # times (review#22, Lumpy).
    res["attempted"] = bool(acq is None or acq.contacted)
    res["final"], res["status"] = final, status
    if acq is None:                                # off-scope redirect — caller records context
        res["off_scope"] = True
        return res
    res["contacted"], res["disposition"] = acq.contacted, acq.disposition
    if not acq.complete:
        # TWO different things, kept apart (review#25, Lumpy): a REFUSAL decided from the state on disk
        # (nothing was requested, and there may be no partial at all) and a transport that broke after
        # contact. Collapsing them told the operator "the partial body is KEPT at None".
        # the RESULT already carries the fact: `contacted` False means no request was made. A list of
        # disposition names would have to be updated by hand for every new one (review#26, Lumpy).
        res["error"] = "incomplete" if acq.contacted else "refused"
        res["partial"] = str(acq.partial) if acq.partial else None
        res["bytes"], res["reason"] = acq.bytes, acq.error
        return res
    res["dest"], res["bytes"], res["sha256"] = str(dest), acq.bytes, acq.sha256
    res["disposition"] = acq.disposition
    if acq.error:
        # a COMPLETE body whose ownership could not be recorded. The evidence is whole — saying
        # otherwise would be a lie about it — but the next call refuses the path, so say why here.
        res["reason"] = acq.error
    if status != 200:
        # the body is KEPT — a 401/403/500 body is evidence of what is there — but a non-200 is not the
        # resource we asked for, so it is not mined as one. `ok` stays False exactly as before.
        return res
    res["ok"] = True
    if acq.bytes > MAX_PARSE:
        # ACQUIRED COMPLETE, INTERPRETATION DEFERRED. The artifact is whole on disk; only the in-process
        # pass is declined, because it would hold the entire body as text. A later worker reads the
        # artifact — zero further requests to the target.
        res["deferred"] = True
        # NOT `sample` (review#22 reasoning, applied consistently): nobody CHOSE this subset, and the
        # run genuinely did not extract from that artifact. A soft limit would let the verdict certify
        # coverage the run does not have. Keeping the artifact makes it RECOVERABLE, not clean.
        events.coverage_partial(source, kind=events.COVERAGE_CAP, measure="evidence_interpretation",
                                unit=f"{source}.artifact:{dest.name}", eligible=1, tested=0, omitted=1,
                                reason=(f"acquired complete ({acq.bytes} bytes, sha256 {acq.sha256[:16]}) "
                                        f"and stored at {dest}; in-process mining deferred above "
                                        f"{MAX_PARSE} bytes — re-runnable from the artifact"))
        ctx.run.add("review", {
            "id": f"deferred-interpretation:{secrets.fingerprint(str(dest))}",
            "klass": "deferred-interpretation", "value": str(dest), "host": host, "location": url,
            "raw_ref": str(dest), "bytes": acq.bytes, "sha256": acq.sha256,
            **({"final": final} if final and final != url else {}),
            "note": f"body fetched WHOLE ({acq.bytes} bytes) and kept; too large to mine in process. "
                    f"Nothing was discarded — run the extractors against the stored artifact.",
            "sources": [source]})
        return res
    text = dest.read_bytes().decode("utf-8", "replace")
    # CLASSIFY BY WHAT ANSWERED. the fetch follows redirects per hop, so a request for
    # `/config/master.key` can be answered by `/checksums.txt` — and a format rule keyed on the
    # REQUESTED path would call that body a Rails master key (review#2, Lumpy). Provenance keeps both:
    # `location` is what we asked for, `final` is what replied.
    final_url = res["final"] or url
    rejected: list = []
    for kind, val, ln in mine(text, source_path=final_url, rejected=rejected):
        got = publish_finding(ctx, kind, val, ln, url=url, dest=dest, source=source, host=host,
                              final_url=final_url)
        if got == "secret":
            res["secrets"] += 1
        elif got == "hash":
            res["hashes"] = res.get("hashes", 0) + 1
    res["unclassified"] = publish_unclassified(ctx, rejected, url=url, dest=dest, source=source,
                                               host=host, final_url=final_url)
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
    added = eligible = attempted = completed = refused_n = replayed_n = 0
    for u in urls:
        if not ctx.scope.active_allowed(normalize.host_of_url(u)):
            continue                               # not ours to request: never part of the denominator
        eligible += 1
        r = fetch_and_extract(ctx, u, source="exposed-fetch", subdir="exposed")
        attempted += 1 if r["attempted"] else 0    # contact was made
        # review#22 (Lumpy): a STATUS is not a readable response. An interrupted 200 counted as
        # completed (`1/1 returned a readable response`) and then vanished, because the review record
        # below is gated on `ok`. Completion means the body arrived whole.
        completed += 1 if (r["ok"] or r["off_scope"]) else 0
        replayed_n += 1 if r.get("disposition") == "replayed-complete" else 0
        if r["off_scope"]:                         # off-scope redirect — record, no extraction
            ctx.run.add("review", {
                "id": f"exposed-redirect:{u}", "klass": "exposure", "value": u,
                "host": normalize.host_of_url(u), "location": r["final"],
                "note": f"redirected off-scope to {r['final']} (status {r['status']}); body NOT extracted",
                "sources": ["exposed-fetch"]})
            continue
        if r.get("error") == "refused":
            # `acquire()` already published the ownership coverage record AND the operator row for this
            # one — a second row here would say the same thing twice in different words. What this lane
            # owes is to keep the candidate OUT of its own denominator: a refusal is not a resource we
            # requested and failed to read (review#26, Lumpy).
            refused_n += 1
            continue
        if r.get("error") == "incomplete":
            # a transport that broke AFTER contact: what arrived is on disk, and it belongs in this
            # lane's own accounting because we did request it.
            ctx.run.add("review", {
                "id": f"exposed-incomplete:{u}", "klass": "exposure", "value": u,
                "host": normalize.host_of_url(u), "raw_ref": r.get("partial"),
                "location": r["final"], "bytes": r.get("bytes", 0),
                "note": (f"INCOMPLETE acquisition after {r.get('bytes', 0)} byte(s) (status "
                         f"{r['status']}): {r.get('reason')} — the partial body is KEPT at "
                         f"{r.get('partial')}; not retried automatically"),
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
    # DISJOINT buckets (review#26, Lumpy): an ownership refusal was landing in BOTH this record and the
    # ownership one, so a single orphan artifact was counted twice under contradictory causes. This
    # record is about resources we asked a target for; `acquire()` owns the ones we never asked for.
    # `attempted` is NOT reduced: a refusal never incremented it in the first place, and subtracting it
    # again produced `eligible=0, tested=0, omitted=0` with the reason "1 never requested" (review#27).
    _fetched("evidence.exposed", eligible - refused_n, attempted, completed,
             "in-scope exposed resource(s)", replayed=replayed_n)
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
        dest = ctx.run.raw_path("params", "graphql", f"{host}-{_artifact_id(u)}.json")
        try:
            acq, final, status = acquire(
                ctx, u, dest, host, source="graphql-introspect", method="POST",
                data=_GQL_INTROSPECTION.encode(), policy="graphql-introspection",
                headers={"Content-Type": "application/json", "Accept": "application/json"})
        except Exception:
            continue
        if acq is None:                            # off-scope redirect — record, don't read schema
            ctx.run.add("review", {
                "id": f"graphql-redirect:{u}", "klass": "graphql", "value": u, "host": host,
                "location": final,
                "note": f"redirected off-scope to {final} (status {status}); not introspected",
                "sources": ["graphql-introspect"]})
            continue
        if not acq.contacted and not acq.complete:
            continue                               # refused by the ownership state; `acquire` said so
        if not acq.complete:
            ctx.run.add("review", {
                "id": f"graphql:{u}", "klass": "graphql", "value": u, "host": host,
                "note": f"introspection response INCOMPLETE after {acq.bytes} byte(s) ({acq.error}); "
                        f"the partial body is kept at {acq.partial} — not retried automatically",
                "sources": ["graphql-introspect"]})
            continue
        text = _text_of(acq)
        if text is None:
            # a schema too large to hold as text is still a schema, and it is on disk.
            _deferred(ctx, "graphql-introspect", u, host, acq, "graphql",
                      "introspection response fetched WHOLE and kept; too large to parse in process.")
            continue
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            obj = None
        introspectable = bool(isinstance(obj, dict)
                              and isinstance(obj.get("data"), dict)
                              and obj["data"].get("__schema"))
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
#: was `_DEEP_MAX_BODY = 64 MiB`, which REFUSED TO SAVE a heap dump over the cap — the single most
#: secret-dense artifact recon can obtain, already fetched, then thrown away with a note suggesting the
#: operator raise a number and pay for the request again. Acquisition is unbounded in bytes now; a heap
#: dump is mined by SCANNING the file rather than holding it as text (review#21, Lumpy).
_DEEP_SCAN_WINDOW = 8 * 1024 * 1024        # bytes held in RAM per mining window
_DEEP_SCAN_OVERLAP = 64 * 1024             # carried between windows so a secret on a boundary survives


def _actuator_index_links(ctx, base: str, host: str) -> set[str]:
    """GET the actuator index (cheap) and return the set of endpoint names it advertises in
    `_links`. This is how we learn heavy endpoints are exposed WITHOUT requesting them."""
    dest = ctx.run.raw_path("params", "actuator",
                            f"{host}-index-{_artifact_id(base)}.json")
    try:
        acq, _final, status = acquire(ctx, base, dest, host, source="actuator-probe")
    except Exception:
        return set()
    if acq is None:
        return set()
    if not acq.contacted and not acq.complete:
        return set()                               # refused by the ownership state; `acquire` said so
    if not acq.complete:
        events.coverage_partial("actuator-probe", kind=events.COVERAGE_TIMEOUT,
                                measure="actuator_index", unit=f"actuator-probe.base:{base}",
                                eligible=1, tested=0, omitted=1,
                                reason=(f"actuator index INCOMPLETE after {acq.bytes} byte(s) "
                                        f"({acq.disposition}: {acq.error}) — advertised endpoints "
                                        f"unread, so HEAVY exposures may be under-reported"))
        ctx.run.add("review", {
            "id": f"actuator-index-incomplete:{base}", "klass": "actuator", "value": base,
            "host": host, "raw_ref": str(acq.partial) if acq.partial else None, "bytes": acq.bytes,
            "note": (f"actuator index INCOMPLETE after {acq.bytes} byte(s) ({acq.error}) — advertised "
                     f"endpoints could NOT be read, so heavy exposures may be under-reported here. "
                     f"Partial body kept; not retried automatically"),
            "sources": ["actuator-probe"]})
        return set()
    if status != 200:
        return set()
    text = _text_of(acq)
    if text is None:
        # the index decides which HEAVY endpoints we know are exposed. Losing it silently would under-
        # report the exposure, so it is recorded rather than swallowed.
        if acq.complete:
            _deferred(ctx, "actuator-probe", base, host, acq, "actuator",
                      "actuator index fetched WHOLE and kept; too large to parse in process.")
        return set()
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    links = obj.get("_links") if isinstance(obj, dict) else None
    return set(links.keys()) if isinstance(links, dict) else set()


def _deep_download(ctx, url: str, host: str, kind: str) -> bool:
    """Deep-evidence (opt-in): download a heavy artifact (bounded), save the raw bytes, and mine it
    for secrets (ASCII secrets survive inside a binary heap dump). Adds its own high-priority review.
    Returns True on a recorded download, False on failure (caller falls back to detect-only)."""
    dest = ctx.run.raw_path("params", "actuator",
                            f"{host}-{kind}-{_artifact_id(url)}.bin")
    try:
        acq, _final, status = acquire(ctx, url, dest, host, source="deep-evidence")
    except Exception:
        return False
    if acq is None or status != 200:
        return False                               # off-scope/absent → caller does detect-only fallback
    if not acq.contacted and not acq.complete:
        return False                               # refused by the ownership state; `acquire` said so
    if not acq.complete:
        # the transport broke mid-dump. What arrived is on disk and is mined — a partial heap dump is
        # still full of credentials — and the gap is stated rather than the whole thing discarded.
        part = acq.partial
        nsec = _mine_file(ctx, part, url, host, "deep-evidence") if part else 0
        ctx.run.add("review", {
            "id": f"actuator-heavy:{url}", "klass": "actuator", "value": url, "host": host,
            "priority": "high", "raw_ref": str(part) if part else None,
            "note": (f"{kind} download INCOMPLETE after {acq.bytes} byte(s) ({acq.error}) — the partial "
                     f"artifact is KEPT and was mined ({nsec} secret(s)); not retried automatically"),
            "sources": ["deep-evidence"]})
        return True
    nsec = _mine_file(ctx, acq.path, url, host, "deep-evidence")
    ctx.run.add("review", {
        "id": f"actuator-heavy:{url}", "klass": "actuator", "value": url, "host": host,
        "priority": "high", "raw_ref": str(dest),
        "note": f"{kind} DOWNLOADED via deep-evidence ({acq.bytes // 1024} KB) — {nsec} secret(s) mined",
        "sources": ["deep-evidence"]})
    return True


def _mine_file(ctx, path, url: str, host: str, source: str) -> int:
    """Mine a file of ANY size by scanning it in overlapping windows. Returns secrets published.

    A heap dump is the case this exists for: gigabytes of binary with ASCII credentials in it. Holding
    it as one str is the only thing that was ever bounded, so the bound moved to the WINDOW — memory is
    `_DEEP_SCAN_WINDOW`, evidence is the whole file. The overlap carries `_DEEP_SCAN_OVERLAP` bytes into
    the next window so a token lying across a boundary is not cut in half and lost.

    `_DEEP_SCAN_OVERLAP` bounds the LONGEST VALUE that can survive a boundary: a token longer than the
    overlap is cut by every window that touches it and matches nowhere. It is set well above any pattern
    here (a PEM block is matched by its header, not its length) and the two must be tuned together.

    Line numbers are per-window and therefore approximate on a multi-window file; the raw artifact and
    the value itself are the evidence, and a line number is provenance, not the finding."""
    n = 0
    seen: set[str] = set()
    seen_unc: set[str] = set()
    try:
        with open(path, "rb") as fh:
            carry = b""
            while True:
                buf = fh.read(_DEEP_SCAN_WINDOW)
                if not buf:
                    break
                window = carry + buf
                rejected: list = []
                for k, val, ln in mine(window.decode("utf-8", "replace"), source_path=url,
                                       rejected=rejected):
                    if val in seen:                # the overlap re-reads bytes on purpose; don't re-publish
                        continue
                    seen.add(val)
                    if publish_finding(ctx, k, val, ln, url=url, dest=path, source=source,
                                       host=host) == "secret":
                        n += 1
                # a SEPARATE set: sharing `seen` with the classified values would let a value first
                # seen as unclassified suppress the same value later PROMOTED by a rule elsewhere in the
                # file — an observation silently eating a secret.
                fresh = [r for r in rejected if r[2] not in seen_unc]
                publish_unclassified(ctx, fresh, url=url, dest=path, source=source, host=host)
                seen_unc.update(r[2] for r in fresh)
                carry = window[-_DEEP_SCAN_OVERLAP:] if len(window) > _DEEP_SCAN_OVERLAP else window
    except OSError:
        return n
    return n


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
            dest = ctx.run.raw_path("params", "actuator",
                                    f"{host}-{sp}-{_artifact_id(u)}")
            try:
                acq, _final, status = acquire(ctx, u, dest, host, source="actuator-probe")
            except Exception:
                continue
            if acq is None or (not acq.contacted and not acq.complete):
                continue                               # off-scope, or refused by the ownership state
            if status != 200:
                continue                               # locked -> not exposed
            # SIZE NO LONGER DECIDES EXPOSURE. A 200 from /actuator/env is the exposure; the old code
            # made a large body read as "not exposed", which is the finding disappearing, not a guard.
            exposed.append(sp)
            if sp in _ACTUATOR_MINE:                   # env/configprops can leak creds -> extract
                if acq.complete:
                    _mine_file(ctx, acq.path, u, host, "actuator-probe")
                elif acq.partial:
                    _mine_file(ctx, acq.partial, u, host, "actuator-probe")
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


#: was `_OPENAPI_MAX_BODY = 5 MiB`, above which a spec was fetched and then dropped — losing every
#: endpoint and parameter it declared. Specs get big precisely when they describe a lot of API.
#: `MAX_PARSE` bounds holding one as text; the document itself is always stored.
#: DELETED (review#22, Lumpy). `_OPENAPI_MAX_PATHS = 2000` kept the first 2000 paths of a parsed
#: document and dropped the rest — silently, unrecorded, and not resumable. It was registered as a
#: memory guard, which it never was: the WHOLE document is already parsed into memory before this line
#: is reached, so the cap saved nothing and cost the endpoints a big API declares. Reading every entry
#: of a dict we are already holding is not the expensive part of anything.


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
        dest = ctx.run.raw_path("params", "openapi",
                                f"{host}-{_artifact_id(u)}.json")
        try:
            acq, final, status = acquire(ctx, u, dest, host, source="openapi")
        except Exception:
            continue
        if acq is None:                            # off-scope redirect — record, don't parse
            ctx.run.add("review", {
                "id": f"openapi-redirect:{u}", "klass": "api-doc", "value": u, "host": host,
                "location": final,
                "note": f"redirected off-scope to {final} (status {status}); not parsed",
                "sources": ["openapi"]})
            continue
        if not acq.contacted and not acq.complete:
            continue                               # refused by the ownership state; `acquire` said so
        if not acq.complete:
            # review#22 (Lumpy): a review row is operator-facing and does NOT make the run incomplete,
            # so the verdict could still certify coverage over a truncated document. The coverage record
            # is the authoritative half; the row is the readable one. TIMEOUT kind = the target/network
            # cost us input, which GATES (sample/provider are the only soft kinds).
            events.coverage_partial("openapi", kind=events.COVERAGE_TIMEOUT, measure="api_documents",
                                    unit=f"openapi.doc:{u}", eligible=1, tested=0, omitted=1,
                                    reason=(f"API document INCOMPLETE after {acq.bytes} byte(s) "
                                            f"({acq.disposition}: {acq.error}) — not parsed; every "
                                            f"endpoint and parameter it declares is unread"))
            ctx.run.add("review", {
                "id": f"openapi-incomplete:{u}", "klass": "api-doc", "value": u, "host": host,
                "raw_ref": str(acq.partial) if acq.partial else None, "bytes": acq.bytes,
                "note": (f"API document INCOMPLETE after {acq.bytes} byte(s) ({acq.error}) — the "
                         f"partial body is KEPT and NOT parsed; a truncated spec is a different spec, "
                         f"not a smaller one. Not retried automatically"),
                "sources": ["openapi"]})
            continue
        if status != 200:
            continue
        text = _text_of(acq)
        if text is None:
            _deferred(ctx, "openapi", u, host, acq, "api-doc",
                      "API document fetched WHOLE and kept; too large to parse in process.")
            continue
        doc = _openapi_load(text)
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            continue
        bases = [b.rstrip("/") + "/" for b in _openapi_bases(doc, u)]
        n_ep = n_pa = 0
        for path, ops in doc["paths"].items():
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
        dest = ctx.run.raw_path("params", "framework",
                                f"{host}-{_artifact_id(u)}")
        try:
            acq, final, status = acquire(ctx, u, dest, host, source="framework-probe")
        except Exception:
            continue
        if acq is None:                                # off-scope redirect — don't read
            continue
        if not acq.contacted and not acq.complete:
            continue                                   # refused by the ownership state; `acquire` said so
        if status == 200:
            # a 200 IS the exposure regardless of body size (the old `<= MAX_BODY` made a big debug
            # dashboard read as not-exposed). Mining scans the file, so it costs one window of RAM.
            src = acq.path if acq.complete else acq.partial
            nsec = _mine_file(ctx, src, u, host, "framework-probe") if src else 0
            exposed_n += 1
            ctx.run.add("review", {
                "id": f"debug:{u}", "klass": "debug", "value": u, "host": host, "priority": "high",
                "framework": c.get("framework"), "raw_ref": str(src) if src else None,
                "note": f"EXPOSED (200): {c.get('note') or 'framework debug/admin endpoint'}"
                        + (f" — {nsec} secret(s) mined" if nsec else "")
                        + ("" if acq.complete else f" — body INCOMPLETE after {acq.bytes} byte(s) "
                                                   f"({acq.error}); partial kept"),
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


def _ssti_hit(path) -> bool | None:
    """Did the template ENGINE evaluate the probe? True/False, or None when the body cannot be read.

    Scanned in overlapping windows so a response of any size is classified with one window of RAM. Both
    markers matter and they are independent: the computed value must appear AND the literal expression
    must not, so the whole file is walked before answering. None is NOT False — an unclassifiable
    response is a gap the caller records, never a quiet "safe"."""
    if path is None:
        return None
    expect = literal = False
    try:
        with open(path, "rb") as fh:
            carry = ""
            while True:
                buf = fh.read(_DEEP_SCAN_WINDOW)
                if not buf:
                    break
                window = carry + buf.decode("utf-8", "replace")
                expect = expect or (_SSTI_EXPECT in window)
                literal = literal or (_SSTI_LITERAL in window)
                if literal:
                    return False                   # the expression came back unevaluated — settled
                carry = window[-64:]               # both markers are < 16 chars; 64 is ample overlap
    except OSError:
        return None
    return expect and not literal


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
        # MEASURED, not intended (review#22, Lumpy). The record used to be emitted BEFORE the loop with
        # `tested=_SSTI_MAX_PARAMS`, so a URL whose every probe failed before contact still published
        # "10 tested" — and an early `break` on a confirmation made it wrong the other way. Coverage is
        # emitted AFTER the loop from what actually happened, and the remainder names every parameter
        # nobody classified: cap-skipped, error-skipped, unclassifiable, and left over after a break.
        # keyed by OCCURRENCE, not by name (review#23, Lumpy): `?a=1&a=2` is two parameters that happen
        # to share a name, and a name-keyed map raised KeyError on the second one. The index is what
        # makes them distinct, and it is what an operator needs to say WHICH `a` was probed.
        # Each BUCKET is a disjoint subset of the parameter occurrences with its own coverage kind and
        # its own unit, so every record's (eligible, tested, omitted) reconciles on its own and the
        # buckets sum to the whole query string. One flat record could not: a hard per-URL ceiling and a
        # request that failed are different facts with different eligible sets (review#23, Lumpy).
        BEYOND, STOPPED, PROBED = "policy-cap", "policy-stop", "unreachable"
        _BUCKET_KIND = {BEYOND: events.COVERAGE_CAP, STOPPED: events.COVERAGE_CAP,
                        PROBED: events.COVERAGE_TIMEOUT}
        resolved: set[tuple[int, str]] = set()
        unresolved: dict[tuple[int, str], tuple[str, str]] = {}
        for i, (k, _v) in enumerate(qs):
            unresolved[(i, k)] = (PROBED, "never probed") if i < _SSTI_MAX_PARAMS else \
                (BEYOND, f"beyond SSTI_MAX_PARAMS={_SSTI_MAX_PARAMS} probes per URL")
        for i, (k, _v) in enumerate(qs[:_SSTI_MAX_PARAMS]):
            newq = list(qs)
            newq[i] = (k, _SSTI_PROBE)
            tu = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(newq), ""))
            # a CLASSIFICATION probe, not evidence collection: the response only matters if the engine
            # evaluated the expression. It still streams, because an over-cap body used to read as "no
            # hit" — a silent false negative that looked identical to a safe parameter (review#21).
            dest = ctx.run.raw_path("params", "ssti",
                                    f"{host}-{_artifact_id(tu)}.http")
            try:
                acq, _final, status = acquire(ctx, tu, dest, host, source="ssti-probe")
            except Exception as e:
                unresolved[(i, k)] = (PROBED, f"request failed ({type(e).__name__})")
                continue
            if acq is None:
                unresolved[(i, k)] = (PROBED, "not contacted (off-scope redirect or scan-box guard)")
                _discard_artifact(dest)
                continue
            if not acq.contacted and not acq.complete:
                unresolved[(i, k)] = (PROBED, f"refused before contact ({acq.disposition})")
                continue
            if status != 200:
                # a non-200 is an ANSWER: this parameter did not render the probe. RESOLVED, not a gap.
                unresolved.pop((i, k), None)
                resolved.add((i, k))
                _discard_artifact(dest)
                continue
            # review#22 (Lumpy): classifying a `.part` is a FALSE POSITIVE generator — the computed
            # value can be in the prefix that arrived while the unevaluated literal, which would have
            # settled it as "reflected only", is in the suffix that never did. An incomplete response
            # answers nothing.
            hit = _ssti_hit(acq.path) if acq.complete else None
            if hit is None:
                unresolved[(i, k)] = (PROBED, f"response could not be classified ({acq.disposition}, {acq.bytes} bytes); "
                                       f"body kept at {acq.path or acq.partial}")
                continue
            unresolved.pop((i, k), None)
            resolved.add((i, k))
            if not hit:
                _discard_artifact(dest)                # a non-hit probe response is not evidence
                continue
            # the body that contained the computed value stays as evidence, so the candidate is
            # auditable / manually validatable — same pattern as the exposed/actuator/openapi probes.
            ctx.run.add("finding", {
                "id": f"ssti:{tu[:80]}", "template": "ssti-candidate",
                "name": (f"SSTI primitive confirmed — template expr evaluated to {_SSTI_EXPECT} "
                         f"on param '{k}' (manual validation required)"),
                "severity": "high", "matched": tu, "raw_ref": str(dest),
                "sources": ["ssti-probe"], "confirmed": False})
            found += 1
            # one confirmation per URL is enough — the parameters after it stay in the remainder,
            # named, rather than being quietly counted as tested.
            for j, (rest, _rv) in enumerate(qs[i + 1:], start=i + 1):
                if (j, rest) in unresolved:
                    unresolved[(j, rest)] = (STOPPED, "a confirmation on an earlier parameter "
                                                      "ended this URL")
            break
        for bucket in (BEYOND, STOPPED, PROBED):
            members = {occ: why for occ, (b, why) in unresolved.items() if b == bucket}
            # the PROBED bucket also owns everything that got an answer; the other two own only what
            # they held back, so their eligible IS their omitted.
            got = len(resolved) if bucket == PROBED else 0
            if not members and not got:
                continue
            events.coverage_partial("ssti-probe", kind=_BUCKET_KIND[bucket], measure="ssti_params",
                                    unit=f"ssti-probe.url:{u}#{bucket}", eligible=got + len(members),
                                    tested=got, omitted=len(members),
                                    reason=(f"{bucket}: "
                                            + ("; ".join(f"{n}[{i}] ({why})"
                                                         for (i, n), why in sorted(members.items()))
                                               or "none")))
    return found
