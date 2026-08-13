"""Recon-layer evidence extraction: fetch exposed, in-scope, unauthenticated, non-mutating resources
and mine secrets from them. By default recon performs no impact; the one deliberate exception is
deep-evidence mode (opt-in), which downloads heavy artifacts such as heap dumps. See
docs/design/EVIDENCE-EXTRACTION-DESIGN.md for the boundary, secret classification, and ownership.
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

#: encrypted credential stores: fetched and reported as an exposed store, not mined.
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

#: a connection-string password needs an anchor field beside it. The scan expands a bounded window
#: around each `=`. See docs/design/EVIDENCE-EXTRACTION-DESIGN.md.
_CONNSTR_EQ_RX = re.compile(r"=")
_CONNSTR_BREAK = frozenset('"\'\r\n')
_CONNSTR_SPAN = 400
_CONNSTR_ANCHOR = re.compile(r"(?i)\A\s*(?:data\s+source|server|host|initial\s+catalog|database|dsn|"
                             r"user\s*id|uid|integrated\s+security|provider)\s*\Z")
_CONNSTR_PASSWORD = re.compile(r"(?i)\A\s*(?:password|pwd)\s*\Z")


class _JSONPath(str):
    """Structural provenance: where in the document a finding lives (`auth.jwt.key`). A `str` subclass so it
    rides in `mine()`'s line slot and is told apart at publication."""


def _json_path(trail, key) -> _JSONPath:
    return _JSONPath(".".join([*(str(t) for t in (trail or ())), str(key)]))


class _OFFSET(int):
    """A byte offset into the body, not a line number; `mine()` resolves it before publication."""


def _connstring_passwords(text: str, rejected=None):
    """(password, offset) for every connection-string value — a `password` field beside an anchor
    (`Server`, `Data Source`, `User ID`…). See docs/design/EVIDENCE-EXTRACTION-DESIGN.md.
    """
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
                # a `password=` with no anchor beside it: kept as an observation, not claimed
                for k, v in fields:
                    if _CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                        rejected.append(("password= without connection-string structure", k.strip(),
                                         v.strip(), _OFFSET(lo)))
            continue
        for k, v in fields:
            if _CONNSTR_PASSWORD.match(k) and len(v.strip()) >= 4:
                yield v.strip(), lo

#: kinds published as `credential-hash` rather than `secret`.
HASH_KINDS = frozenset({"bcrypt-hash"})
#: kinds routed to the observation queue rather than `secret`.
OBSERVATION_KINDS = frozenset({"signing-key"})
#: a symmetric algorithm, which promotes a bare key to `secret` (signing key = verifying key).
_SYMMETRIC_ALG_RX = re.compile(r'"(?:alg|algorithm)"\s*:\s*"(?:HS(?:256|384|512)|A\d{3}(?:GCM)?KW|'
                               r'dir|symmetric)"', re.I)
_HASH_RX = [
    ("bcrypt-hash", re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}")),
]

#: format rules: (path pattern, kind, body pattern), gated on the source path.
_FORMAT_RULES = [
    (re.compile(r"(?:^|/)master\.key$", re.I), "rails-master-key", re.compile(r"\A[0-9a-f]{32}\Z")),
]

# dotenv assignment: a secret-looking value on a secret-looking key. Three value shapes — single-
# quoted, double-quoted, and bare (inline comment stripped).
_DOTENV_RX = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[=:]\s*(?:
      '([^'\r\n]{4,})'                      # 'single quoted, # and " allowed'
    | "([^"\r\n]{4,})"                      # "double quoted"
    | ([^'"\r\n]{6,}?)                      # bare, inline comment stripped below
    )\s*$""", re.VERBOSE)
_INLINE_COMMENT_RX = re.compile(r"\s+#.*$")
_SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|pass|pwd|api|auth|cred|private|access)")

# JSON config on a secret-looking key: `"x.password": "val"` and the actuator wrap
# `"x.password": {"value": "val"}`.
_JSON_SECRET_RX = re.compile(
    r'"([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|signing[_-]?key|api[_-]?key|apikey|'
    r'access[_-]?key|private[_-]?key|token|credential)[A-Za-z0-9_.\-]*)"'
    r'\s*:\s*(?:\{\s*"value"\s*:\s*)?"([^"]{4,})"', re.I)
#: a bare `"Key"`, promoted only under a signing-key file format or a signing parent.
_JSON_BARE_KEY_RX = re.compile(r'"(key)"\s*:\s*"([^"]{20,})"', re.I)
_JSON_BARE_KEY_PATHS = re.compile(r"(?:^|/)(?:appsettings(?:\.[\w-]+)?\.json|web\.config)$", re.I)
#: a bare `"key"` promoted when its parent names JWT/signing or the object carries a signing field.
_JSON_SIGNING_CONTEXT_RX = re.compile(
    r'"[A-Za-z0-9_.\-]*(?:jwt|jws|signing|signature)[A-Za-z0-9_.\-]*"\s*:\s*\{[^{}]{0,300}?'
    r'"(key)"\s*:\s*"([^"]{20,})"', re.I)
#: structural scan where the body parses: the object a key lives in decides, not text proximity. The
#: regexes below are the fallback for bodies that do not parse, where they stay observations only.
_SIGNING_FIELDS = {"alg", "algorithm", "iss", "issuer", "aud", "audience", "kid",
                   "expiry", "expires_in", "lifetime"}
_SYMMETRIC_ALGS = re.compile(r"\A(?:HS(?:256|384|512)|A\d{3}(?:GCM)?KW|dir|symmetric)\Z", re.I)
_SIGNING_PARENT = re.compile(r"(?:jwt|jws|signing|signature)", re.I)


def _json_key_findings(doc, *, trail=(), by_format: bool = False, rejected=None):
    """Walk a parsed document and classify every bare `key` by the object it lives in. Yields (kind, value,
    json_path): symmetric algorithm or a signing parent in a signing-key format is a secret, other signing
    context is an observation. See docs/design/EVIDENCE-EXTRACTION-DESIGN.md."""
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
    # the nearest named ancestor, so `{"Jwt": [{"key": …}]}` counts as signing config
    _named = next((t for t in reversed(trail) if not str(t).startswith("[")), "")
    signing_parent = bool(_SIGNING_PARENT.search(str(_named)))
    for k, v in doc.items():
        if str(k).lower() == "key" and isinstance(v, str) and len(v) >= 20:
            here = _json_path(trail, k)
            if symmetric:
                yield f"json:{k}", v, here
            elif by_format and (signing_parent or companions):
                # signing-key format and a signing object: both, since the format alone also holds
                # cache keys and public ids
                yield f"json:{k}", v, here
            elif signing_parent or companions:
                yield "signing-key", v, here
            elif rejected is not None:
                # a 20+ char `key` with no signing context: kept as an observation at its structural
                # path, no line
                rejected.append((f"bare `key` field with no signing or symmetric context "
                                 f"[at {here}]", str(k), v, here))
    for k, v in doc.items():
        if isinstance(v, (dict, list)):
            yield from _json_key_findings(v, trail=(*trail, str(k)), by_format=by_format,
                                          rejected=rejected)


#: the same object naming how the key is used. Two patterns rather than one alternation, because every
#: rule must yield (key, value) as groups 1 and 2 and an alternation renumbers them.
_SIGNING_COMPANION = (r"alg|algorithm|iss|issuer|aud|audience|kid|expiry|expires_in|lifetime")
_JSON_SIGNING_COMPANION_AFTER_RX = re.compile(
    r'\{[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"', re.I)
_JSON_SIGNING_COMPANION_BEFORE_RX = re.compile(
    r'\{[^{}]{0,300}?"(?:' + _SIGNING_COMPANION + r')"[^{}]{0,300}?"(key)"\s*:\s*"([^"]{20,})"', re.I)
_MASKED_RX = re.compile(r"^[*•]+$")             # actuator sanitizes sensitive values to ******

#: maximum in-process parse size; larger complete artifacts are deferred.
MAX_PARSE = 64 * 1024 * 1024
#: one chunk in RAM while streaming, and the wall-clock bound on a socket that never reaches EOF.
STREAM_CHUNK = 1024 * 1024
STREAM_DEADLINE_S = 300.0
#: membership is not the control — request pressure is `RATELIMIT.HTTP`. Each lane owes an honest
#: count of what it looked at.


#: shape controls display order only; every candidate is retained.
_SHAPE_HIGH_MIN = 16                    # shorter than this is rarely a credential on shape alone


def _shape_interest(value: str) -> str:
    """"high" | "low", from length and character diversity only, never the key's name. No secrecy claim: it
    only decides what the report shows first."""
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
    """A collision-resistant stem for an artifact filename."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _discard_artifact(dest) -> None:
    """Remove a probe response we are not keeping, and its acquisition receipt with it."""
    dest = Path(dest)
    dest.unlink(missing_ok=True)
    dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).unlink(missing_ok=True)


def _text_of(acq, *, limit: int | None = None) -> str | None:
    """The artifact as text for an in-process pass, or None when it is complete but too large to hold. None
    is a memory decision about interpretation, never empty and never a failure — `acq.path` is the whole
    body on disk."""
    if acq is None or not acq.complete or acq.path is None:
        return None
    # read at call time, not as a default argument: a default binds `MAX_PARSE` once at import, so the
    # module constant could be changed and this would keep using the value it was born with.
    if acq.bytes > (MAX_PARSE if limit is None else limit):
        return None
    return acq.path.read_bytes().decode("utf-8", "replace")


def acquire(ctx, url: str, dest, host: str, *, source: str, **kw):
    """The acquisition entry point for every evidence lane, so shared ownership reporting cannot be missed:
    returns `(acq|None, final, status)` and emits `evidence_durability` on a complete-but-unowned
    acquisition, `evidence_ownership` on a refusal.
    """
    acq, final, status = fetch.scoped_get_file(ctx, url, dest, host, chunk=STREAM_CHUNK,
                                               deadline_s=STREAM_DEADLINE_S, **kw)
    if acq is None:
        return acq, final, status
    if acq.disposition in ("complete-unowned", "incomplete-unowned"):
        _durability(ctx, source, url, host, acq, dest)
    elif acq.contacted is False and not acq.complete:
        # `contacted=False` and complete is a `replayed-complete`, not a refusal
        _refused(ctx, source, url, host, acq, dest)
    else:
        _ownership_ok(ctx, source, url, dest, acq)
    return acq, final, status


#: append-only transition states for one artifact path; see docs/design/EVIDENCE-EXTRACTION-DESIGN.md.
OWNERSHIP_STATES = ("refused", "unowned", "ok")
OWNERSHIP_ENTITY = "ownership_transition"


def _state_key(source: str, path) -> str:
    return secrets.fingerprint(f"{source}|{path}")


def _held_path(acq, dest):
    """Where the bytes are — `<dest>.part` when incomplete, so every ownership row agrees on the path."""
    if acq is not None and not acq.complete and getattr(acq, "partial", None):
        return Path(acq.partial)
    return Path(getattr(acq, "path", None) or dest)


def _material(state: str, fields: dict) -> str:
    """The identity of a transition: a full sha256 over canonical JSON of its material fields."""
    doc = {"state": state, "disposition": fields.get("disposition") or "",
           "raw_ref": fields.get("raw_ref") or "",
           "state_paths": [str(x) for x in (fields.get("state_paths") or [])]}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _valid_transition(r) -> bool:
    """A persisted transition we can act on: `state`, `state_seq`, id and `state_fp` must all be present and
    agree. These rows come off disk, so a mismatch is input to reject.
    """
    if not (isinstance(r, dict)
            and isinstance(r.get("state_key"), str) and r["state_key"]
            and r.get("state") in OWNERSHIP_STATES
            and type(r.get("state_seq")) is int and r["state_seq"] > 0):
        return False
    if r.get("id") != f"ownership:{r['state_key']}:{r['state_seq']}":
        return False
    fp = r.get("state_fp")
    return isinstance(fp, str) and fp == _material(r["state"], r)


#: fields whose value is the transition. The store merges observations sharing an id, so a conflict
#: parked on any of these in `_alt` is the same (key, seq) ambiguity by another route.
_PROTECTED_TRANSITION_FIELDS = ("state", "state_seq", "state_key", "state_fp", "id")


def _has_conflict(r) -> bool:
    alt = r.get("_alt")
    return isinstance(alt, dict) and any(alt.get(f) for f in _PROTECTED_TRANSITION_FIELDS)


def _ownership_index(ctx, *, record_coverage: bool = True) -> tuple:
    """`({state_key: [transition, …]}, ambiguous_keys, authoritative)`, built once per context. Authority is
    global; live callers record its health, while derived/report callers request a read-only fold. See
    docs/design/EVIDENCE-EXTRACTION-DESIGN.md.
    """
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
            # a merged conflict on a transition field: two observations claimed one identity, and which is
            # current is exactly what we cannot decide
            ambiguous.add(r["state_key"])
    for k, v in idx.items():
        v.sort(key=lambda r: (r["state_seq"], str(r.get("id", ""))))
        if len({r["state_seq"] for r in v}) != len(v):
            ambiguous.add(k)
    # authority is global: an untrustworthy log gives no key a current state and takes no appends
    authoritative = (trust == "valid" and not corrupt)
    if record_coverage:
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
    idx, _amb, _auth = _ownership_index(ctx)
    return idx.get(key, [])


def _ownership_state(ctx, key: str) -> str:
    idx, ambiguous, authoritative = _ownership_index(ctx)
    if not authoritative or key in ambiguous:
        return "unknown"
    log = idx.get(key, [])
    return str(log[-1].get("state", "")) if log else ""


def _publish_state(ctx, key: str, state: str, *, klass: str, value: str, source: str, **fields) -> bool:
    """Append one transition, or a no-op when nothing material changed. Read-only while the log is
    non-authoritative or the key ambiguous.
    """
    if state not in OWNERSHIP_STATES:
        raise ValueError(f"unknown ownership state {state!r}")
    idx, ambiguous, authoritative = _ownership_index(ctx)
    if not authoritative or key in ambiguous:
        # read-only until repaired: appending onto an incomplete sequence manufactures a history
        return False
    log = idx.get(key, [])
    fp = _material(state, fields)
    if log and str(log[-1].get("state", "")) == state and log[-1].get("state_fp") == fp:
        return False
    seq = max(r["state_seq"] for r in log) + 1 if log else 1
    row = {"id": f"ownership:{key}:{seq}", "klass": klass, "state_key": key, "state": state,
           "state_seq": seq, "state_fp": fp, "value": value, "sources": [source], **fields}
    ctx.run.add(OWNERSHIP_ENTITY, row)
    idx.setdefault(key, []).append(row)
    return True


def current_ownership_rows(run, *, record_coverage: bool = False) -> tuple:
    """`(rows, authoritative)` for a report: the current transition for each path, through the single
    trust-aware resolver so a log the lane refuses to act on is not rendered as fact."""
    ctx = SimpleNamespace(run=run)
    idx, ambiguous, authoritative = _ownership_index(ctx, record_coverage=record_coverage)
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


def classify_ownership(run) -> tuple:
    """Fold and record ownership health while base events are still writable."""
    return current_ownership_rows(run, record_coverage=True)


def _ownership_ok(ctx, source: str, url: str, dest, acq) -> None:
    """The healthy counterpart of `_refused`/`_durability`, on the same units, so a repaired path clears the
    gap. The operator row is written only when the last state was a problem.
    """
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_ownership",
                            unit=f"{source}.url:{url}", eligible=1, tested=1, omitted=0,
                            reason=f"acquisition owned and readable ({acq.disposition})")
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_durability",
                            unit=f"{source}.artifact:{Path(dest).name}", eligible=1, tested=1,
                            omitted=0, reason=f"ownership receipt in place ({acq.disposition})")
    # …and the operator row, only when the last state was a problem
    key = _state_key(source, dest)
    if _ownership_state(ctx, key) in ("refused", "unowned"):
        held = _held_path(acq, dest)
        _publish_state(ctx, key, "ok", klass="ownership-resolved", value=str(held), source=source,
                       location=url, raw_ref=str(held), state_paths=[str(held)],
                       note=(f"RESOLVED: acquired and owned on a later attempt ({acq.disposition}). "
                             f"The earlier ownership problem no longer applies"))


def _durability(ctx, source: str, url: str, host: str, acq, dest) -> None:
    """A complete body whose ownership receipt could not be written: readable, but the path is refused
    from here on.
    """
    whole = acq.disposition == "complete-unowned"
    # the state key stays `dest` so one artifact path is one log
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
    """The acquisition state on disk withheld this URL; nothing was requested."""
    if acq.disposition == "replayed-complete":
        return                              # not a shortfall: the evidence is here and was not re-bought
    events.coverage_partial(source, kind=events.COVERAGE_OWNERSHIP, measure="evidence_ownership",
                            unit=f"{source}.url:{url}", eligible=1, tested=0, omitted=1,
                            reason=(f"acquisition refused by the ownership state on disk "
                                    f"({acq.disposition}); nothing was requested: {acq.error}"))
    # every file that exists, by `lstat`: `exists()` raises on an unreadable directory and answers False
    # for a dangling symlink, which is state that exists
    d = Path(dest)

    def _present(x):
        try:
            x.lstat()
            return True
        except OSError:
            return False                       # missing or unreadable: not present
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
    """Record an artifact acquired whole and not interpreted in process. A coverage record and a review row;
    neither claims the body was empty, oversized-and-dropped, or failed."""
    # deferred interpretation is a gating coverage gap
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
    """Emit the fetch coverage record: readable responses over eligible candidates, remainder split by
    disposition.
    """
    unreadable = max(0, attempted - completed)
    # subtract verified replays when calculating unrequested candidates
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
    """(kind, raw_value, line) for each secret in `text`. Read-only, no exploit.

    Provider-shaped tokens win over the generic dotenv catch for one value. `source_path` gates the format
    rules. See docs/design/EVIDENCE-EXTRACTION-DESIGN.md.
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
            # an assignment we found and did not claim: kept as an observation
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
    # bare `"key"` fields, decided structurally where the body parses: text proximity does not
    # establish a relationship
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
            # a structural finding travels with its JSON path and no line
            out.append((kind, val, where))
    else:
        # a body that does not parse never promotes: observation only
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
    # …and the file that is itself a secret, format-gated: see the docstring
    body = text.strip()
    if rejected is not None:
        # one place resolves provenance: an offset becomes a line, an unlocatable value keeps none
        for i, (reason, key, val, line) in enumerate(rejected):
            if isinstance(line, _JSONPath):
                continue
            if isinstance(line, _OFFSET):
                rejected[i] = (reason, key, val, text.count("\n", 0, int(line)) + 1)
            # `line is None` stays None: a structural finding carries its JSON path, and a text search reports
            # the first occurrence, not where the finding is
    if body and path and body not in seen_vals:
        for path_rx, kind, body_rx in _FORMAT_RULES:
            if path_rx.search(path) and body_rx.match(body):
                out.append((kind, body, 1))
                break
    return out


def _provenance(line) -> dict:
    """`{"line": 4}`, `{"json_path": "auth.jwt.key"}`, or `{}` — never a line we did not measure. A
    structural finding has no text offset, and the first line holding the same string is a different
    field.
    """
    if isinstance(line, _JSONPath):
        return {"json_path": str(line)}
    return {"line": line} if isinstance(line, int) and not isinstance(line, bool) else {}


def publish_finding(ctx, kind: str, val: str, line, *, url: str, dest, source: str,
                    host: str | None = None, final_url: str | None = None) -> str:
    """Route one mined finding to the entity that describes it — one place, so a kind is classified once.
    Returns "secret", "hash", "observation" or "". The complete value is stored and shown by every local
    artifact; only Quarry's own credentials are redacted.
    """
    # the host that answered owns the finding; `location` keeps the requested URL
    where = normalize.host_of_url(final_url or url) or host or normalize.host_of_url(url)
    if kind in OBSERVATION_KINDS:
        # signing context, not a proven secret: kept whole in the review queue
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
    """Route every detector-matched, rule-declined candidate to the observation queue with the reason it was
    not promoted. Returns the count. Classification changes placement, never retention; `interest` is shape
    only and drops nothing."""
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
    """General recon fetch -> parse -> extract: GET an in-scope, non-mutating resource, save the body, and
    extract secrets and in-scope links in full with provenance.

    The body is streamed to disk with no byte ceiling, so `dest` holds whatever arrived; `deferred` True
    means it is complete and only the in-process pass was declined. Returns
    `{ok, off_scope, final, status, dest, bytes, sha256, secrets, links (+ deferred, partial)}`; `ok` False
    means it was not the resource we asked for.
    """
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
        # a failure after contact is an attempt, not "never requested"
        res["attempted"], res["error"] = True, type(e).__name__
        return res
    # attempted = contact was made; a replayed receipt makes none
    res["attempted"] = bool(acq is None or acq.contacted)
    res["final"], res["status"] = final, status
    if acq is None:                                # off-scope redirect — caller records context
        res["off_scope"] = True
        return res
    res["contacted"], res["disposition"] = acq.contacted, acq.disposition
    if not acq.complete:
        # a refusal (nothing requested) and a broken transport are different; `contacted` False carries it
        res["error"] = "incomplete" if acq.contacted else "refused"
        res["partial"] = str(acq.partial) if acq.partial else None
        res["bytes"], res["reason"] = acq.bytes, acq.error
        return res
    res["dest"], res["bytes"], res["sha256"] = str(dest), acq.bytes, acq.sha256
    res["disposition"] = acq.disposition
    if acq.error:
        # a complete body whose ownership could not be recorded: the evidence is whole, but the next call
        # refuses the path
        res["reason"] = acq.error
    if status != 200:
        # a non-200 body is kept as evidence but not mined; `ok` stays False
        return res
    res["ok"] = True
    if acq.bytes > MAX_PARSE:
        # acquired complete, interpretation deferred: whole on disk, re-runnable with no further request
        res["deferred"] = True
        # not `sample`: nobody chose this subset, so it is a gap, recoverable from the kept artifact
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
    # classify by what answered: the fetch follows redirects. `location` is asked, `final` replied.
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
    """GET each exposed in-scope resource, extract its secrets and links, and raise a reviewable exposure
    marker. Returns the count of new secret entities."""
    added = eligible = attempted = completed = refused_n = replayed_n = 0
    for u in urls:
        if not ctx.scope.active_allowed(normalize.host_of_url(u)):
            continue                               # not ours to request: never part of the denominator
        eligible += 1
        r = fetch_and_extract(ctx, u, source="exposed-fetch", subdir="exposed")
        attempted += 1 if r["attempted"] else 0    # contact was made
        # completion means the body arrived whole; an interrupted 200 is not completed
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
            # `acquire()` already reported this refusal; keep it out of this lane's denominator
            refused_n += 1
            continue
        if r.get("error") == "incomplete":
            # a broken transport: what arrived is on disk, and this lane requested it
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
        # the exposure as reviewable evidence; confirmed:false, no impact performed
        ctx.run.add("review", {
            "id": f"exposed:{u}", "klass": "exposure", "value": u,
            "host": normalize.host_of_url(u), "raw_ref": r["dest"],
            "note": note, "sources": ["exposed-fetch"]})
    # disjoint buckets: this record is resources we requested, `acquire()` owns refusals
    _fetched("evidence.exposed", eligible - refused_n, attempted, completed,
             "in-scope exposed resource(s)", replayed=replayed_n)
    return added


# minimal introspection query — a non-mutating read: type/field names, enough to prove it is
# enabled and dump the shape
_GQL_INTROSPECTION = json.dumps({"query":
    "query{__schema{queryType{name} mutationType{name} "
    "types{name kind fields{name}}}}"})


def probe_graphql(ctx, endpoints: list[str]) -> int:
    """Send an introspection query to each in-scope GraphQL endpoint — a non-mutating read. When enabled the
    schema is dumped as evidence and a review is raised. Returns the count with introspection enabled."""
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
            continue                               # refused by the ownership state
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


# actuator sensitive read endpoints, cheap to GET: probed directly for reachability. Mutating POSTs
# (`shutdown`/`restart`) and `heapdump` are excluded — see _ACTUATOR_HEAVY.
ACTUATOR_SENSITIVE = ("env", "configprops", "mappings", "beans", "httptrace", "threaddump",
                      "loggers", "metrics", "sessions")
# Config endpoints whose 200 body can leak credentials -> worth mining for secrets.
_ACTUATOR_MINE = ("env", "configprops")
# heavy endpoints whose GET forces server-side work (a heapdump GET makes the JVM run a full GC and
# write a multi-GB dump): never requested in default recon, detected from the index `_links` instead
_ACTUATOR_HEAVY = ("heapdump",)
#: fixed-memory file scan; overlap preserves values crossing window boundaries.
_DEEP_SCAN_WINDOW = 8 * 1024 * 1024        # bytes held in RAM per mining window
_DEEP_SCAN_OVERLAP = 64 * 1024             # carried between windows so a secret on a boundary survives


def _actuator_index_links(ctx, base: str, host: str) -> set[str]:
    """GET the actuator index and return the endpoint names it advertises in `_links` — how we learn a heavy
    endpoint is exposed without requesting it."""
    dest = ctx.run.raw_path("params", "actuator",
                            f"{host}-index-{_artifact_id(base)}.json")
    try:
        acq, _final, status = acquire(ctx, base, dest, host, source="actuator-probe")
    except Exception:
        return set()
    if acq is None:
        return set()
    if not acq.contacted and not acq.complete:
        return set()                               # refused by the ownership state
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
        # the index decides which heavy endpoints are exposed; losing it silently under-reports
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
    """Deep-evidence opt-in: download a heavy artifact, save it, and mine it (ASCII secrets survive inside a
    binary heap dump). Returns True on a recorded download, False on failure."""
    dest = ctx.run.raw_path("params", "actuator",
                            f"{host}-{kind}-{_artifact_id(url)}.bin")
    try:
        acq, _final, status = acquire(ctx, url, dest, host, source="deep-evidence")
    except Exception:
        return False
    if acq is None or status != 200:
        return False                               # off-scope/absent → caller does detect-only fallback
    if not acq.contacted and not acq.complete:
        return False                               # refused by the ownership state
    if not acq.complete:
        # a partial heap dump is on disk and mined; the gap is stated, not discarded
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
    """Mine a file of any size by scanning it in overlapping windows. Returns secrets published.

    The window is the only bound — memory is `_DEEP_SCAN_WINDOW`, evidence is the whole file — and the
    overlap carries `_DEEP_SCAN_OVERLAP` bytes so a token on a boundary is not cut in half. Line numbers are
    per-window and approximate; the value and the artifact are the evidence."""
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
                # a separate set, or an unclassified value would suppress the same value later promoted
                fresh = [r for r in rejected if r[2] not in seen_unc]
                publish_unclassified(ctx, fresh, url=url, dest=path, source=source, host=host)
                seen_unc.update(r[2] for r in fresh)
                carry = window[-_DEEP_SCAN_OVERLAP:] if len(window) > _DEEP_SCAN_OVERLAP else window
    except OSError:
        return n
    return n


def probe_actuator(ctx, bases: list[str]) -> int:
    """Interrogate a Spring Boot actuator base. Cheap sensitive reads (`/actuator/env`…) are GET-probed for
    reachability and mined. Heavy endpoints (heapdump) are detected from the index `_links`: by default they
    are flagged, never requested (the GET itself triggers dump generation); deep-evidence mode (opt-in)
    downloads and mines them. Returns the count of bases with a sensitive endpoint exposed."""
    found = 0
    for base in bases:
        host = normalize.host_of_url(base)
        if not ctx.scope.active_allowed(host):
            continue
        advertised = _actuator_index_links(ctx, base, host)
        deep = getattr(getattr(ctx, "profile", None), "deep_evidence", False)
        # heavy endpoints: default flags high-priority from the advertised link with no request; deep-
        # evidence mode (opt-in) downloads and mines it
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
            # a 200 from /actuator/env is the exposure, whatever the body size
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


# OpenAPI specs: the document is stored whole; interpretation is bounded by `MAX_PARSE` and deferred above it


def _openapi_load(text: str):
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
    """The API base URL(s): OpenAPI v3 `servers`, Swagger v2 `host`+`basePath`, else the doc's own origin.
    Relative server URLs are joined against the doc origin."""
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
    """Fetch discovered OpenAPI/Swagger docs (unauth, in-scope, non-mutating GET) and extract the endpoint and
    query-param corpus. Only in-scope endpoints are kept. Returns the count of new endpoint entities."""
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
            continue                               # refused by the ownership state
        if not acq.complete:
            # the coverage record is authoritative, the review row readable; the timeout kind gates
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
            # build under every declared base, filtering in-scope per base
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
    """GET framework-specific recon endpoints on hosts whose tech matched a framework — non-mutating reads
    of exposed debug/admin dashboards. 200 is exposed (mined, high-priority), 401/403/redirect is
    present-but-protected. Returns the count exposed.
    """
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
            continue                                   # refused by the ownership state
        if status == 200:
            # a 200 is the exposure regardless of body size; mining scans the file
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


# SSTI confirmation payload: a benign math eval across the common template syntaxes. The computed value
# appearing while the literal `1234*5678` does not means the engine evaluated it.
_SSTI_PROBE = "{{1234*5678}}${1234*5678}#{1234*5678}<%=1234*5678%>"
_SSTI_EXPECT = "7006652"
_SSTI_LITERAL = "1234*5678"
_SSTI_MAX_PARAMS = 10          # bound params tested per URL


def _ssti_hit(path) -> bool | None:
    """Did the template engine evaluate the probe? True/False, or None when the body cannot be read. Both
    markers are independent — the computed value must appear and the literal must not — so the whole file
    is walked. None is not False: an unclassifiable response is a gap, never a quiet "safe".
    """
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
    """Confirm the SSTI primitive on gf candidates: inject a benign `{{math}}` polyglot into each query param
    (GET, non-mutating) and check the engine evaluated it. A hit is a candidate, not proof of impact.
    Returns the count of confirmed primitives."""
    found = 0
    for u in urls:
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):
            continue
        sp = urlsplit(u)
        qs = parse_qsl(sp.query, keep_blank_values=True)
        if not qs:
            continue
        # coverage is occurrence-keyed (`?a=1&a=2` is two) and split into independently reconciled
        # buckets: cap, stop, probed
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
            # a classification probe; it still streams, or an over-cap body reads as a false "no hit"
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
                # a non-200 is an answer: this parameter did not render the probe. Resolved, not a gap.
                unresolved.pop((i, k), None)
                resolved.add((i, k))
                _discard_artifact(dest)
                continue
            # an incomplete response answers nothing: the deciding literal may be in the suffix that
            # never arrived
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
            # the body with the computed value stays as evidence for manual validation
            ctx.run.add("finding", {
                "id": f"ssti:{tu[:80]}", "template": "ssti-candidate",
                "name": (f"SSTI primitive confirmed — template expr evaluated to {_SSTI_EXPECT} "
                         f"on param '{k}' (manual validation required)"),
                "severity": "high", "matched": tu, "raw_ref": str(dest),
                "sources": ["ssti-probe"], "confirmed": False})
            found += 1
            # one confirmation per URL; the rest stay named in the remainder, not counted as tested
            for j, (rest, _rv) in enumerate(qs[i + 1:], start=i + 1):
                if (j, rest) in unresolved:
                    unresolved[(j, rest)] = (STOPPED, "a confirmation on an earlier parameter "
                                                      "ended this URL")
            break
        for bucket in (BEYOND, STOPPED, PROBED):
            members = {occ: why for occ, (b, why) in unresolved.items() if b == bucket}
            # the probed bucket owns everything answered; the other two own only what they held back
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
