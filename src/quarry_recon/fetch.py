"""Shared direct-HTTP choke point for recon fetches to a TARGET.

Direct `urllib` requests bypass the guards the tool flags give nuclei/httpx/ffuf, so ONE place
enforces them for every hand-rolled fetch (evidence probes + crawl JS/sourcemap): RATELIMIT.HTTP
pacing, a bounded read, and PER-HOP redirect scope enforcement. `urlopen` follows redirects silently
— an in-scope URL can 30x to the SCAN BOX / cloud-metadata / OFF-scope infra, and with auto-follow that
request has ALREADY fired before any check. So `scoped_get` follows redirects MANUALLY with the no-follow
opener and guards EACH hop's host BEFORE contacting it: a hop that leaves scope, or that would hit the scan
box itself (loopback/metadata/own-iface), is never requested — while a private/internal answer is a LEAD
(recorded as intel + contacted by default). Same boundary rule: unauthenticated, non-mutating, rate-safe.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import errno
import re
import secrets as _secrets
import stat
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import contract, netguard, normalize

UA = "Mozilla/5.0"
DEFAULT_MAX_BODY = 2 * 1024 * 1024      # 2 MB default cap
DEFAULT_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})   # actual navigations (304 is NOT a redirect)
_SENSITIVE_HEADERS = ("authorization", "cookie", "proxy-authorization")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):     # never follow — return None so the 30x is handed back
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)
# CSP retrieval tolerates self-signed / broken TLS (internal & staging apexes often have it — csprecon did
# too). Used ONLY by scoped_headers(insecure=True); the verifying opener stays the default everywhere else.
import ssl as _ssl  # noqa: E402
_INSECURE_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=_ssl._create_unverified_context()))


def _pace(ctx) -> None:
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                    # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)


def _open_no_follow(req, timeout, opener=None):
    """Open `req` WITHOUT following redirects. Returns (status, headers, response|None). A 3xx comes
    back either as a normal response (redirect_request->None) or as an HTTPError depending on handler
    order — both carry status+headers, so we normalize. A 4xx/5xx is ALSO handed back (audit #15): an
    HTTPError IS an open, readable response, so returning it (not raising) lets scoped_get honor its
    (body, final_url, status) contract — a 401/403 'protected-but-present' body is real evidence, and
    raising it lost that. Transport errors (URLError/timeout) still propagate — those aren't a status."""
    try:
        resp = (opener or _NO_REDIRECT_OPENER).open(req, timeout=timeout)
        return getattr(resp, "status", 200), getattr(resp, "headers", {}) or {}, resp
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            try:
                return e.code, e.headers, None   # redirect surfaced as error: headers only, nothing to read
            finally:
                e.close()                        # HTTPError is itself an open response — release it here
        return e.code, (e.headers or {}), e      # 4xx/5xx: a readable response — hand it back, do NOT raise


def redirect_location(ctx, url, origin_host=None, *, timeout=20):
    """ONE scoped request to `url` WITHOUT following redirects; returns (location_header|None, status).
    Rate-paced like scoped_get. For open-redirect probing: read WHERE the app would send us (the
    Location header) without ever fetching the attacker-controlled target — non-mutating, safe. The caller
    scope-gates the origin by NAME; this ALSO resolve-guards it (audit #1/#3) because redirect/SSRF
    candidates come from the GF/archive corpus, not only vetted live hosts. Returns (None, 0) — not
    contacted — for an origin that resolves to the SCAN BOX / metadata (a private origin IS contacted) or
    cannot be resolved."""
    _h = urlsplit(url).hostname
    _st, _deny, _intel = netguard.contact_state(_h, block_private=netguard._block_private(ctx))
    if _intel:
        netguard.record_internal(ctx, _h, _intel)          # record a private/self lead the live lookup found
    if _st != "contact":
        return None, 0
    _pace(ctx)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    status, rhdrs, resp = _open_no_follow(req, timeout)   # reuse the choke point: closes HTTPError, no fd leak
    try:
        return (rhdrs.get("Location") if rhdrs else None), status
    finally:
        if resp is not None:
            resp.close()


@contextlib.contextmanager
def _walk(ctx, url, origin_host=None, *, timeout=20, data=None, method="GET", headers=None,
          max_redirects=DEFAULT_MAX_REDIRECTS):
    """Walk the redirect chain with every guard and yield the TERMINAL hop as `(resp, final, status,
    contacted)` — the response is still OPEN, so the caller decides how the body is consumed.

    This is the loop `scoped_get` used to own inline. It was lifted out (2026-08-06) so a second body
    policy — streaming to disk instead of reading a bounded slice into memory — reuses the SAME guards
    rather than growing a second copy of them. Two copies of a scope check is how one of them stops
    matching the other.

    `contacted` False means the request was never made (a hop would leave scope, or would hit the scan
    box / metadata); status is 0 and there is nothing to read. `contacted` True with `resp` None means
    either a redirect surfaced as an HTTPError (headers only) or the redirect limit was exhausted — an
    EMPTY body, never confused with off-scope."""
    origin = origin_host or normalize.host_of_url(url)
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    current = url
    cur_parts = urlsplit(url)
    status = 0
    for _hop in range(max_redirects + 1):
        # self-attack guard: don't contact the SCAN BOX / metadata; RECORD a private/self lead the lookup
        # finds. private space IS contacted by default (block only under BLOCK_PRIVATE_TARGETS). Covers the
        # origin AND every redirect target (each becomes `current` at its hop top).
        _st, _deny, _intel = netguard.contact_state(cur_parts.hostname, block_private=netguard._block_private(ctx))
        if _intel:
            netguard.record_internal(ctx, cur_parts.hostname, _intel)
        if _st != "contact":
            yield None, current, 0, False
            return
        _pace(ctx)
        req = urllib.request.Request(current, data=data, method=method, headers=hdrs)
        status, rhdrs, resp = _open_no_follow(req, timeout)
        try:
            if status in _REDIRECT_STATUSES:
                loc = rhdrs.get("Location")
                if not loc:                              # redirect status without a Location — terminal
                    yield resp, current, status, True
                    return
                nxt = urljoin(current, loc)
                nhost = normalize.host_of_url(nxt)
                if nhost != origin and not ctx.scope.active_allowed(nhost):
                    yield None, nxt, status, False       # would leave scope -> DO NOT contact the target
                    return
                nxt_parts = urlsplit(nxt)
                if (nxt_parts.hostname, nxt_parts.port, nxt_parts.scheme) != \
                   (cur_parts.hostname, cur_parts.port, cur_parts.scheme):
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() not in _SENSITIVE_HEADERS}
                cur_parts, current = nxt_parts, nxt
                data, method = None, "GET"               # follow non-mutating: never re-POST to a redirect
                continue
            yield resp, current, status, True            # terminal (incl 304)
            return
        finally:
            if resp is not None:
                resp.close()                             # always release the connection/fd
    yield None, current, status, True                    # redirect limit exceeded — NOT off-scope; empty body


def scoped_get(ctx, url, origin_host=None, *, max_body=DEFAULT_MAX_BODY, timeout=20,
               data=None, method="GET", headers=None, max_redirects=DEFAULT_MAX_REDIRECTS):
    """Fetch `url` with all guards. Returns (data|None, final_url, status):
      - data is None  => the hop was NOT contacted: either a redirect would leave scope, OR the host
        resolves to the scan box / metadata (self-attack guard; a private answer IS contacted + recorded).
        Caller records context, no body is read;
      - otherwise     => bounded body read (<= max_body+1 bytes; caller drops if len > max_body).
    Redirects are followed MANUALLY, scope-checking each hop's host BEFORE the request — so an in-scope
    host that 30x's to the SCAN BOX / metadata / off-scope never gets contacted (a private hop IS contacted +
    recorded as a lead — offensive posture) (unlike auto-follow, which
    fires the request first, then checks). Sensitive headers are dropped when authority/scheme changes.
    Redirect-limit exhaustion returns an EMPTY body (not None) so a loop is never mistaken for off-scope.
    Paces to profile.http_rl. Caller MUST scope-gate the origin.

    This reads into MEMORY and is therefore the wrong tool when the body is EVIDENCE we intend to keep —
    an over-cap response comes back as `max_body+1` bytes for the caller to drop, which loses what was
    already fetched. `scoped_get_file` streams instead; see its docstring."""
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        return (resp.read(max_body + 1) if resp else b""), final, status


class Acquisition:
    """What a STREAMED fetch actually got. The artifact is on disk either way.

    `complete` False does not mean empty: `path` (or `partial`) holds the bytes that did arrive, and
    `error` says why the rest did not. Nothing here decides whether the body gets PARSED — that is the
    caller's separate question, and the point of the split (review#21, Lumpy).

    `contacted` and `disposition` exist because a REPLAYED receipt is not a request (review#22, Lumpy).
    A lane that counts an attempt on every call reports "1 attempted without a readable response" for a
    run that touched the network zero times. `disposition` is one of:

        complete             the body arrived whole, this call
        incomplete           we requested it and the transport or the disk broke, this call
        replayed-incomplete  a PRIOR incomplete acquisition; nothing was requested
        path-collision       the artifact path is already owned by a DIFFERENT request

    `final` and `status` are carried on the object so a replay reports the ORIGINAL response line rather
    than a synthetic zero — several lanes branch on status before they look at completeness."""

    __slots__ = ("path", "bytes", "sha256", "complete", "partial", "error",
                 "contacted", "disposition", "final", "status")

    def __init__(self, path, size, sha256, complete, partial=None, error=None,
                 contacted=True, disposition=None, final=None, status=None):
        self.path, self.bytes, self.sha256 = path, size, sha256
        self.complete, self.partial, self.error = complete, partial, error
        self.contacted = contacted
        self.disposition = disposition or ("complete" if complete else "incomplete")
        self.final, self.status = final, status


#: the acquisition RECEIPT sits beside the partial artifact. review#22 (Lumpy): the previous version
#: trusted the EXISTENCE of a `.part` file, and callers name artifacts with a truncated hash — two URLs
#: that collide there would have had one blocking the other with "this URL was incomplete". Existence is
#: not identity. The receipt binds the request that produced it.
_RECEIPT_SUFFIX = ".acq.json"


def acquisition_identity(url, method="GET", data=None, policy=None) -> str:
    """What makes two acquisitions THE SAME request: the URL, the method, the request body, and any
    policy the caller says changes the answer. A digest of those, never the values themselves."""
    h = hashlib.sha256()
    for part in (str(method or "GET").upper(), str(url), str(policy or "")):
        h.update(part.encode("utf-8", "replace")); h.update(b"\x00")
    h.update(hashlib.sha256(data if isinstance(data, bytes) else (data or b"")).digest()
             if data is not None else b"")
    return h.hexdigest()


class AcquisitionRefused(Exception):
    """The acquisition state on disk does not permit a request. Carries the disposition to report.

    review#23 (Lumpy): a refusal raised as an ordinary exception reached the caller's `except Exception`
    and was counted as a network attempt. A refusal is a RESULT — it says contact did not happen — so it
    is typed, and `scoped_get_file` converts it into an `Acquisition` rather than letting it escape."""

    def __init__(self, disposition, message, *, bytes_=0, partial=None, final=None, status=None,
                 digest=""):
        super().__init__(message)
        self.disposition, self.bytes, self.partial = disposition, bytes_, partial
        self.final, self.status = final, status
        #: review#24 (Lumpy): a verified replay knows the digest it just checked. Dropping it gave
        #: replayed evidence WEAKER provenance than the original acquisition, for no reason.
        self.digest = digest


def _digest_file(path, chunk: int = 1024 * 1024) -> "tuple[int, str]":
    """(size, sha256) of a file, read in fixed-memory chunks."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf); n += len(buf)
    return n, h.hexdigest()


_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _refuse_os(what, path, e):
    """A filesystem error while INSPECTING ownership is not a network attempt.

    review#24 (Lumpy): these escaped `_reconcile` as ordinary exceptions, the caller's blanket `except`
    caught them, and an unreadable receipt directory was reported as `attempted=True` for a run that
    never touched the target. If we cannot inspect the state, we do not know whether a request already
    happened — so we refuse, and we say contact did not occur."""
    return AcquisitionRefused("ownership-uninspectable",
                              f"cannot inspect {what} at {path} ({e}); the prior acquisition state is "
                              f"unknown, so this is NOT requested")


def _exists(path, follow=False):
    try:
        (path.stat() if follow else path.lstat())
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        raise _refuse_os("acquisition state", path, e) from e


def _read_regular(path, what):
    """Read a file WITHOUT following a symlink, or refuse.

    review#25 (Lumpy): `_exists` used `lstat`, but the read then went through `read_text`, which
    follows. A receipt pointed at an external valid document replayed as our own ownership record."""
    try:
        # O_NOFOLLOW: a symlink is not our receipt. O_NONBLOCK: a FIFO at this path would otherwise
        # block the open until a writer appears — a scan hanging forever on a named pipe someone left
        # in the run tree. `S_ISREG` below rejects both of those anyway; these flags make sure we get
        # to that check.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        if getattr(e, "errno", None) in (errno.ELOOP, errno.EMLINK):
            raise AcquisitionRefused("evidence-modified",
                                     f"{what} {path} is a symlink; refusing to follow it") from e
        raise AcquisitionRefused("receipt-unreadable",
                                 f"{what} {path} exists but cannot be read ({e}); refusing to request "
                                 f"again under an unknown prior state") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AcquisitionRefused("evidence-modified",
                                     f"{what} {path} is not a regular file; refusing")
        return os.read(fd, 1024 * 1024).decode("utf-8", "replace")
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    finally:
        os.close(fd)


def _str_field(doc, key, path, *, required=True):
    v = doc.get(key)
    if v is None and not required:
        return ""
    if not isinstance(v, str):
        return None
    return v


def _read_receipt(path):
    """The receipt as a VALIDATED record, or RAISE.

    review#23: collapsing "unreadable" into "absent" fails OPEN — a torn JSON after a crash read as "no
    prior acquisition" and the URL was requested again, which is the automatic retry this mechanism
    exists to prevent.

    review#24 (Lumpy): every integrity field is now REQUIRED and TYPED. An optional digest is not an
    integrity check — a receipt carrying `complete: true` and a byte count, with no digest, replayed
    same-length modified content as if it were the evidence we acquired. `complete` must be an actual
    bool, not something truthy."""
    raw = _read_regular(path, "acquisition receipt")
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise AcquisitionRefused("receipt-damaged",
                                 f"acquisition receipt {path} is not valid JSON ({e}); a torn receipt "
                                 f"may describe a request already made — refusing") from e
    if not isinstance(doc, dict):
        raise AcquisitionRefused("receipt-damaged", f"acquisition receipt {path} is not an object")
    bad = []
    if not isinstance(doc.get("ident"), str) or not _HEX64.match(doc.get("ident") or ""):
        bad.append("ident (64-hex)")
    if type(doc.get("complete")) is not bool:                      # not `truthy`: the exact type
        bad.append("complete (bool)")
    n = doc.get("bytes")
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        bad.append("bytes (non-negative int)")
    if not isinstance(doc.get("digest"), str) or not _HEX64.match(doc.get("digest") or ""):
        bad.append("digest (64-hex, REQUIRED)")
    # EVERY consumed field, not only the integrity four (review#25, Lumpy): `final` and `status` are
    # handed straight back to callers, and a receipt carrying `final: ["not-a-url"]` passed
    # reconciliation and then raised `TypeError: unhashable type` in the middle of interpretation.
    for key in ("url", "method"):
        if _str_field(doc, key, path) is None:
            bad.append(f"{key} (string)")
    if _str_field(doc, "final", path, required=False) is None:
        bad.append("final (string or absent)")
    if _str_field(doc, "error", path, required=False) is None:
        bad.append("error (string or absent)")
    st = doc.get("status")
    if st is not None and (isinstance(st, bool) or not isinstance(st, int) or not 0 <= st <= 599):
        bad.append("status (HTTP status int or absent)")
    if bad:
        raise AcquisitionRefused("receipt-damaged",
                                 f"acquisition receipt {path} is missing or malformed: "
                                 f"{', '.join(bad)}; refusing to act on an unverifiable record")
    return doc


def _verify_file(path, recorded_bytes, recorded_digest, *, what):
    """The stored evidence must be a REGULAR file of exactly the recorded size and digest.

    `lstat` (never `stat`) so a symlink is caught rather than followed: review#24 (Lumpy) pointed a
    symlink at matching external bytes and the complete branch — which had no such check, unlike the
    partial one — replayed it as our own evidence."""
    try:
        st = path.lstat()
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    if not stat.S_ISREG(st.st_mode):
        raise AcquisitionRefused("evidence-modified",
                                 f"{path} is not a regular file; refusing to treat it as {what}")
    try:
        size, sha = _digest_file(path)
    except OSError as e:
        raise _refuse_os(what, path, e) from e
    if size != recorded_bytes or sha != recorded_digest:
        raise AcquisitionRefused("evidence-modified",
                                 f"{path} no longer matches its receipt ({size} bytes/{sha[:16]} vs "
                                 f"{recorded_bytes}/{recorded_digest[:16]}); the stored {what} changed "
                                 f"under us and is NOT re-fetched automatically",
                                 bytes_=size, digest=sha)
    return size, sha


def _reconcile(dest, part, rec_path, ident, url):
    """Decide whether this artifact path may be ACQUIRED INTO, from ALL THREE files as one state.

    review#23 + review#24 (Lumpy). Only NOTHING-EXISTS permits a request; every other combination means
    a prior acquisition either happened or cannot be ruled out:

        nothing                  -> acquire
        dest, no receipt         -> orphan-complete     (evidence we cannot prove we own)
        part, no receipt         -> orphan-partial      (a crash, or a receipt that could not be written)
        receipt, other ident     -> path-collision      (this path belongs to a different request)
        receipt(complete), dest  -> replayed-complete   (verified; nothing requested)
        receipt(partial), part   -> replayed-incomplete (verified; nothing requested)
        receipt, file missing    -> evidence-lost
        file changed/symlink     -> evidence-modified
        receipt unreadable/torn  -> receipt-unreadable / receipt-damaged
        state uninspectable      -> ownership-uninspectable

    The `dest`-without-receipt case is the one that mattered most: an artifact already on disk was
    treated as a clean slate and OVERWRITTEN by a fresh request. Evidence we hold but cannot prove we
    own is not a reason to fetch again over the top of it.

    An operator clears any of these by removing the files; nothing here does it automatically, because
    each of them is evidence."""
    has_rec, has_part, has_dest = _exists(rec_path), _exists(part), _exists(dest)
    if not (has_rec or has_part or has_dest):
        return None
    if not has_rec:
        if has_part:
            raise AcquisitionRefused("orphan-partial",
                                     f"{part} exists with no acquisition receipt — a crash, or a "
                                     f"receipt that could not be written. Whose bytes these are is "
                                     f"unprovable, so this is NOT re-requested; remove the file to "
                                     f"try again", partial=part)
        raise AcquisitionRefused("orphan-complete",
                                 f"{dest} already holds an artifact with no acquisition receipt. It "
                                 f"cannot be proved to be this request's evidence, and it is NOT "
                                 f"overwritten by a fresh fetch; remove it to try again")
    rec = _read_receipt(rec_path)
    if rec.get("ident") != ident:
        # the artifact path is already owned by a DIFFERENT request. Truncated-hash filenames make this
        # possible, and silently writing over it would mix two URLs' evidence into one file — far worse
        # than refusing. Loud, and never a network request under an ambiguous name.
        raise AcquisitionRefused("path-collision",
                                 f"artifact path {dest} already holds a different acquisition "
                                 f"({rec.get('url')!r}); refusing to overwrite or to fetch under an "
                                 f"ambiguous name")
    recorded, digest = rec["bytes"], rec["digest"]
    final, status = rec.get("final"), rec.get("status")
    # a receipt describes ONE file. The other one being there means something wrote evidence this
    # record does not account for, and an unexplained file is exactly what the whole mechanism exists
    # to refuse (review#25, Lumpy).
    if rec["complete"] and has_part:
        raise AcquisitionRefused("ownership-conflict",
                                 f"receipt describes a COMPLETE acquisition, but {part} is also "
                                 f"present; the extra file is unaccounted evidence — refusing until an "
                                 f"operator resolves it", partial=part, final=final, status=status)
    if not rec["complete"] and has_dest:
        raise AcquisitionRefused("ownership-conflict",
                                 f"receipt describes an INCOMPLETE acquisition, but {dest} is also "
                                 f"present; the extra file is unaccounted evidence — refusing until an "
                                 f"operator resolves it", final=final, status=status)
    if rec["complete"]:
        if not has_dest:
            raise AcquisitionRefused("evidence-lost",
                                     f"receipt records a COMPLETE acquisition of {url} but {dest} is "
                                     f"gone; refusing to silently re-fetch what we claim to have",
                                     bytes_=recorded, final=final, status=status)
        size, sha = _verify_file(dest, recorded, digest, what="acquired evidence")
        raise AcquisitionRefused("replayed-complete",
                                 "already acquired WHOLE in this run; not re-requested",
                                 bytes_=size, digest=sha, final=final, status=status)
    if not has_part:
        raise AcquisitionRefused("evidence-lost",
                                 f"receipt records {recorded} byte(s) of {url} but {part} is gone; the "
                                 f"partial evidence cannot be shown and is NOT re-fetched automatically",
                                 bytes_=recorded, final=final, status=status)
    size, sha = _verify_file(part, recorded, digest, what="partial evidence")
    raise AcquisitionRefused("replayed-incomplete",
                             f"a prior acquisition of this URL was incomplete ({rec.get('error')}); "
                             f"NOT re-requested — remove {rec_path.name} and {part.name} to try again",
                             bytes_=size, digest=sha, partial=part, final=final, status=status)


def _publish_receipt(rec_path, doc) -> str:
    """Write the receipt ATOMICALLY. Returns "" on success or the failure text.

    review#23 (Lumpy): suppressing this failure left a partial with no receipt — which `_reconcile` now
    reads as `orphan-partial` and refuses, so the state stays FAIL-CLOSED. The caller still reports the
    failure, because "we could not record what we did" is not a detail."""
    tmp = None
    try:
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        # review#26 (Lumpy): the temp path was PREDICTABLE (`<receipt>.tmp`) and written with
        # `write_text`, which follows a symlink. Planting that path made Quarry overwrite an external
        # file, move the symlink into the receipt path, and report success — claiming an ownership it
        # did not have. A UNIQUE name created with O_CREAT|O_EXCL|O_NOFOLLOW cannot be pre-planted or
        # followed, and the write goes through the descriptor we opened rather than a path resolved a
        # second time.
        tmp = rec_path.with_name(f"{rec_path.name}.{os.getpid()}.{_secrets.token_hex(8)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            with contextlib.suppress(Exception):
                os.close(fd)
            raise
        os.replace(tmp, rec_path)
        return ""
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        with contextlib.suppress(Exception):
            if tmp is not None:
                tmp.unlink()
        return f"; the acquisition RECEIPT could not be written ({e}), so this artifact path is now " \
               f"refused until an operator clears it"


def scoped_get_file(ctx, url, dest, origin_host=None, *, timeout=20, data=None, method="GET",
                    headers=None, max_redirects=DEFAULT_MAX_REDIRECTS,
                    chunk=1024 * 1024, deadline_s=300.0, policy=None):
    """Same guards as `scoped_get`, but the body is STREAMED TO `dest` with NO byte ceiling.

    Returns `(Acquisition|None, final_url, status)`; None means the hop was never contacted, exactly as
    in `scoped_get`. An `Acquisition` with `contacted` False is a REFUSAL decided from the state on disk
    — no request was made — and `disposition` says which one.

    Lumpy, 2026-08-06, extending the paid-response rule to the target side: a byte cap on a response we
    have ALREADY REQUESTED does not prevent the cost — the request happened, the bytes crossed the wire —
    it only converts a fetched body into no evidence at all. `evidence.MAX_BODY` dropped an over-cap
    response ENTIRELY: not truncated, not saved, not reported, and the fetch counter still called it
    completed. Acquisition and interpretation are separate questions, and only the second one has a
    legitimate memory bound.

    So: fixed-memory chunks (`chunk` is what is held in RAM), hashed while streaming, published in one
    `os.replace`, and a broken transport keeps the partial bytes with `complete=False`. `deadline_s`
    bounds TIME, not size — a socket that never reaches EOF must not stream forever. Nothing retries."""
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")
    rec_path = dest.with_name(dest.name + _RECEIPT_SUFFIX)
    ident = acquisition_identity(url, method, data, policy)
    try:
        _reconcile(dest, part, rec_path, ident, url)
    except AcquisitionRefused as r:
        # every refusal is a RESULT, never an exception the caller has to guess about: `contacted` is
        # False, so nothing counts it as an attempt on the target.
        return (Acquisition(dest if r.disposition == "replayed-complete" else None,
                            r.bytes, r.digest, r.disposition == "replayed-complete",
                            partial=r.partial, error=str(r), contacted=False,
                            disposition=r.disposition, final=r.final, status=r.status),
                r.final or url, r.status or 0)
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        if resp is None:                       # redirect loop / headers-only 3xx: an EMPTY body, published
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"")
            n, sha = 0, hashlib.sha256(b"").hexdigest()
            note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                               "final": final, "status": status, "bytes": 0,
                                               "digest": sha, "complete": True})
            return (Acquisition(dest, 0, sha, True, final=final, status=status, error=note or None,
                                disposition="complete-unowned" if note else "complete"),
                    final, status)
        try:
            n, sha = contract.stream_to_file(resp, dest, chunk=chunk, deadline_s=deadline_s)
        except contract.IncompleteAcquisition as e:
            # the bytes that DID arrive stay on disk beside the destination, with a RECEIPT binding them
            # to the request that produced them. This is an acquisition GAP, reported as one — never a
            # silent empty result and never an automatic retry.
            written, partial = getattr(e, "bytes_written", 0), getattr(e, "partial", None)
            psha = ""
            if partial is not None and Path(partial).exists():
                written, psha = _digest_file(partial)     # what is ON DISK, not what we think we wrote
            note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                               "final": final, "status": status, "bytes": written,
                                               "digest": psha, "complete": False, "error": str(e)})
            # review#28 (Lumpy): the disposition stayed `incomplete` even when the RECEIPT write
            # failed, so the caller certified the acquisition as durably owned — while the next
            # lifecycle would meet an `orphan-partial` and refuse. The transport gap and the ownership
            # gap are separate facts and both are true here.
            return (Acquisition(None, written, "", False, partial=partial, error=str(e) + note,
                                disposition="incomplete-unowned" if note else "incomplete",
                                final=final, status=status), final, status)
        # a COMPLETE acquisition is bound too (review#23, Lumpy): without a receipt, another method,
        # body or policy for the same URL would overwrite this artifact even though
        # `acquisition_identity()` says they are different work.
        # the receipt can only be written AFTER the artifact is published, because it records the
        # digest of what actually landed. If that write fails the body IS complete — saying otherwise
        # would be a lie about the evidence — but its ownership is unrecorded, so the disposition says
        # so and the next call refuses the path as `orphan-complete` (review#24, Lumpy).
        note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                           "final": final, "status": status, "bytes": n,
                                           "digest": sha, "complete": True})
        return (Acquisition(dest, n, sha, True, final=final, status=status, error=note or None,
                            disposition="complete-unowned" if note else "complete"),
                final, status)


def scoped_headers(ctx, url, *, timeout=20, max_redirects=DEFAULT_MAX_REDIRECTS, max_body=512 * 1024,
                   insecure=False):
    """Guarded HEADER+BODY fetch: resolve- + scope-guard EVERY hop, follow only in-scope redirects, return
    (headers|None, body, final_url, status). headers is None when a hop would leave scope / hit the scan box
    (never contacted) OR on a swallowed TRANSPORT failure (URLError/TLS/timeout) so one bad request never
    aborts the caller's phase. A bounded body is read (for <meta http-equiv> CSP). `insecure` tolerates self-
    signed TLS (CSP retrieval on internal/staging apexes). csprecon auto-follows redirects unsafely."""
    opener = _INSECURE_OPENER if insecure else _NO_REDIRECT_OPENER
    origin = normalize.host_of_url(url)
    current = url
    cur_parts = urlsplit(url)
    status = 0
    for _hop in range(max_redirects + 1):
        _st, _deny, _intel = netguard.contact_state(cur_parts.hostname, block_private=netguard._block_private(ctx))
        if _intel:
            netguard.record_internal(ctx, cur_parts.hostname, _intel)
        if _st != "contact":
            return None, b"", current, 0                  # scan box/metadata / unresolved -> not contacted (private IS)
        _pace(ctx)
        req = urllib.request.Request(current, headers={"User-Agent": UA}, method="GET")
        try:
            status, rhdrs, resp = _open_no_follow(req, timeout, opener)
        except (urllib.error.URLError, OSError):
            return None, b"", current, 0                  # transport failure -> swallow, caller continues
        try:
            if status in _REDIRECT_STATUSES:
                loc = rhdrs.get("Location") if rhdrs else None
                if not loc:
                    return rhdrs, b"", current, status
                nxt = urljoin(current, loc)
                if normalize.host_of_url(nxt) != origin and not ctx.scope.active_allowed(normalize.host_of_url(nxt)):
                    return None, b"", nxt, status         # redirect would leave scope -> stop
                cur_parts, current = urlsplit(nxt), nxt
                continue
            body = resp.read(max_body) if resp else b""
            return rhdrs, body, current, status
        finally:
            if resp is not None:
                resp.close()
    return None, b"", current, status
