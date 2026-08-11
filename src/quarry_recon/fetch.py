"""Shared direct-HTTP choke point for recon fetches to a target.

One place enforces the guards that tool flags give nuclei/httpx/ffuf on every hand-rolled fetch:
http_rl pacing, a bounded read, and per-hop redirect scope enforcement. Redirects are followed
manually with the no-follow opener so each hop's host is guarded before contact — a hop leaving scope
or hitting the scan box (loopback/metadata/own-iface) is never requested, while a private/internal
answer is recorded as intel and contacted by default. All fetches are unauthenticated and non-mutating.
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
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})   # actual navigations (304 is not a redirect)
_SENSITIVE_HEADERS = ("authorization", "cookie", "proxy-authorization")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):     # never follow — return None so the 30x is handed back
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)
# Tolerates self-signed/broken TLS for CSP retrieval on internal/staging apexes. Used only by
# scoped_headers(insecure=True); the verifying opener stays the default everywhere else.
import ssl as _ssl  # noqa: E402
_INSECURE_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=_ssl._create_unverified_context()))


def _pace(ctx) -> None:
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                    # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)


def _open_no_follow(req, timeout, opener=None):
    """Open `req` without following redirects. Returns (status, headers, response|None).

    A 3xx surfaces as a normal response or an HTTPError depending on handler order — both carry
    status+headers, normalized here. A 4xx/5xx is handed back rather than raised: an HTTPError is an
    open readable response, and a 401/403 'protected-but-present' body is evidence scoped_get keeps.
    Transport errors (URLError/timeout) still propagate — those are not a status."""
    try:
        resp = (opener or _NO_REDIRECT_OPENER).open(req, timeout=timeout)
        return getattr(resp, "status", 200), getattr(resp, "headers", {}) or {}, resp
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            try:
                return e.code, e.headers, None   # redirect surfaced as error: headers only, nothing to read
            finally:
                e.close()                        # HTTPError is itself an open response — release it here
        return e.code, (e.headers or {}), e      # 4xx/5xx: a readable response — hand it back, don't raise


def redirect_location(ctx, url, origin_host=None, *, timeout=20):
    """One scoped, rate-paced request to `url` without following redirects; returns
    (location_header|None, status). For open-redirect probing: read where the app would send us
    without fetching the attacker-controlled target. Resolve-guards the origin as well as the caller's
    name-based scope gate, since redirect/SSRF candidates come from the gf/archive corpus. Returns
    (None, 0) for an origin that resolves to the scan box / metadata (a private origin is contacted) or
    cannot be resolved."""
    _h = urlsplit(url).hostname
    _st, _deny, _intel = netguard.contact_state(_h, block_private=netguard._block_private(ctx))
    if _intel:
        netguard.record_internal(ctx, _h, _intel)          # record a private/self lead the lookup found
    if _st != "contact":
        return None, 0
    _pace(ctx)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    status, rhdrs, resp = _open_no_follow(req, timeout)   # reuse the choke point: no fd leak
    try:
        return (rhdrs.get("Location") if rhdrs else None), status
    finally:
        if resp is not None:
            resp.close()


@contextlib.contextmanager
def _walk(ctx, url, origin_host=None, *, timeout=20, data=None, method="GET", headers=None,
          max_redirects=DEFAULT_MAX_REDIRECTS):
    """Walk the redirect chain with every guard and yield the terminal hop as `(resp, final, status,
    contacted)`; the response is still open, so the caller decides how the body is consumed. Shared by
    both body policies (bounded read and stream-to-disk) so one copy of the guards serves both.

    `contacted` False means the request was never made (a hop would leave scope or hit the scan box /
    metadata); status is 0, nothing to read. `contacted` True with `resp` None is an empty body — a
    redirect surfaced as an HTTPError (headers only) or the redirect limit was exhausted — never
    confused with off-scope."""
    origin = origin_host or normalize.host_of_url(url)
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    current = url
    cur_parts = urlsplit(url)
    status = 0
    for _hop in range(max_redirects + 1):
        # self-attack guard on the origin and every redirect target: never contact the scan box /
        # metadata; record a private/self lead (private space is contacted unless block_private_targets).
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
                    yield None, nxt, status, False       # would leave scope -> don't contact the target
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
    yield None, current, status, True                    # redirect limit exceeded — not off-scope; empty body


def scoped_get(ctx, url, origin_host=None, *, max_body=DEFAULT_MAX_BODY, timeout=20,
               data=None, method="GET", headers=None, max_redirects=DEFAULT_MAX_REDIRECTS):
    """Fetch `url` with all guards. Returns (data|None, final_url, status):
      - data is None  => the hop was not contacted: a redirect would leave scope, or the host resolves
        to the scan box / metadata (a private answer is contacted + recorded). No body is read.
      - otherwise     => bounded body read (<= max_body+1 bytes; caller drops if len > max_body).
    Sensitive headers are dropped when authority/scheme changes. Redirect-limit exhaustion returns an
    empty body (not None) so a loop is never mistaken for off-scope. Paces to profile.http_rl; caller
    must scope-gate the origin.

    Reads into memory, so it is the wrong tool when the body is evidence to keep: an over-cap response
    comes back as `max_body+1` bytes to drop, losing what was fetched. Use `scoped_get_file` instead."""
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        return (resp.read(max_body + 1) if resp else b""), final, status


class Acquisition:
    """What a streamed fetch got; the artifact is on disk either way.

    `complete` False is not empty: `path` (or `partial`) holds the bytes that arrived and `error` says
    why the rest did not. Whether the body gets parsed is the caller's separate question. `contacted`
    and `disposition` distinguish a replayed receipt from a request. `disposition` is one of:

        complete             the body arrived whole, this call
        incomplete           we requested it and the transport or the disk broke, this call
        replayed-incomplete  a prior incomplete acquisition; nothing was requested
        path-collision       the artifact path is already owned by a different request

    `final` and `status` carry the original response line so a replay reports it rather than a synthetic
    zero — several lanes branch on status before completeness."""

    __slots__ = ("path", "bytes", "sha256", "complete", "partial", "error",
                 "contacted", "disposition", "final", "status", "truncation")

    def __init__(self, path, size, sha256, complete, partial=None, error=None,
                 contacted=True, disposition=None, final=None, status=None, truncation=None):
        self.path, self.bytes, self.sha256 = path, size, sha256
        self.complete, self.partial, self.error = complete, partial, error
        self.contacted = contacted
        self.disposition = disposition or ("complete" if complete else "incomplete")
        self.final, self.status = final, status
        self.truncation = truncation      # a typed `contract.Truncation` distinguishes it from a generic incomplete


#: the acquisition receipt sits beside the partial artifact and binds it to the request that produced
#: it — existence of a truncated-hash `.part` file is not identity.
_RECEIPT_SUFFIX = ".acq.json"


def acquisition_identity(url, method="GET", data=None, policy=None) -> str:
    """A digest of what makes two acquisitions the same request: URL, method, body, and any policy the
    caller says changes the answer — never the values themselves."""
    h = hashlib.sha256()
    for part in (str(method or "GET").upper(), str(url), str(policy or "")):
        h.update(part.encode("utf-8", "replace")); h.update(b"\x00")
    h.update(hashlib.sha256(data if isinstance(data, bytes) else (data or b"")).digest()
             if data is not None else b"")
    return h.hexdigest()


class AcquisitionRefused(Exception):
    """The acquisition state on disk does not permit a request. Typed (not a bare exception) and carries
    the disposition to report, so a refusal is a result — `scoped_get_file` converts it into an
    `Acquisition` rather than letting the caller's `except` count it as a network attempt."""

    def __init__(self, disposition, message, *, bytes_=0, partial=None, final=None, status=None,
                 digest="", truncation=None):
        super().__init__(message)
        self.disposition, self.bytes, self.partial = disposition, bytes_, partial
        self.final, self.status = final, status
        self.digest = digest             # a verified replay keeps the digest it checked
        self.truncation = truncation     # a replayed truncation carries its typed remainder forward


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
    """A filesystem error while inspecting ownership is not a network attempt: if we cannot inspect the
    state we do not know whether a request already happened, so we refuse and say contact did not occur."""
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
    """Read a file without following a symlink, or refuse — a symlinked receipt could point at an
    external document and replay as our own ownership record."""
    try:
        # O_NOFOLLOW rejects a symlink; O_NONBLOCK keeps a FIFO from blocking the open forever. S_ISREG
        # below rejects both anyway; these flags just ensure we reach that check.
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
    """The receipt as a validated record, or raise.

    "Unreadable" must not collapse into "absent": a torn receipt describes a request that may already
    have been made, so it refuses rather than fetching again. Every integrity field is required and
    typed — an optional digest is not an integrity check, and `complete` must be an actual bool."""
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
    # validate every consumed field, not only the integrity four: `final`/`status` are handed straight
    # back to callers, so a malformed one must be caught here, not raised mid-interpretation.
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
    # an incomplete receipt may carry a typed policy truncation: validate its shape so a replay
    # reconstructs it rather than reducing every incomplete to a generic one
    trunc = doc.get("truncation")
    if trunc is not None:
        try:
            contract.Truncation.from_receipt(trunc)
        except ValueError:
            bad.append("truncation ({kind: layer, limit: non-negative int})")
        # a truncation is a policy stop: a whole body cannot also be a truncated one
        if doc.get("complete") is True:
            bad.append("truncation on a complete acquisition (contradictory)")
    if bad:
        raise AcquisitionRefused("receipt-damaged",
                                 f"acquisition receipt {path} is missing or malformed: "
                                 f"{', '.join(bad)}; refusing to act on an unverifiable record")
    return doc


def _verify_file(path, recorded_bytes, recorded_digest, *, what):
    """The stored evidence must be a regular file of exactly the recorded size and digest. Uses `lstat`
    (never `stat`) so a symlink pointed at matching external bytes is caught, not followed."""
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
    """Decide whether this artifact path may be acquired into, reading all three files as one state.
    Only nothing-exists permits a request; every other combination means a prior acquisition happened
    or cannot be ruled out:

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

    An operator clears any of these by removing the files; nothing here does it automatically, because
    each is evidence."""
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
        # path owned by a different request (truncated-hash filenames collide); overwriting would mix
        # two URLs' evidence into one file — refuse loudly, never fetch under an ambiguous name.
        raise AcquisitionRefused("path-collision",
                                 f"artifact path {dest} already holds a different acquisition "
                                 f"({rec.get('url')!r}); refusing to overwrite or to fetch under an "
                                 f"ambiguous name")
    recorded, digest = rec["bytes"], rec["digest"]
    final, status = rec.get("final"), rec.get("status")
    # a receipt describes one file; the other being present is unaccounted evidence — refuse.
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
    # `_read_receipt` already validated the shape; rebuild the typed remainder so a replay reports the
    # truncation as one rather than a generic incomplete
    trunc = contract.Truncation.from_receipt(rec["truncation"]) if rec.get("truncation") is not None else None
    raise AcquisitionRefused("replayed-incomplete",
                             f"a prior acquisition of this URL was incomplete ({rec.get('error')}); "
                             f"NOT re-requested — remove {rec_path.name} and {part.name} to try again",
                             bytes_=size, digest=sha, partial=part, final=final, status=status,
                             truncation=trunc)


def _publish_receipt(rec_path, doc) -> str:
    """Write the receipt atomically. Returns "" on success or the failure text. The failure is reported
    (not suppressed): a partial with no receipt reconciles as `orphan-partial` and refuses, staying
    fail-closed."""
    tmp = None
    try:
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        # a unique name with O_CREAT|O_EXCL|O_NOFOLLOW cannot be pre-planted or symlink-followed, and the
        # write goes through the descriptor rather than a path resolved a second time.
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
                    chunk=1024 * 1024, deadline_s=300.0, policy=None, governor=None):
    """Same guards as `scoped_get`, but the body is streamed to `dest` under `governor`'s disk policy.

    Returns `(Acquisition|None, final_url, status)`; None means the hop was never contacted, as in
    `scoped_get`. An `Acquisition` with `contacted` False is a refusal decided from the state on disk —
    no request was made — and `disposition` says which one.

    The body is not size-capped for its own sake — the request already happened and the bytes already
    crossed the wire — but a `DiskGovernor` bounds free space (and any configured byte ceiling) so a
    hostile infinite body cannot fill the host: at the boundary the partial is KEPT with `complete=False`
    (it reconciles as an incomplete acquisition) and the receipt records the binding layer as the
    durable, reproducible remainder.
    Fixed-memory chunks (`chunk` is what is held in RAM), hashed while streaming, published in one
    `os.replace`; a broken transport keeps the partial too. `deadline_s` bounds time. Nothing retries."""
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")
    rec_path = dest.with_name(dest.name + _RECEIPT_SUFFIX)
    ident = acquisition_identity(url, method, data, policy)
    try:
        _reconcile(dest, part, rec_path, ident, url)
    except AcquisitionRefused as r:
        # a refusal is a result: `contacted` False, so nothing counts it as an attempt on the target.
        return (Acquisition(dest if r.disposition == "replayed-complete" else None,
                            r.bytes, r.digest, r.disposition == "replayed-complete",
                            partial=r.partial, error=str(r), contacted=False,
                            disposition=r.disposition, final=r.final, status=r.status,
                            truncation=getattr(r, "truncation", None)),
                r.final or url, r.status or 0)
    # admit against the byte governor before contacting: an exhausted/tripped or misconfigured budget
    # must not open the request (no spend) and must leave no receipt
    try:
        gov = governor if governor is not None else contract.default_governor()
    except ValueError as e:
        return (Acquisition(None, 0, "", False, contacted=False, disposition="budget-invalid",
                            error=f"acquisition budget misconfigured; NOT contacted: {e}",
                            final=url, status=0), url, 0)
    dest.parent.mkdir(parents=True, exist_ok=True)
    denied = gov.admit(dest.parent)
    if denied is not None:
        return (Acquisition(None, 0, "", False, contacted=False, disposition="budget-exhausted",
                            error=f"acquisition budget exhausted at the {denied} policy; NOT contacted",
                            final=url, status=0), url, 0)
    with _walk(ctx, url, origin_host, timeout=timeout, data=data, method=method, headers=headers,
               max_redirects=max_redirects) as (resp, final, status, contacted):
        if not contacted:
            return None, final, status
        if resp is None:                       # redirect loop / headers-only 3xx: an empty body, published
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
            n, sha = contract.stream_to_file(resp, dest, chunk=chunk, deadline_s=deadline_s,
                                             governor=gov)
        except contract.IncompleteAcquisition as e:
            # the arrived bytes stay on disk with a receipt binding them to the request: an acquisition
            # gap, reported as one — never a silent empty result and never an automatic retry.
            written, partial = getattr(e, "bytes_written", 0), getattr(e, "partial", None)
            psha = ""
            if partial is not None and Path(partial).exists():
                written, psha = _digest_file(partial)     # what is on disk, not what we think we wrote
            rec = {"ident": ident, "url": url, "method": method, "final": final, "status": status,
                   "bytes": written, "digest": psha, "complete": False, "error": str(e)}
            # a policy truncation is a typed remainder: the binding layer + bound ride the receipt so a
            # raised bound is reproducible, distinct from a transport break with no configured cause.
            trunc = None
            if isinstance(e, contract.AcquisitionTruncated):
                trunc = contract.Truncation(e.limit_kind, e.limit_bytes)
                rec["truncation"] = trunc.as_receipt()
            note = _publish_receipt(rec_path, rec)
            # transport gap and ownership gap are separate facts: a failed receipt write makes the
            # disposition `-unowned` so the next lifecycle refuses the partial rather than trusting it.
            return (Acquisition(None, written, psha, False, partial=partial, error=str(e) + note,
                                disposition="incomplete-unowned" if note else "incomplete",
                                final=final, status=status, truncation=trunc), final, status)
        # bind the complete acquisition too, or another method/body/policy for the same URL overwrites
        # it. Written after the artifact; a failed write leaves it complete-but-unowned (orphan-complete).
        note = _publish_receipt(rec_path, {"ident": ident, "url": url, "method": method,
                                           "final": final, "status": status, "bytes": n,
                                           "digest": sha, "complete": True})
        return (Acquisition(dest, n, sha, True, final=final, status=status, error=note or None,
                            disposition="complete-unowned" if note else "complete"),
                final, status)


def scoped_headers(ctx, url, *, timeout=20, max_redirects=DEFAULT_MAX_REDIRECTS, max_body=512 * 1024,
                   insecure=False):
    """Guarded header+body fetch: resolve- + scope-guard every hop, follow only in-scope redirects,
    return (headers|None, body, final_url, status). headers is None when a hop would leave scope / hit
    the scan box (never contacted) or on a swallowed transport failure (URLError/TLS/timeout), so one
    bad request never aborts the caller's phase. A bounded body is read (for <meta http-equiv> CSP).
    `insecure` tolerates self-signed TLS for CSP retrieval on internal/staging apexes."""
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
            return None, b"", current, 0                  # scan box/metadata/unresolved -> not contacted
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
