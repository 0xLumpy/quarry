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

import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from . import netguard, normalize

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
    Paces to profile.http_rl. Caller MUST scope-gate the origin."""
    origin = origin_host or normalize.host_of_url(url)
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    current = url
    cur_parts = urlsplit(url)
    status = 0
    for _hop in range(max_redirects + 1):
        # self-attack guard: don't contact the SCAN BOX / metadata; RECORD a private/self lead the lookup finds.
        # private space IS contacted by default (block only under BLOCK_PRIVATE_TARGETS). Covers the origin AND
        # every redirect target (each becomes `current` at its hop top).
        _st, _deny, _intel = netguard.contact_state(cur_parts.hostname, block_private=netguard._block_private(ctx))
        if _intel:
            netguard.record_internal(ctx, cur_parts.hostname, _intel)
        if _st != "contact":
            return None, current, 0
        _pace(ctx)
        req = urllib.request.Request(current, data=data, method=method, headers=hdrs)
        status, rhdrs, resp = _open_no_follow(req, timeout)
        try:
            if status in _REDIRECT_STATUSES:
                loc = rhdrs.get("Location")
                if not loc:                              # redirect status without a Location — terminal
                    return (resp.read(max_body + 1) if resp else b""), current, status
                nxt = urljoin(current, loc)
                nhost = normalize.host_of_url(nxt)
                if nhost != origin and not ctx.scope.active_allowed(nhost):
                    return None, nxt, status             # would leave scope -> DO NOT contact the target
                nxt_parts = urlsplit(nxt)
                if (nxt_parts.hostname, nxt_parts.port, nxt_parts.scheme) != \
                   (cur_parts.hostname, cur_parts.port, cur_parts.scheme):
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() not in _SENSITIVE_HEADERS}
                cur_parts, current = nxt_parts, nxt
                data, method = None, "GET"               # follow non-mutating: never re-POST to a redirect
                continue
            return (resp.read(max_body + 1) if resp else b""), current, status   # terminal (incl 304)
        finally:
            if resp is not None:
                resp.close()                             # always release the connection/fd
    return b"", current, status                          # redirect limit exceeded — NOT off-scope; empty body


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
