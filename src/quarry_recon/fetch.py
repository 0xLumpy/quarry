"""Shared direct-HTTP choke point for recon fetches to a TARGET.

Direct `urllib` requests bypass the guards the tool flags give nuclei/httpx/ffuf, so ONE place
enforces them for every hand-rolled fetch (evidence probes + crawl JS/sourcemap): RATELIMIT.HTTP
pacing, a bounded read, and PER-HOP redirect scope enforcement. `urlopen` follows redirects silently
— an in-scope URL can 30x to RFC1918 / cloud-metadata / OFF-scope infra, and with auto-follow that
request has ALREADY fired before any check. So `scoped_get` follows redirects MANUALLY with the
no-follow opener and scope-gates EACH hop's host BEFORE contacting it: a hop that would leave scope is
never requested at all. Same rule as the boundary: unauthenticated, in-scope, non-mutating, rate-safe.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from . import normalize

UA = "Mozilla/5.0"
DEFAULT_MAX_BODY = 2 * 1024 * 1024      # 2 MB default cap
DEFAULT_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})   # actual navigations (304 is NOT a redirect)
_SENSITIVE_HEADERS = ("authorization", "cookie", "proxy-authorization")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):     # never follow — return None so the 30x is handed back
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _pace(ctx) -> None:
    rl = getattr(getattr(ctx, "profile", None), "http_rl", None)
    if rl:                                    # RATELIMIT.HTTP -> pace to rl req/s
        time.sleep(1.0 / rl)


def _open_no_follow(req, timeout):
    """Open `req` WITHOUT following redirects. Returns (status, headers, response|None). A 3xx comes
    back either as a normal response (redirect_request->None) or as an HTTPError depending on handler
    order — both carry status+headers, so we normalize. A real 4xx/5xx re-raises (caller handles it,
    same as before this change)."""
    try:
        resp = _NO_REDIRECT_OPENER.open(req, timeout=timeout)
        return getattr(resp, "status", 200), getattr(resp, "headers", {}) or {}, resp
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            try:
                return e.code, e.headers, None   # redirect surfaced as error: headers only, nothing to read
            finally:
                e.close()                        # HTTPError is itself an open response — release it here
        raise


def redirect_location(ctx, url, origin_host=None, *, timeout=20):
    """ONE scoped request to `url` WITHOUT following redirects; returns (location_header|None, status).
    Rate-paced like scoped_get. For open-redirect probing: read WHERE the app would send us (the
    Location header) without ever fetching the attacker-controlled target — non-mutating, safe. The
    caller MUST have scope-gated the origin host already (this only touches the in-scope target)."""
    _pace(ctx)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
            return resp.headers.get("Location"), getattr(resp, "status", 200)
    except urllib.error.HTTPError as e:       # a 4xx/5xx (or a 30x surfaced as error) still carries headers
        return e.headers.get("Location"), e.code


def scoped_get(ctx, url, origin_host=None, *, max_body=DEFAULT_MAX_BODY, timeout=20,
               data=None, method="GET", headers=None, max_redirects=DEFAULT_MAX_REDIRECTS):
    """Fetch `url` with all guards. Returns (data|None, final_url, status):
      - data is None  => a redirect would leave scope; the off-scope hop is NEVER contacted (caller
        records context, no body is read);
      - otherwise     => bounded body read (<= max_body+1 bytes; caller drops if len > max_body).
    Redirects are followed MANUALLY, scope-checking each hop's host BEFORE the request — so an in-scope
    host that 30x's to RFC1918 / metadata / off-scope never gets contacted (unlike auto-follow, which
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
