"""Cloud-asset discovery — candidate bucket enumeration (S3 + GCS) from the target's apex/org.

Map-don't-exploit + verify-ownership: DETECT bucket existence + public/private (unauth, non-mutating
GET, **status only — no content is read, downloaded, or modified**), emit candidates for human
confirmation. A guessed name is NOT proof of ownership — items are review candidates tagged
"VERIFY OWNERSHIP", same model as the OSINT RDAP/azmap candidates. Azure *tenancy* is handled
separately (azmap in osint); this is object storage only.
"""
from __future__ import annotations

import re
import socket
import urllib.error
import urllib.request

from . import events

# common bucket-name patterns around a seed (apex label / org / brand).
_SUFFIXES = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-assets", "-static",
             "-media", "-uploads", "-data", "-logs", "-config", "-public", "-private",
             "-files", "-cdn", "-images", "-app", "-test", "-archive", "-internal", "-storage"]
_MAX_NAMES = 120
_PROVIDERS = [
    ("s3", lambda n: f"https://{n}.s3.amazonaws.com/"),
    ("gcs", lambda n: f"https://storage.googleapis.com/{n}/"),
]


def _seeds(profile) -> set:
    s = set()
    for a in profile.apex_domains:
        lbl = a.split(".")[0]
        if lbl:
            s.add(lbl)
    for name in list(getattr(profile, "org_names", []) or []) + list(getattr(profile, "brands", []) or []):
        cleaned = re.sub(r"[^a-z0-9]", "", str(name).lower())
        if cleaned:
            s.add(cleaned)
    return s


def _all_candidates(profile) -> list:
    out = set()
    for seed in _seeds(profile):
        for suf in _SUFFIXES:
            out.add(f"{seed}{suf}")
    return sorted(out)


def _check(url: str, timeout: int = 8):
    """Return (exists, access): GET status ONLY — the body is never read (non-mutating; no content is
    touched). C06 tri-state: exists is True (200=public / 403=private), False (404 = definitively absent),
    or None when INDETERMINATE — a transport error or non-definitive HTTP code. An indeterminate probe must
    NOT be recorded as a confirmed absence (the old `except → not found` was a false negative: a bucket that
    EXISTS but whose probe timed out / DNS-failed was dropped)."""
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, ("public" if getattr(r, "status", 200) == 200 else "unknown")
    except urllib.error.HTTPError as e:                      # a definitive HTTP response from the endpoint
        if e.code == 403:
            return True, "private"
        if e.code == 404:
            return False, None                              # NoSuchBucket — definitively absent
        return None, None                                   # other 4xx/5xx — indeterminate, not "absent"
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError):
        return None, None                                   # transport error — INDETERMINATE (never a false negative)


def discover(ctx) -> int:
    """Enumerate S3/GCS bucket candidates from the target's apex/org and record the ones that exist as `cloud`
    review candidates (verify-ownership). Returns the count found. Skipped in passive. review-r2#2: the whole
    enumeration runs UNDER the provider contract (registered source_id `horizontal.cloud_buckets`) so it gets a
    tool_start/tool_finish lifecycle like every other source — not an unbracketed side channel."""
    if ctx.profile.passive_only:
        return 0
    from .contract import run_provider
    # review-r3#5: stable work_unit from the bounded inputs (candidate seeds) + effective config (providers,
    # name cap) — the C07/C10 resume key.
    wu = events.work_unit("horizontal.cloud_buckets",
                          inputs={"seeds": sorted(_seeds(ctx.profile))},
                          config={"providers": [p for p, _ in _PROVIDERS], "name_cap": _MAX_NAMES,
                                  "suffixes": _SUFFIXES})     # review-r4#4: suffix set is coverage-affecting
    r = run_provider("horizontal.cloud_buckets", lambda: _enumerate(ctx), work_unit=wu)
    return len(r) if r else 0


def _enumerate(ctx) -> set:
    """C06: the bucket-enum body (run under run_provider). Records existing buckets as review candidates and
    returns the set of existing-bucket URLs. Candidates over the `_MAX_NAMES` cap AND probes that were
    INDETERMINATE (transport/other errors — not confirmed absences) are surfaced as STRUCTURED coverage, so a
    capped or partly-unreachable enum is an honest gap the verdict sees, not silent."""
    sid = "horizontal.cloud_buckets"
    all_names = _all_candidates(ctx.profile)
    names = all_names[:_MAX_NAMES]
    total_probes = len(names) * len(_PROVIDERS)
    found_urls: set = set()
    indeterminate = 0
    for n in names:
        for prov, urlf in _PROVIDERS:
            url = urlf(n)
            exists, access = _check(url)
            if exists is None:                              # couldn't determine — count it, never a silent absence
                indeterminate += 1
                continue
            if exists:
                ctx.run.add("review", {
                    "id": f"cloud:{url}", "klass": "cloud", "value": url,
                    "provider": prov, "access": access,
                    "note": f"{prov} bucket exists ({access}) — VERIFY OWNERSHIP",
                    "sources": ["cloud-enum"]})
                found_urls.add(url)
    # review#4: STRUCTURED coverage (eligible/tested/omitted + stable unit) so the VERDICT actually sees it —
    # an unstructured reason-only event is dropped by _read_coverage. Emit BOTH units EVERY run (omitted=0 when
    # clean) so a later clean rerun CLEARS a prior gap (latest-per-unit reconciliation).
    events.coverage_partial(sid, kind=events.COVERAGE_CAP, measure="bucket_names", unit="cloud.bucket_names",
                            eligible=len(all_names), tested=len(names), omitted=len(all_names) - len(names),
                            reason=f"bucket-name candidates {len(names)}/{len(all_names)} probed (cap {_MAX_NAMES})")
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="bucket_probes", unit="cloud.bucket_probes",
                            eligible=total_probes, tested=total_probes - indeterminate, omitted=indeterminate,
                            reason=(f"{indeterminate}/{total_probes} bucket probe(s) indeterminate "
                                    f"(transport/other error) — not confirmed absent"))
    return found_urls
