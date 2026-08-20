"""Cloud-asset discovery — candidate bucket enumeration (S3 + GCS) from the target's apex/org.

Detects bucket existence and public/private via an unauth, non-mutating GET (status only — no content
is read, downloaded, or modified) and emits candidates tagged "VERIFY OWNERSHIP" for human review; a
guessed name is not proof of ownership. Object storage only — Azure tenancy is handled by azmap.
"""
from __future__ import annotations

import re
import socket
import urllib.error

from . import events, fetch, policy

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


def _check(ctx, url: str, timeout: int = 8):
    """Return (exists, access) from a status-only GET (body never read): exists True (200 public /
    403 private), False (404 absent), or None when indeterminate (transport error or non-definitive
    HTTP code). An indeterminate probe is never recorded as a confirmed absence."""
    try:
        _location, status = fetch.redirect_location(
            ctx, url, timeout=timeout, source_id="horizontal.cloud_buckets",
        )
        if status == 403:
            return True, "private"
        if status == 404:
            return False, None                              # NoSuchBucket — definitively absent
        if status == 200:
            return True, "public"
        if status:
            return None, None                               # other HTTP status is indeterminate
        return None, None
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError):
        return None, None                                   # transport error — indeterminate, not absent


def discover(ctx) -> int:
    """Enumerate S3/GCS bucket candidates and record existing ones as `cloud` review candidates
    (verify-ownership); returns the count found. Skipped in passive. Runs under the provider contract
    (source_id `horizontal.cloud_buckets`) for a tool_start/tool_finish lifecycle."""
    if ctx.profile.passive_only:
        return 0
    from .contract import run_provider
    # stable work_unit from the bounded inputs (seeds) + effective config — the resume key
    wu = events.work_unit("horizontal.cloud_buckets",
                          inputs={"seeds": sorted(_seeds(ctx.profile))},
                          config={"providers": [p for p, _ in _PROVIDERS],
                                  "name_cap": policy.limit("CLOUD_NAME_CAP"),
                                  "suffixes": _SUFFIXES})     # suffix set is coverage-affecting
    r = run_provider("horizontal.cloud_buckets", lambda: _enumerate(ctx), work_unit=wu)
    return len(r) if r else 0


def _enumerate(ctx) -> set:
    """Probe the candidate buckets (under run_provider), record existing ones as review candidates,
    and return the set of existing-bucket URLs. Names over the cap and indeterminate probes are
    emitted as structured coverage so a capped or partly-unreachable enum is a visible gap."""
    sid = "horizontal.cloud_buckets"
    all_names = _all_candidates(ctx.profile)
    cap = policy.limit("CLOUD_NAME_CAP")        # 0 = every candidate name (`--unbound`)
    names = all_names if not cap else all_names[:cap]
    total_probes = len(names) * len(_PROVIDERS)
    found_urls: set = set()
    indeterminate = 0
    for n in names:
        for prov, urlf in _PROVIDERS:
            url = urlf(n)
            exists, access = _check(ctx, url)
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
    # emit both units every run (omitted=0 when clean) so a later clean rerun clears a prior gap
    events.coverage_partial(sid, kind=events.COVERAGE_CAP, measure="bucket_names", unit="cloud.bucket_names",
                            eligible=len(all_names), tested=len(names), omitted=len(all_names) - len(names),
                            reason=f"bucket-name candidates {len(names)}/{len(all_names)} probed (cap {_MAX_NAMES})")
    events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="bucket_probes", unit="cloud.bucket_probes",
                            eligible=total_probes, tested=total_probes - indeterminate, omitted=indeterminate,
                            reason=(f"{indeterminate}/{total_probes} bucket probe(s) indeterminate "
                                    f"(transport/other error) — not confirmed absent"))
    return found_urls
