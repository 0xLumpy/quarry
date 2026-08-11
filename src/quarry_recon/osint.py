"""OSINT pre-flight (`quarry osint`): discover scope candidates and attack-surface intel from a target
profile's anchors, score them, and write a review-only workspace under <project>/osint/<ts>/.

Never edits scope — candidates are review-only. Coverage verdict and provider taxonomy:
docs/design/PROVIDER-QUOTA-DESIGN.md.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import contextlib
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import budget, events, osint_report, privfs, secrets, settings, whoxy_page
from .contract import (PROVIDER_PARSE, PROVIDER_TRANSPORT, ProviderBodyError, capture_error_body,
                       provider_error_class, whoxy_envelope)
from .runner import RunResult, Status, fresh_artifact_dir, have, run as exec_tool, skipped

#: organizations one ASRank name search materialises — a throughput bound (0 = every match), in
#: `policy.BOUNDS`. See docs/design/PROVIDER-QUOTA-DESIGN.md.
ASRANK_ORGS = 10
#: CAIDA ASRank — free, keyless, public. GraphQL only.
_ASRANK_URL = "https://api.asrank.caida.org/v2/graphql"
#: member ASNs one org query requests; an org holding more is re-queried for its own count.
_ASRANK_ASN_PAGE = 200

#: resolved addresses the RDAP lane looks up per session — a throughput bound (0 = all), in
#: `policy.BOUNDS`. See docs/design/PROVIDER-QUOTA-DESIGN.md.
RDAP_LOOKUPS = 20

# Full email (no inner capture group) — findall returns the whole address.
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()
_DMARC_PROCESSORS = ("dmarcian", "proofpoint", "agari", "valimail", "easydmarc",
                     "ondmarc", "mxtoolbox", "fraudmarc", "dmarcadvisor", "redsift")

# source reliability for confidence scoring
_RELIABLE = {"whoxy-revwhois": 2, "azmap-tenant": 2, "azmap-tenant-email": 2, "asnmap": 1,
             "dmarc": 1, "dmarc-3rdparty": 0}
_HINT_RANK = {"noise": 0, "verify-ownership": 1, "related": 2, "in-scope-likely": 3}

# sources automation can't reach — shown verbatim in the report's manual section
MANUAL_TODO = [
    ("ASN / IP ranges", "bgp.he.net (search org + free-form description), asrank.caida.org, "
     "ARIN/RIPE full-text — confirm ownership, then add to CIDR/ASN"),
    ("Acquisitions / subsidiaries", "Crunchbase, Tracxn, Pitchbook, OCCRP Aleph, SEC-API — "
     "acquired brands become new APEX_DOMAINS (confirm program scope)"),
    ("Ad/analytics relationships", "builtwith.com Relationships tab — shared GA/NewRelic codes"),
    ("Cloud cert sweep", "Caduceus on owned ASN ranges + merklemap.com (run during recon once "
     "CIDR confirmed)"),
]


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "quarry-osint"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _http_post_json(url: str, payload: dict, timeout: int = 25) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": "quarry-osint",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        doc = json.loads(r.read().decode("utf-8", "replace"))
    if isinstance(doc, dict) and doc.get("errors"):
        raise ValueError("; ".join(str(e.get("message", e)) for e in doc["errors"])[:300])
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), dict):
        raise ValueError("response carried no data object")
    return doc["data"]


class OsintSession:
    """OSINT workspace: candidates + intel + raw evidence under <project>/osint/<ts>/."""

    def __init__(self, project_dir: Path, target: str, ts: str | None = None):
        self.project_dir = Path(project_dir)
        self.target = target
        self.ts = ts or time.strftime("%Y%m%d-%H%M%S")
        self.dir = self.project_dir / "osint" / self.ts
        self.raw = self.dir / "raw"
        privfs.private_dir(self.raw)                         # osint/ session tree is 0700
        self.started = _utc()
        self._cands: dict[tuple, dict] = {}     # (type, value) -> candidate
        self._intel: list[dict] = []
        self._tool_runs: list[dict] = []
        self._lane_failures: list[dict] = []    # native lanes that only echo (azmap/whois/dmarc/rdap)
        self.notes: list[str] = []

    def raw_path(self, source: str, name: str) -> Path:
        from .repository_identity import validate_artifact_component
        source = validate_artifact_component(source, "OSINT source")
        name = validate_artifact_component(name, "OSINT raw filename")
        p = self.raw / source
        privfs.private_dir(p)                                # 0700 raw evidence dir
        return p / name

    def record(self, result) -> None:
        # redact secret values from the recorded command/note (same choke point as store.Run.record)
        entry = {"tool": result.tool, "status": str(result.status.value),
                 "note": secrets.redact(result.note),
                 "cmd": secrets.redact(" ".join(result.cmd))}
        # carry the structured outcome into the manifest: a limit recorded only as prose cannot be
        # acted on
        meta = getattr(result, "meta", None)
        if isinstance(meta, dict) and meta:
            # redacted too: a machinery reason can carry an exception string carrying a key
            entry["outcome"] = secrets.redact_deep(dict(meta))
        self._tool_runs.append(entry)

    def candidate(self, value: str, ctype: str, source: str, scope_hint: str, reason: str,
                  raw_ref: str | None = None, manual_followup: str | None = None) -> None:
        value = (value or "").strip().rstrip(".")
        if ctype == "apex":                 # only host-like values are case-normalized; keep org casing
            value = value.lower()
        if not value or (ctype == "apex" and "." not in value):
            return
        key = (ctype, value)
        c = self._cands.get(key)
        if c:
            if source not in c["sources"]:
                c["sources"].append(source)
            if raw_ref and raw_ref not in c["raw_refs"]:
                c["raw_refs"].append(raw_ref)
            if _HINT_RANK.get(scope_hint, 0) > _HINT_RANK.get(c["scope_hint"], 0):
                c["scope_hint"], c["reason"] = scope_hint, reason
        else:
            self._cands[key] = {"value": value, "type": ctype, "sources": [source],
                                "scope_hint": scope_hint, "reason": reason,
                                "raw_refs": [raw_ref] if raw_ref else [],
                                "manual_followup": manual_followup}

    def intel(self, kind: str, value: str, source: str, **provenance) -> None:
        """One intel row; `provenance` records where the value came from."""
        self._intel.append({"kind": kind, "value": value, "sources": [source],
                            **{k: v for k, v in provenance.items() if v not in (None, "")}})

    def _confidence(self, sources: list[str]) -> str:
        score = sum(_RELIABLE.get(s, 1) for s in sources)
        return "high" if score >= 2 else "med" if score == 1 else "low"

    def candidates(self) -> list[dict]:
        out = []
        for c in self._cands.values():
            c = dict(c)
            c["confidence"] = self._confidence(c["sources"])
            out.append(c)
        rank = {"in-scope-likely": 0, "related": 1, "verify-ownership": 2, "noise": 3}
        out.sort(key=lambda c: (rank.get(c["scope_hint"], 9),
                                {"high": 0, "med": 1, "low": 2}[c["confidence"]], c["value"]))
        return out

    def note_failure(self, tool: str, why: str) -> None:
        """Record a native-lane failure so a session where half the lanes broke does not report clean."""
        self._lane_failures.append({"tool": tool, "why": secrets.redact(str(why))})

    def outcome(self) -> dict:
        """The session's own coverage verdict — limits and gaps recorded independently, gaps dominating. See
        docs/design/PROVIDER-QUOTA-DESIGN.md.
        """
        limits, operator_limits, gaps = [], [], list(self._lane_failures)
        for tr in self._tool_runs:
            out = tr.get("outcome") or {}
            entry = {"tool": tr["tool"], "why": tr.get("note", ""), **out}
            # a limit and a gap are independent facts and one result can carry both; provider and
            # operator limits stay on separate lists. Never `elif` these.
            if out.get("provider_limit"):
                limits.append(entry)
            if out.get("operator_limit"):
                operator_limits.append(entry)
            if (out.get("failed") or out.get("truncated_pages")
                    or tr.get("status") in ("failed", "partial", "timed_out", "blocked")):
                gaps.append(entry)
        # gaps dominate: a limit may only lift an otherwise-clean session
        verdict = ("complete_with_gaps" if gaps
                   else "complete_with_limits" if (limits or operator_limits) else "complete")
        return {"verdict": verdict, "provider_limits": limits,
                "operator_limits": operator_limits, "gaps": gaps}

    def finalize(self, profile) -> Path:
        cands = self.candidates()
        # OSINT evidence is private (0600): candidate/intel values can name a target's private assets
        privfs.write_private(self.dir / "candidates.jsonl",
                             "\n".join(json.dumps(c, ensure_ascii=False) for c in cands) + ("\n" if cands else ""))
        privfs.write_private(self.dir / "intel.jsonl",
                             "\n".join(json.dumps(i, ensure_ascii=False) for i in self._intel) + ("\n" if self._intel else ""))
        privfs.write_private(self.dir / "manifest.json", json.dumps({
            "target": self.target, "ts": self.ts, "started": self.started, "finished": _utc(),
            "profile_anchors": {"apex": profile.apex_domains, "asn": profile.asn,
                                "org_names": profile.org_names, "brands": profile.brands},
            "tool_runs": self._tool_runs, "candidate_count": len(cands),
            "intel_count": len(self._intel), "notes": self.notes,
            "summary": self.outcome(),
        }, indent=2))
        report = osint_report.render(self, profile, cands, self._intel, MANUAL_TODO)
        privfs.write_private(self.dir / "osint-report.md", report)
        privfs.write_private(self.dir / "target.suggested.yaml",
                             osint_report.suggested_yaml(profile, cands))
        # latest pointer (per-project)
        link = self.project_dir / "osint" / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            os.symlink(self.dir.resolve(), link)
        except OSError:
            privfs.write_private(self.project_dir / "osint" / "latest.txt", str(self.dir.resolve()))
        return self.dir / "osint-report.md"


# ── sources ──────────────────────────────────────────────────────────────────

def _azmap(s: OsintSession, apex: str, echo, timeout: int) -> None:
    try:
        data = _http(f"https://azmap.dev/api/tenant?domain={apex}&extract=true",
                     timeout=min(timeout, 30))
        raw = s.raw_path("azmap", f"{apex}.json")
        privfs.write_private(raw, data)
        obj = json.loads(data)
        # union, not `or`: related and e-mail domains are both evidence, with different reasons
        related = [d for d in (obj.get("related_domains") or []) if d != apex]
        by_email = [d for d in (obj.get("email_domains") or []) if d != apex]
        # distinct source ids: a domain in both lists then carries both in `sources`, reached two ways
        for d in related:
            s.candidate(d, "apex", "azmap-tenant", "related",
                        f"M365 tenant of {apex}", raw_ref=str(raw))
        for d in by_email:
            s.candidate(d, "apex", "azmap-tenant-email", "related",
                        f"M365 tenant e-mail domain of {apex}", raw_ref=str(raw))
        if obj.get("tenant_name"):
            s.candidate(obj["tenant_name"], "org", "azmap-tenant", "related",
                        f"M365 tenant name for {apex}", raw_ref=str(raw))
        echo(f"  azmap[{apex}]: {len(related)} related + {len(by_email)} e-mail domain(s)")
    except Exception as e:
        echo(f"    azmap[{apex}]: {e}")
        s.note_failure("azmap", f"{apex}: {e}")


def _whois(s: OsintSession, apex: str, echo, timeout: int) -> set[str]:
    """Returns registrant emails for whoxy reverse-whois."""
    emails: set[str] = set()
    try:
        p = subprocess.run(["whois", apex], capture_output=True, text=True,
                           timeout=min(timeout, 30), stdin=subprocess.DEVNULL)
        raw = s.raw_path("whois", f"{apex}.txt")
        privfs.write_private(raw, p.stdout)
        # `whois` can exit nonzero without raising, so the exit code is checked separately
        if p.returncode != 0:
            s.note_failure("whois", f"{apex}: exit {p.returncode} "
                                    f"{(p.stderr or '').strip().splitlines()[:1]}")
        for line in p.stdout.splitlines():
            low = line.lower()
            if "registrant organization" in low or "registrant org" in low:
                org = line.split(":", 1)[-1].strip()
                if org:
                    s.candidate(org, "org", "whois", "related",
                                f"registrant org of {apex}", raw_ref=str(raw))
        for email in _EMAIL_RE.findall(p.stdout):       # full emails now
            email = email.lower()
            if "abuse" not in email and "registrar" not in email:
                emails.add(email)
    except Exception as e:
        echo(f"    whois[{apex}]: {e}")
        s.note_failure("whois", f"{apex}: {e}")
    return emails


def _dmarc(s: OsintSession, apex: str, echo, timeout: int) -> None:
    try:
        p = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{apex}"],
                           capture_output=True, text=True, timeout=min(timeout, 15),
                           stdin=subprocess.DEVNULL)
        raw = s.raw_path("dmarc", f"{apex}.txt")
        privfs.write_private(raw, p.stdout)
        if p.returncode != 0:                          # dig exits nonzero without raising
            s.note_failure("dmarc", f"{apex}: dig exit {p.returncode}")
        for email in _EMAIL_RE.findall(p.stdout):       # rua/ruf mailto addresses
            dom = _email_domain(email)                  # the reporting domain is the candidate
            if not dom or dom == apex:
                continue
            third = any(proc in dom for proc in _DMARC_PROCESSORS)
            s.candidate(dom, "apex", "dmarc-3rdparty" if third else "dmarc",
                        "noise" if third else "related",
                        f"DMARC rua/ruf of {apex}" + (" (3rd-party processor)" if third else ""),
                        raw_ref=str(raw))
    except Exception as e:
        echo(f"    dmarc[{apex}]: {e}")
        s.note_failure("dmarc", f"{apex}: {e}")


def _whoxy_get(url: str, timeout: int):
    raw = b""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "quarry-osint"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except Exception as e:
        # capture the failure bytes: Whoxy usually answers failure inside a 200, but when it does
        # not, these are the evidence
        capture_error_body(e, provider="whoxy")
        # the exact bytes: `body_text` is a lossy decode
        body = getattr(e, "body_bytes", None)
        if body:
            raw = body
        try:
            e.error_class = provider_error_class(e)
        except Exception:
            pass
        return raw, e
    return raw, None


def _balance_from_error(err) -> "whoxy_page.BalanceRead":
    """A failed balance request as a balance outcome — refused only when the provider answered or a limit
    was proven. See docs/design/PROVIDER-QUOTA-DESIGN.md.
    """
    cls = provider_error_class(err) or PROVIDER_TRANSPORT
    from .contract import PROVIDER_LIMITS
    answered = isinstance(err, (urllib.error.HTTPError, ProviderBodyError))
    refused = cls in PROVIDER_LIMITS or (answered and cls != PROVIDER_PARSE)
    return whoxy_page.BalanceRead(error_class=cls, reason=str(err) or "balance request failed",
                                  refused=refused)


def _whoxy(s: OsintSession, emails: set[str], org_names: list[str], echo, timeout: int) -> None:
    """Reverse-whois by registrant email and by org name: paginated, budgeted and resumable, one credit per
    page. There is no first-N cap on anchors — ordering decides what is asked first, the balance and reserve
    decide how much.
    """
    # a third door into a provider, outside `run_contract`: a closed campaign must not buy through it
    from . import campaign as _campaign
    _allowed, _why = _campaign.acquisition_allowed("osint.whoxy")
    if not _allowed:
        events.tool_blocked("osint.whoxy", reason=_why)
        s.record(skipped("whoxy-revwhois", _why))
        return
    key = secrets.whoxy()
    if not key:
        s.record(skipped("whoxy", "no Whoxy key in secrets.yaml"))
        return
    # order, not membership: registrant emails are the stronger ownership signal, so they go first
    anchors = [whoxy_page.Anchor("email", e) for e in sorted(emails)]
    anchors += [whoxy_page.Anchor("company", o) for o in sorted(org_names or [])]
    if not anchors:
        s.record(skipped("whoxy", "no registrant email / org-name anchors to pivot on"))
        return

    # raw, not `concurrency()`: a spending control must see what the operator wrote, not a clamped 1
    reserve = settings.raw("WHOXY_CREDIT_RESERVE", 0)
    run_budget = settings.raw("WHOXY_PAGE_BUDGET", 0)
    states = [whoxy_page.AnchorState(a) for a in anchors]
    labels = {("email", a.value): f"registrant email {a.value}" for a in anchors}
    labels.update({("company", a.value): f"org name '{a.value}'" for a in anchors})
    seen: dict = {"policy": None, "balance": None}

    def fetch(anchor, page):
        """One page as the paginator's `(raw_bytes, error)`. Whoxy reports failure inside an HTTP 200, so the
        status envelope classifies here.
        """
        q = urllib.parse.quote(anchor.value)
        raw, err = _whoxy_get(f"https://api.whoxy.com/?key={key}&reverse=whois&{anchor.param}={q}"
                              f"&page={page}", min(timeout, 60))
        if err is not None:
            return raw, err
        try:
            whoxy_envelope(json.loads(raw.decode("utf-8", "replace")))
        except ProviderBodyError as e:
            return raw, e
        except Exception:
            return raw, ProviderBodyError(PROVIDER_PARSE, "response was not JSON", "whoxy")
        return raw, None

    def ingest(anchor, page, doc, art):
        label = labels.get((anchor.param, anchor.value), f"{anchor.param} {anchor.value}")
        for d in doc.get("rows") or []:
            s.candidate(d, "apex", "whoxy-revwhois", "in-scope-likely",
                        f"reverse-whois on {label}", raw_ref=str(art))
        return len(doc.get("rows") or [])

    @contextlib.contextmanager
    def paid():
        """The account-wide spend lock, the free balance read, and the settled allowance in that order,
        entered only when pending work remains.
        """
        with whoxy_page.spend_lock():
            raw, err = _whoxy_get(f"https://api.whoxy.com/?key={key}&account=balance", min(timeout, 30))
            if err is None:
                bal = whoxy_page.read_balance(raw.decode("utf-8", "replace"))
            else:
                bal = _balance_from_error(err)
            pol = whoxy_page.spend_policy(bal, reserve, run_budget)
            seen["balance"], seen["policy"] = bal, pol
            echo(f"  whoxy: balance {bal.remaining if bal.remaining is not None else '?'}"
                 f" · reserve {reserve} · budget {pol.pages if pol.pages is not None else 'unbounded'}")
            yield pol.pages

    try:
        with whoxy_page.open_state(s.project_dir) as (ledger, pages_dir):
            attempt = fresh_artifact_dir(pages_dir)
            out = whoxy_page.run_pages(states, paid=paid, fetch=fetch, ingest=ingest,
                                       read=whoxy_page.read_page, ledger=ledger, attempt_dir=attempt)
    except (KeyboardInterrupt, SystemExit):
        raise                                    # cancellation ends the run; it is not a lane outcome
    except whoxy_page.LockBusy as e:
        # another run holds the page state: a gap, not a skip — nothing read, nothing spent
        echo(f"  whoxy: {e}")
        s.record(RunResult("whoxy", ["whoxy", "reverse=whois"], Status.BLOCKED, None, 0.0, None, 0,
                           note=f"another run holds this project's whoxy page state — {e}",
                           meta={"eligible": len(anchors), "attempted": 0, "completed": 0,
                                 "coverage_incomplete": True}))
        return
    except Exception as e:
        # best-effort: a page-state machinery failure is this lane's gap, not the session's
        echo(secrets.redact(f"  whoxy: {e}"))
        s.record(RunResult("whoxy", ["whoxy", "reverse=whois"], Status.FAILED, None, 0.0, None, 0,
                           note=f"whoxy page state is unusable: {e}",
                           meta={"eligible": len(anchors), "attempted": 0, "completed": 0,
                                 "failed": 1, "not_sent": len(anchors), "truncated_pages": 0,
                                 "gap_reason": f"page state machinery failed: {e}",
                                 "provider_limit": False, "operator_limit": False,
                                 "coverage_incomplete": True}))
        return
    _whoxy_record(s, out, seen["policy"], anchors, echo)


def _whoxy_record(s: OsintSession, out, pol, anchors, echo) -> None:
    """Turn one paginator Outcome into this lane's terminal. Every fact is recorded independently and the
    status chosen afterward, gaps dominating limits.
    """
    # anchors we actually sent a request for
    attempted = len(out.requested)
    # pages and anchors are different units; an unopened anchor has no knowable page count
    pages_left, unopened = out.pages_left_known, len(out.unopened)
    # `failed` is what the session verdict folds in: parse failures, publish failures, unconsumed pages
    failed = sum(out.fail_classes.values()) + out.publish_failed + out.pages_unconsumed
    pol = pol or whoxy_page.SpendPolicy()

    limits = dict(out.limit_classes)
    limit_why = out.limit_reason or pol.limit
    gap_why = out.fail_reason or pol.gap
    # every real failure gets a reason, or the status could read success over it
    if out.publish_failed and not gap_why:
        gap_why = f"{out.publish_failed} page(s) could not be stored"
    if out.evidence_invalid and not gap_why:
        gap_why = f"{out.evidence_invalid} page(s) were unusable and were not owned"
    # a machinery failure is appended, not hidden behind an earlier provider one; each entry checks
    # whether it has already been said
    machinery_why = "; ".join(m for m in out.machinery if m not in gap_why)
    if machinery_why:
        gap_why = (f"{gap_why} · page state machinery also failed ({machinery_why})" if gap_why
                   else f"page state machinery failed ({machinery_why})")
    # an unconsumed page is owned and out of the page remainder, so it is stated here
    if out.pages_unconsumed:
        why = f"{out.pages_unconsumed} page(s) were read but not ingested"
        gap_why = f"{gap_why} · {why}" if gap_why else why
    if out.stop_cause in ("ledger_unwritable", "publish_failed", "scheduler_invariant"):
        gap_why = gap_why or f"page state machinery failed ({out.stop_cause})"
    if out.stop_cause == "account_busy":
        # another project holding the account is a gap, not a soft limit: nothing refused us
        gap_why = gap_why or "another project is spending this account; the remainder was not bought"
    if out.stop_cause.startswith("provider_stop:"):
        gap_why = gap_why or out.stop_cause
    if not out.persisted:
        gap_why = gap_why or "page state was NOT persisted — paid pages will be bought again"
    # a remainder is known pages or unopened anchors, kept as separate units
    has_remainder = bool(pages_left or unopened)
    left_desc = " and ".join(x for x in ((f"{pages_left} page(s)" if pages_left else ""),
                                         (f"{unopened} anchor(s)" if unopened else "")) if x)
    # provider and operator limits are independent; one run can hit both
    provider_why = out.limit_reason or pol.limit or ""
    operator_why = ""
    # a policy explains a remainder only when its allowance was actually spent, which the scheduler
    # counts
    bounded = has_remainder and out.allowance_exhausted
    if bounded and pol.stop_kind in ("operator_reserve", "run_budget"):
        operator_why = f"{left_desc} withheld by the operator ({pol.stop_kind})"
    elif bounded and pol.stop_kind == "provider_balance" and not provider_why:
        provider_why = f"{left_desc} not bought — the account balance is the boundary"
    provider_limit = bool(limits or pol.limit or provider_why)
    operator_limit = bool(operator_why)
    limit_why = limit_why or provider_why or operator_why

    # what was bought, in Whoxy's unit: replayed pages cost nothing, and requests are not the bill
    events.spend("osint.whoxy", provider="whoxy", measure="pages", amount=int(out.pages_bought))

    counts = (f"{attempted}/{out.anchors} anchor(s) attempted · {out.pages_bought} page(s) bought"
              f" · {out.pages_replayed} replayed · {out.domains} domain(s)"
              + (f" · {out.requests_issued} request(s) issued" if out.requests_issued else "")
              + (f" · {pages_left} page(s) remaining" if pages_left else "")
              + (f" · {unopened} anchor(s) never opened" if unopened else "")
              + (f" · {out.pages_unconsumed} page(s) not ingested" if out.pages_unconsumed else "")
              + (f" · {out.error_bodies} error body(ies) kept" if out.error_bodies else ""))
    # the balance outcome's class counts too: a lane stopped before its first page has no page class
    cls = next(iter(out.fail_classes), None) or next(iter(limits), None) or (pol.error_class or None)
    meta = {"eligible": out.anchors, "attempted": attempted, "completed": out.anchors_touched,
            # `truncated_pages` is a gap in the verdict, so only a remainder nothing else explains
            # belongs there — a quota is a soft limit, not a gap
            "failed": failed, "not_sent": unopened,
            "truncated_pages": pages_left if (gap_why and not limit_why) else 0,
            "pages_left": pages_left, "unopened_anchors": unopened,
            "pages_bought": out.pages_bought, "pages_replayed": out.pages_replayed,
            "requests_issued": out.requests_issued, "unopened": list(out.unopened),
            "domains": out.domains, "total_drift": out.total_drift, "persisted": out.persisted,
            "evidence_invalid": out.evidence_invalid, "spend_stop_kind": pol.stop_kind,
            "pages_unconsumed": out.pages_unconsumed, "machinery": list(out.machinery),
            "limit_reason": limit_why or None, "gap_reason": gap_why or None,
            "config_invalid": pol.invalid or None, "balance_invalid": pol.balance_invalid or None,
            # limit and gap recorded independently before any status is chosen; an operator boundary
            # is a limit the verdict must see
            "provider_limit": provider_limit, "operator_limit": operator_limit,
            "provider_limit_reason": provider_why or None,
            "operator_limit_reason": operator_why or None,
            # both, when both happened — a scalar origin could only ever name one of them.
            "limit_origin": ("+".join(k for k, on in (("provider", provider_limit),
                                                      ("operator", operator_limit)) if on) or None)}

    # gaps dominate: a limit only lifts an otherwise-clean lane. An unusable control outranks both.
    if pol.invalid:
        status, note = Status.FAILED, f"unusable spending control ({pol.invalid}) — no paid request issued"
        meta["coverage_incomplete"] = True
    elif gap_why:
        status = Status.PARTIAL if (out.domains or out.pages_replayed) else Status.FAILED
        note = gap_why
        meta["coverage_incomplete"] = True
    elif provider_limit or operator_limit:
        status = Status.LIMITED
        note = " · ".join(x for x in (provider_why, operator_why) if x) or f"provider limit {limits}"
        meta["coverage_incomplete"] = True
    else:
        status, note = Status.SUCCESS, counts
    if cls:
        meta["error_class"] = cls
    if status is not Status.SUCCESS:
        note = f"{note} — {counts}"
    echo(secrets.redact(f"  whoxy: {note}"))
    s.record(RunResult("whoxy", ["whoxy", "reverse=whois"], status,
                       0 if status is Status.SUCCESS else None, 0.0, None, out.domains,
                       note=note, meta=meta))


_ASRANK_ORG_Q = """
{ organizations(name: %(name)s, first: %(first)d, offset: %(offset)d) {
    totalCount
    edges { node { orgId orgName rank country { iso }
                   members { numberAsns asns(first: %(asns)d) { edges { node { asn asnName } } } } } } } }
"""
_ASRANK_MEMBERS_Q = """
{ organization(orgId: %(org)s) {
    orgName members { numberAsns asns(first: %(asns)d) { edges { node { asn asnName } } } } } }
"""


#: the widest 32-bit AS number; AS0 is reserved, so a valid ASN is 1..4294967295
_ASN_MAX = 2 ** 32 - 1


def _exact_count(value) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _asn_number(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v.isascii() or not v.isdigit() or v != str(int(v)):
        return None
    n = int(v)
    return v if 0 < n <= _ASN_MAX else None


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _readable(value, want) -> bool:
    return value is None or isinstance(value, want)


def _asrank_orgs(name: str, limit: int, timeout: int, save) -> tuple[list, int | None, int | None]:
    """`(organizations, total_matches, provider_short)` for one org-name search; `total` and `short` are None
    when the provider count could not be read. Pages until it has what the bound allows, saving each
    response as its own artifact.
    """
    page = max(1, min(limit, 50)) if limit > 0 else 50
    nodes: list = []
    total, offset, guard = None, 0, 0
    while True:
        data = _http_post_json(_ASRANK_URL, {"query": _ASRANK_ORG_Q % {
            "name": json.dumps(name), "first": page, "offset": offset,
            "asns": _ASRANK_ASN_PAGE}}, timeout=timeout)
        orgs = (data.get("organizations") or {})
        ref = save(f"orgs-{offset:05d}", data)
        if total is None:
            total = _exact_count(orgs.get("totalCount"))
        got = [dict(e["node"], _ref=ref) for e in (orgs.get("edges") or [])
               if isinstance(e, dict) and isinstance(e.get("node"), dict)]
        nodes += got
        offset += len(got)
        guard += 1
        want = (total if total is not None else len(nodes)) if limit <= 0 else \
            min(limit, total if total is not None else limit)
        if not got or len(nodes) >= want or guard >= 40:
            break
    if total is None:
        # an unreadable denominator is unknown, never `len(nodes)`: that would compute a zero shortfall
        return (nodes if limit <= 0 else nodes[:limit]), None, None
    allowed = total if limit <= 0 else min(limit, total)
    return nodes[:allowed], total, max(0, allowed - len(nodes))


def _asrank_asns(node: dict, timeout: int, save) -> tuple[list, str, str]:
    """`(member ASNs, shortfall reason, artifact)` for one organisation. A page returning fewer than
    `numberAsns` is re-requested for exactly that count.
    """
    members = _obj(node.get("members"))
    edges = (_obj(members.get("asns")).get("edges") or [])
    asns = [e["node"] for e in edges if isinstance(e, dict) and isinstance(e.get("node"), dict)]
    ref = node.get("_ref", "")
    declared = _exact_count(members.get("numberAsns"))
    if declared is None:
        return asns, f"{_text(node.get('orgName')) or '?'}: unreadable member count", ref
    if declared > len(asns) and node.get("orgId"):
        try:
            data = _http_post_json(_ASRANK_URL, {"query": _ASRANK_MEMBERS_Q % {
                "org": json.dumps(node["orgId"]), "asns": declared}}, timeout=timeout)
            ref = save(f"members-{re.sub(r'[^A-Za-z0-9]', '_', str(node['orgId']))[:40]}", data)
            more = _obj(_obj(_obj(data.get("organization")).get("members")).get("asns"))
            asns = [e["node"] for e in (more.get("edges") or [])
                    if isinstance(e, dict) and isinstance(e.get("node"), dict)]
        except Exception as e:                                   # noqa: BLE001
            return asns, f"{_text(node.get('orgName')) or '?'}: {len(asns)}/{declared} member ASNs ({e})", ref
    if declared > len(asns):
        return asns, f"{_text(node.get('orgName')) or '?'}: {len(asns)}/{declared} member ASNs", ref
    return asns, "", ref


def _asrank(s: OsintSession, profile, echo, timeout: int) -> None:
    """Org name -> CAIDA ASRank -> ASN and related-org candidates (review-only). ASRank's org search is
    fuzzy, so every result is `verify-ownership`. ORG_NAMES only; brands would match half the internet.
    """
    from . import policy
    if not profile.org_names:
        s.record(skipped("asrank", "no ORG_NAMES anchor to search (add one to target.yaml)"))
        return
    cap = policy.limit("ASRANK_ORGS")
    n_orgs = n_asns = withheld = provider_short = bad_asns = bad_orgs = bad_fields = 0
    short: list = []
    failed = unknown_total = 0
    seq = {"n": 0}                 # run-wide, so no two responses in this lane share a filename
    for name in profile.org_names:
        # the slug is for humans; the digest makes it unique, or two names collide onto one artifact
        slug = (re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40] + "-"
                + hashlib.sha256(name.encode("utf-8")).hexdigest()[:8])

        def save(kind: str, doc: dict, _slug=slug) -> str:
            """One immutable artifact per response, so a candidate always cites the file that contains it."""
            seq["n"] += 1
            raw = s.raw_path("asrank", f"{_slug}.{seq['n']:03d}-{kind}.json")
            privfs.write_private(raw, json.dumps(doc, indent=2, ensure_ascii=False))
            return str(raw)

        try:
            orgs, total, missing = _asrank_orgs(name, cap, timeout=min(timeout, 30), save=save)
        except Exception as e:                                   # noqa: BLE001
            failed += 1
            echo(f"    asrank[{name}]: {e}")
            s.note_failure("asrank", f"{name}: {e}")
            continue
        # our bound and their shortfall are different facts; blaming our cap for what the provider
        # never sent is the same blame-shift, reversed
        if total is None:
            unknown_total += 1
            s.note_failure("asrank", f"{name}: the provider's match count was unreadable — coverage of "
                                     f"this anchor is UNKNOWN, not complete")
        else:
            withheld += max(0, total - (total if cap <= 0 else min(cap, total)))
            if missing:
                provider_short += missing
                s.note_failure("asrank", f"{name}: provider returned {missing} fewer organisation(s) "
                                         f"than the {min(cap, total) if cap > 0 else total} it admitted to")
        for node in orgs:
            try:
                raw_name, raw_country = node.get("orgName"), node.get("country")
                # the leaf carries the evidence: an unreadable container makes the leaf unreachable
                # (absent), not discarded, so it is counted once
                raw_iso = _obj(raw_country).get("iso") if isinstance(raw_country, dict) else None
                for field, value, want in (("orgName", raw_name, str),
                                           ("country", raw_country, dict),
                                           ("country.iso", raw_iso, str)):
                    if not _readable(value, want):
                        # a discarded field is counted: a lane may not report success over evidence
                        # it could not read
                        bad_fields += 1
                        s.note_failure("asrank", f"{name}: unreadable {field} on organisation "
                                                 f"{_text(raw_name) or node.get('orgId') or '?'} "
                                                 f"({type(value).__name__})")
                org_name = _text(raw_name)
                iso = _text(raw_iso)
                asns, shortfall, asn_ref = _asrank_asns(node, timeout=min(timeout, 30), save=save)
            except Exception as e:                               # noqa: BLE001
                # one unreadable row may not cost the lane its terminal
                bad_orgs += 1
                s.note_failure("asrank", f"{name}: unreadable organisation row ({type(e).__name__})")
                continue
            if org_name:
                n_orgs += 1
                s.candidate(org_name, "org", "asrank", "verify-ownership",
                            f"CAIDA ASRank organisation matching {name!r}"
                            + (f" (rank {node['rank']}" if node.get("rank") else " (")
                            + (f", {iso})" if iso else ")"),
                            raw_ref=node.get("_ref"),
                            manual_followup="confirm this org IS the target (ASRank name search is fuzzy)")
            if shortfall:
                short.append(shortfall)
            for a in asns:
                num = _asn_number(a.get("asn"))
                if num is None:
                    # a discarded ASN row is counted: a partly-unreadable response may not finish
                    # success
                    bad_asns += 1
                    continue
                n_asns += 1
                s.candidate(f"AS{num}", "asn", "asrank", "verify-ownership",
                            f"member ASN of {org_name or name} ({_text(a.get('asnName')) or 'unnamed'}) "
                            f"per CAIDA ASRank",
                            raw_ref=asn_ref,
                            manual_followup="verify ownership on bgp.he.net / RDAP before adding — an "
                                            "ASN in the profile authorises active range scanning")
        echo(f"  asrank[{name}]: {len(orgs)}/{total if total is not None else '?'} org(s), "
             f"{n_asns} member ASN(s)")

    note = f"{n_orgs} org(s), {n_asns} ASN(s) from {len(profile.org_names)} anchor(s)"
    meta = {"orgs": n_orgs, "asns": n_asns, "withheld_orgs": withheld, "measure": "organizations",
            "bound": cap, "provider_short_orgs": provider_short,
            "unknown_total_anchors": unknown_total, "unreadable_asn_rows": bad_asns,
            "unreadable_org_rows": bad_orgs, "unreadable_fields": bad_fields}
    if withheld:
        meta["operator_limit"] = True
        note += (f" — {withheld} matching org(s) withheld by the ASRANK_ORGS={cap} bound "
                 f"(`quarry osint --unbound` searches every match)")
    if provider_short:
        note += f" — {provider_short} admitted org(s) the provider did not return"
    if unknown_total:
        note += f" — {unknown_total} anchor(s) with an UNREADABLE match count (coverage unknown)"
    if bad_asns:
        note += f" — {bad_asns} unreadable ASN row(s) discarded"
    if bad_orgs:
        note += f" — {bad_orgs} unreadable organisation row(s) discarded"
    if bad_fields:
        note += f" — {bad_fields} unreadable field(s) on otherwise usable organisation(s)"
    if short:
        meta["incomplete_members"] = short[:8]
        note += f" — member ASNs incomplete for {len(short)} org(s)"
    if failed:
        meta["failed"] = True
    s.record(RunResult("asrank", ["asrank", f"orgs={cap or 'unbounded'}"],
                       Status.FAILED if failed and not n_orgs
                       else Status.PARTIAL if (failed or short or provider_short or unknown_total
                                               or bad_asns or bad_orgs or bad_fields)
                       else Status.SUCCESS if n_asns or n_orgs else Status.EMPTY,
                       0, 0.0, None, n_asns, note=note, meta=meta))


def _asn_expand(s: OsintSession, profile, echo, timeout: int) -> None:
    if not profile.asn or not have("asnmap"):
        return
    raw = s.raw_path("asnmap", "ranges.txt")
    r = exec_tool("asnmap", ["asnmap", "-silent"], stdin_data="\n".join(profile.asn),
                  raw_path=raw, timeout=min(timeout, 120))
    s.record(r)
    if r.raw_path:
        for line in r.raw_path.read_text().splitlines():
            line = line.strip()
            if "/" in line:
                s.candidate(line, "cidr", "asnmap", "verify-ownership",
                            "expanded from profile ASN seed — confirm ownership before scanning",
                            raw_ref=str(raw),
                            manual_followup="verify ownership on bgp.he.net / RDAP before adding")


#: strips porch-pirate's ANSI colouring; the globals view has no plain-text or JSON mode.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _porch_globals(text: str) -> list[dict]:
    """`{author, key, value}` per workspace global, from the tool's coloured output. The value is preserved
    exactly — a Postman global is where a workspace leaks its API keys.
    """
    out: list = []
    author = ""
    pending_key = None
    for line in _ANSI_RE.sub("", text).splitlines():
        line = line.strip()
        if line.startswith("- Author:"):
            author, pending_key = line.split(":", 1)[1].strip(), None
        elif line.startswith("- Key:"):
            pending_key = line.split(":", 1)[1].strip()
        elif line.startswith("- Value:") and pending_key is not None:
            out.append({"author": author, "key": pending_key,
                        "value": line.split(":", 1)[1].strip()})
            pending_key = None
    return out


def _porch_pirate(s: OsintSession, apex: str, echo, timeout: int) -> None:
    """Public Postman leaks -> intel. Two views: `--urls` gives endpoints, `--globals` gives workspace global
    variables. Both are intel, never scope; a global with an empty value is still recorded.
    """
    pp = s.raw_path("porch-pirate", f"{apex}.txt")
    r = exec_tool("porch-pirate", ["porch-pirate", "-s", apex, "--urls"],
                  raw_path=pp, timeout=timeout)
    s.record(r)
    n_urls = 0
    if r.raw_path:
        for u in sorted(set(re.findall(r"https?://[^\s\"'<>]+", r.raw_path.read_text()))):
            s.intel("postman-endpoint", u, "porch-pirate")
            n_urls += 1

    gl = s.raw_path("porch-pirate", f"{apex}.globals.txt")
    rg = exec_tool("porch-pirate", ["porch-pirate", "-s", apex, "--globals"],
                   raw_path=gl, timeout=timeout)
    s.record(rg)
    n_globals = 0
    if rg.raw_path:
        for g in _porch_globals(rg.raw_path.read_text()):
            # verbatim, with the workspace author as its own field: `apiKey=…` without it is evidence
            # nobody can return to
            s.intel("postman-global", f"{g['key']}={g['value']}", "porch-pirate",
                    workspace_author=g["author"] or "unknown", key=g["key"])
            n_globals += 1
    if n_urls or n_globals:
        echo(f"  porch-pirate[{apex}]: {n_urls} endpoint(s), {n_globals} workspace global(s) (intel)")


def _rdap_org(obj: dict) -> str:
    for ent in obj.get("entities") or []:
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) > 3 and field[0] in ("fn", "org"):
                    val = field[3]
                    if isinstance(val, str) and val.strip():
                        return val.strip()
    return ""


def _rdap_addresses(profile, s: OsintSession) -> dict:
    import socket
    per_apex: dict = {}
    for apex in profile.apex_domains:
        found: set = set()
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                for info in socket.getaddrinfo(apex, None, family, socket.SOCK_STREAM):
                    found.add(info[4][0])
            except OSError:
                continue          # one family missing is normal; only a complete failure is a gap
        per_apex[apex] = sorted(found)
        if not found:
            # an apex that resolved to nothing is a gap in the verdict, not a silent continue
            s.note_failure("rdap", f"{apex}: resolved to no address (v4 or v6)")
    return per_apex


def _rdap(s: OsintSession, profile, echo, timeout: int) -> None:
    """Resolved apex IPs -> RDAP netblock/org -> CIDR/org candidates (suggest-only, verify-ownership). The
    lookup count is a throughput bound over the host-fair eligible set, never a membership cut; the withheld
    remainder is reported as our own operator limit.
    """
    from . import policy
    per_apex = _rdap_addresses(profile, s)
    owner = {ip: apex for apex, ips in per_apex.items() for ip in ips}
    eligible = budget.order_fairly(sorted(owner), lambda ip: owner[ip])
    cap = policy.limit("RDAP_LOOKUPS")
    chosen = eligible if cap <= 0 else eligible[:cap]
    withheld = len(eligible) - len(chosen)
    for ip in chosen:
        try:
            data = _http(f"https://rdap.org/ip/{ip}", timeout=min(timeout, 30))
            raw = s.raw_path("rdap", f"{ip}.json")
            privfs.write_private(raw, data)
            obj = json.loads(data)
        except Exception as e:
            echo(f"    rdap[{ip}]: {e}")
            s.note_failure("rdap", f"{ip}: {e}")
            continue
        netname = (obj.get("name") or "").strip()
        org = _rdap_org(obj)
        for c in obj.get("cidr0_cidrs") or []:
            prefix, length = c.get("v4prefix") or c.get("v6prefix"), c.get("length")
            if prefix and length is not None:
                s.candidate(f"{prefix}/{length}", "cidr", "rdap", "verify-ownership",
                            f"RDAP netblock for resolved IP {ip} ({netname or 'unknown'})",
                            raw_ref=str(raw),
                            manual_followup="confirm ownership (may be CDN/shared host) before scanning")
        if org:
            s.candidate(org, "org", "rdap", "verify-ownership",
                        f"RDAP org for resolved IP {ip}", raw_ref=str(raw))
        echo(f"  rdap[{ip}]: {netname or org or 'no netblock'}")
    # our bound, so our limit: a withheld remainder is reported, never silent
    note = f"{len(chosen)}/{len(eligible)} resolved address(es) looked up"
    meta = {"eligible": len(eligible), "tested": len(chosen), "withheld": withheld,
            "measure": "addresses", "bound": cap}
    if withheld:
        meta["operator_limit"] = True
        note += (f" — {withheld} withheld by the RDAP_LOOKUPS={cap} throughput bound "
                 f"(`quarry osint --unbound` covers every eligible address)")
    s.record(RunResult("rdap", ["rdap", f"lookups={cap or 'unbounded'}"],
                       Status.SUCCESS if chosen else Status.EMPTY,
                       0, 0.0, None, len(chosen), note=note, meta=meta))


def _key_health(s: OsintSession, echo) -> None:
    """Surface which keys this OSINT run uses (set vs missing), so thin OSINT is explained."""
    status = {"whoxy (reverse-whois)": bool(secrets.whoxy()),
              "projectdiscovery/chaos (asnmap)": bool(secrets.chaos())}
    have_ = [k for k, v in status.items() if v]
    missing = [k for k, v in status.items() if not v]
    s.notes.append("OSINT keys set: " + (", ".join(have_) or "none"))
    if missing:
        s.notes.append("OSINT keys missing (those sources are skipped/limited): " + ", ".join(missing))
    echo(f"  key-health: {len(have_)} key(s) set, {len(missing)} missing")


def run(profile, scope, project_dir: Path, echo=print, timeout: int = 1800) -> Path:
    """Run the OSINT pre-flight and return the report path. Never edits scope. `timeout` is the per-tool
    ceiling; fast lookups use shorter caps.
    """
    sess = OsintSession(project_dir, profile.target)
    from .runner import set_tool_cwd
    set_tool_cwd(sess.dir)   # contain any stray tool output inside the osint session dir
    emails: set[str] = set()
    for apex in profile.apex_domains:
        _azmap(sess, apex, echo, timeout)
        emails |= _whois(sess, apex, echo, timeout)
        _dmarc(sess, apex, echo, timeout)
    _whoxy(sess, emails, profile.org_names, echo, timeout)
    _asrank(sess, profile, echo, timeout)      # org name -> ASN candidates (the discovery step)
    _asn_expand(sess, profile, echo, timeout)  # ...and profile ASN seeds -> CIDR context
    _rdap(sess, profile, echo, timeout)
    _key_health(sess, echo)
    if have("porch-pirate"):
        for apex in profile.apex_domains:
            _porch_pirate(sess, apex, echo, timeout)
    else:
        sess.record(skipped("porch-pirate", "not installed (optional)"))
    return sess.finalize(profile)
