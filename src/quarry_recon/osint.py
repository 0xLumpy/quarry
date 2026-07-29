"""OSINT pre-flight module (standalone `quarry osint`).

Discovers scope CANDIDATES (apex/asn/cidr/org) + attack-surface INTEL (endpoints/secrets/
emails) from the anchors in a target profile, scores them (confidence + scope_hint), and
writes a review-oriented OSINT workspace.

It NEVER edits scope. Candidates are review-only; the human confirms and copies approved ones
into target.yaml (see target.suggested.yaml + docs/target-prep.md). Automated parts of the
horizontal-OSINT methodology; manual-only sources are surfaced as a "manual to-do" list.

Output:  <project>/osint/<ts>/{raw/, candidates.jsonl, intel.jsonl, osint-report.md,
                              target.suggested.yaml, manifest.json}   + <project>/osint/latest
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

from . import osint_report, secrets, settings, whoxy_page
from .contract import (PROVIDER_PARSE, PROVIDER_TRANSPORT, ProviderBodyError, capture_error_body,
                       provider_error_class, whoxy_envelope)
from .runner import RunResult, Status, fresh_artifact_dir, have, run as exec_tool, skipped

# Full email (no inner capture group) — findall returns the whole address.
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()
_DMARC_PROCESSORS = ("dmarcian", "proofpoint", "agari", "valimail", "easydmarc",
                     "ondmarc", "mxtoolbox", "fraudmarc", "dmarcadvisor", "redsift")

# source reliability for confidence scoring
_RELIABLE = {"whoxy-revwhois": 2, "azmap-tenant": 2, "asnmap": 1,
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


class OsintSession:
    """OSINT workspace: candidates + intel + raw evidence under <project>/osint/<ts>/."""

    def __init__(self, project_dir: Path, target: str, ts: str | None = None):
        self.project_dir = Path(project_dir)
        self.target = target
        self.ts = ts or time.strftime("%Y%m%d-%H%M%S")
        self.dir = self.project_dir / "osint" / self.ts
        self.raw = self.dir / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.started = _utc()
        self._cands: dict[tuple, dict] = {}     # (type, value) -> candidate
        self._intel: list[dict] = []
        self._tool_runs: list[dict] = []
        self._lane_failures: list[dict] = []    # native lanes that only echo (azmap/whois/dmarc/rdap)
        self.notes: list[str] = []

    def raw_path(self, source: str, name: str) -> Path:
        p = self.raw / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def record(self, result) -> None:
        # redact secret values from the recorded command/note (same choke point as store.Run.record)
        entry = {"tool": result.tool, "status": str(result.status.value),
                 "note": secrets.redact(result.note),
                 "cmd": secrets.redact(" ".join(result.cmd))}
        # review-B0#3: carry the STRUCTURED outcome into the manifest. A provider limit recorded only as
        # prose in `note` cannot be acted on — a consumer would have to grep English to tell "the account
        # is out of credits" from "the tool broke", which is precisely the distinction B0 exists to make.
        meta = getattr(result, "meta", None)
        if isinstance(meta, dict) and meta:
            # review-B1.6b24#1: `note` and `cmd` were redacted here and the structured outcome was not,
            # so a machinery reason carrying an exception string — which can carry a configured key —
            # reached the manifest verbatim beside a redacted `note: ***`.
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

    def intel(self, kind: str, value: str, source: str) -> None:
        self._intel.append({"kind": kind, "value": value, "sources": [source]})

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
        """Record a native-lane failure. review-B0r3#3: `_azmap` / `whois` / `dmarc` / `rdap` only ECHOED
        their exceptions, so a session where half of them blew up still produced a clean verdict."""
        self._lane_failures.append({"tool": tool, "why": secrets.redact(str(why))})

    def outcome(self) -> dict:
        """The session's own coverage verdict — the OSINT path has no events pipeline, so without this a
        provider LIMIT lived only in a per-tool `outcome` block nothing ever read (review-B0r2#5), and the
        CLI printed an unconditional green `osint done` over a run that never queried half its anchors."""
        limits, operator_limits, gaps = [], [], list(self._lane_failures)
        for tr in self._tool_runs:
            out = tr.get("outcome") or {}
            entry = {"tool": tr["tool"], "why": tr.get("note", ""), **out}
            # review-B0r3#2: a limit and a gap are INDEPENDENT facts and one tool result can carry BOTH —
            # query 1 fails or is page-limited, query 2 exhausts the credits. The old if/elif recorded only
            # the limit, so a genuine gap vanished behind an expected boundary. Never `elif` these.
            # review-B1.6b14#4: an OPERATOR boundary (a credit reserve, a page budget) is a limit the
            # session must state too — it was invisible here, so a deliberately withheld remainder folded
            # as `complete`. `limit_origin` carries which, so a reader is never told the provider
            # refused us when our own policy did.
            # review-B1.6b15#1: both kinds were appended to ONE list and returned as
            # `provider_limits`, so an operator's own reserve was reported to them as the provider
            # refusing us — the blame-shift this taxonomy exists to prevent, at the last step.
            if out.get("provider_limit"):
                limits.append(entry)
            if out.get("operator_limit"):
                operator_limits.append(entry)
            if (out.get("failed") or out.get("truncated_pages")
                    or tr.get("status") in ("failed", "partial", "timed_out", "blocked")):
                gaps.append(entry)
        # gaps DOMINATE: a limit may only lift an otherwise-clean session.
        verdict = ("complete_with_gaps" if gaps
                   else "complete_with_limits" if (limits or operator_limits) else "complete")
        return {"verdict": verdict, "provider_limits": limits,
                "operator_limits": operator_limits, "gaps": gaps}

    def finalize(self, profile) -> Path:
        cands = self.candidates()
        (self.dir / "candidates.jsonl").write_text(
            "\n".join(json.dumps(c, ensure_ascii=False) for c in cands) + ("\n" if cands else ""))
        (self.dir / "intel.jsonl").write_text(
            "\n".join(json.dumps(i, ensure_ascii=False) for i in self._intel) + ("\n" if self._intel else ""))
        (self.dir / "manifest.json").write_text(json.dumps({
            "target": self.target, "ts": self.ts, "started": self.started, "finished": _utc(),
            "profile_anchors": {"apex": profile.apex_domains, "asn": profile.asn,
                                "org_names": profile.org_names, "brands": profile.brands},
            "tool_runs": self._tool_runs, "candidate_count": len(cands),
            "intel_count": len(self._intel), "notes": self.notes,
            "summary": self.outcome(),
        }, indent=2))
        report = osint_report.render(self, profile, cands, self._intel, MANUAL_TODO)
        (self.dir / "osint-report.md").write_text(report)
        (self.dir / "target.suggested.yaml").write_text(
            osint_report.suggested_yaml(profile, cands))
        # latest pointer (per-project)
        link = self.project_dir / "osint" / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            os.symlink(self.dir.resolve(), link)
        except OSError:
            (self.project_dir / "osint" / "latest.txt").write_text(str(self.dir.resolve()))
        return self.dir / "osint-report.md"


# ── sources ──────────────────────────────────────────────────────────────────

def _azmap(s: OsintSession, apex: str, echo, timeout: int) -> None:
    try:
        data = _http(f"https://azmap.dev/api/tenant?domain={apex}&extract=true",
                     timeout=min(timeout, 30))
        raw = s.raw_path("azmap", f"{apex}.json")
        raw.write_text(data)
        obj = json.loads(data)
        for d in (obj.get("related_domains") or obj.get("email_domains") or []):
            if d != apex:
                s.candidate(d, "apex", "azmap-tenant", "related",
                            f"M365 tenant of {apex}", raw_ref=str(raw))
        if obj.get("tenant_name"):
            s.candidate(obj["tenant_name"], "org", "azmap-tenant", "related",
                        f"M365 tenant name for {apex}", raw_ref=str(raw))
        echo(f"  azmap[{apex}]: {len(obj.get('related_domains') or [])} related domains")
    except Exception as e:
        echo(f"    azmap[{apex}]: {e}")
        s.note_failure("azmap", f"{apex}: {e}")


def _whois(s: OsintSession, apex: str, echo, timeout: int) -> set[str]:
    """Returns full registrant EMAILS (for whoxy reverse-whois)."""
    emails: set[str] = set()
    try:
        p = subprocess.run(["whois", apex], capture_output=True, text=True,
                           timeout=min(timeout, 30), stdin=subprocess.DEVNULL)
        raw = s.raw_path("whois", f"{apex}.txt")
        raw.write_text(p.stdout)
        # review-B0r4#2: `whois` can exit NONZERO without raising, so the lane parsed an empty/partial
        # body and reported clean completion. An outcome check is not the same as an exception handler.
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
        raw.write_text(p.stdout)
        if p.returncode != 0:                          # review-B0r4#2: dig exits nonzero without raising
            s.note_failure("dmarc", f"{apex}: dig exit {p.returncode}")
        for email in _EMAIL_RE.findall(p.stdout):       # rua/ruf mailto addresses
            dom = _email_domain(email)                  # the reporting DOMAIN is the candidate
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
    """One Whoxy request -> `(raw_bytes, error)`. NEVER raises: the paginator classifies, it does not
    catch. Returns the EXACT response bytes, which are what gets stored as evidence."""
    raw = b""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "quarry-osint"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except Exception as e:
        # review-B1.6b13#7: `capture_error_body` reads an HTTPError's body and stamps it onto the
        # exception — but `raw` was still empty, so the EXACT failure bytes could never be persisted.
        # Whoxy answers failure inside a 200 more often than not, and when it does not, this is the
        # evidence.
        capture_error_body(e, provider="whoxy")
        # the EXACT bytes captured at the raise site — `body_text` is a lossy decode and re-encoding it
        # would not give back what the provider sent (review-B1.6b14#5).
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
    """A failed balance REQUEST as a balance outcome.

    review-B1.6b15#2: this said `refused=False` unconditionally, so a class the type requires to be
    refused — a proven quota or entitlement — built an INVALID `BalanceRead` and raised `ValueError` out
    of the lane.

    review-B1.6b16#1: the fix then derived refusal from the CLASS alone, which infers a provider response
    from something that may never have reached the provider. `PROVIDER_ERROR` is what an unclassified
    LOCAL exception maps to, and calling that "the provider refused us" is a claim about a conversation
    that did not happen. ORIGIN and class together:

      · a PROVEN limit is a refusal by definition, whatever carried it;
      · an HTTPError or a provider ENVELOPE failure is the provider having answered — except `parse`,
        which is our inability to read what it said;
      · anything else (a timeout, a URLError, a local bug) is a failure to READ, not a refusal.

    Whoxy reports quota inside an HTTP 200 today, so the transport path is unlikely to produce a limit
    class — but "unlikely" is not a contract, and getting it wrong crashes the lane rather than
    degrading it."""
    cls = provider_error_class(err) or PROVIDER_TRANSPORT
    from .contract import PROVIDER_LIMITS
    answered = isinstance(err, (urllib.error.HTTPError, ProviderBodyError))
    refused = cls in PROVIDER_LIMITS or (answered and cls != PROVIDER_PARSE)
    return whoxy_page.BalanceRead(error_class=cls, reason=str(err) or "balance request failed",
                                  refused=refused)


def _whoxy(s: OsintSession, emails: set[str], org_names: list[str], echo, timeout: int) -> None:
    """Reverse-whois by registrant EMAIL (from whois) and by ORG_NAMES (profile anchor).

    B1.6b: paginated, budgeted and RESUMABLE. Whoxy charges ONE CREDIT PER PAGE and a single anchor can
    run to hundreds of pages, so a page bought in an earlier run is OWNED and replayed for free, ordering
    is page-tier-first across anchors, and whatever a budget does not reach is a counted remainder rather
    than a silent truncation. Page state lives beside the timestamped sessions so it survives them.

    review-B0#4: there is no first-N cap on anchors. Ordering decides what is asked FIRST; the balance
    and the operator's reserve decide how much is asked at all."""
    key = secrets.whoxy()
    if not key:
        s.record(skipped("whoxy", "no Whoxy key in secrets.yaml"))
        return
    # ORDER (not membership): registrant emails are the stronger ownership signal, so they go first.
    anchors = [whoxy_page.Anchor("email", e) for e in sorted(emails)]
    anchors += [whoxy_page.Anchor("company", o) for o in sorted(org_names or [])]
    if not anchors:
        s.record(skipped("whoxy", "no registrant email / org-name anchors to pivot on"))
        return

    # RAW, not `concurrency()`: that clamps to `max(1, ...)` and falls back silently, which would turn
    # an explicit 0 into 1, a negative typo into 1, and a malformed value into "unbounded". A spending
    # control's own parser must see what the operator actually wrote (review-B1.6b13#1).
    reserve = settings.raw("WHOXY_CREDIT_RESERVE", 0)
    run_budget = settings.raw("WHOXY_PAGE_BUDGET", 0)
    states = [whoxy_page.AnchorState(a) for a in anchors]
    labels = {("email", a.value): f"registrant email {a.value}" for a in anchors}
    labels.update({("company", a.value): f"org name '{a.value}'" for a in anchors})
    seen: dict = {"policy": None, "balance": None}

    def fetch(anchor, page):
        """One page, as the paginator's `(raw_bytes, error)` — the EXACT bytes either way.

        Whoxy reports failure INSIDE an HTTP 200 (`{"status": 0, "status_reason": "Zero Account
        Balance"}`), so a transport-only check sees no error at all and the paginator would treat a
        spent account as an unreadable page — the false-empty B0 exists to prevent, one layer up. The
        STATUS ENVELOPE is what classifies here; the row contract stays with `read_page`."""
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
        """The account-wide spend lock, the FREE balance read, and the settled allowance — in that order,
        entered only when pending work remains (see `whoxy_page.spend_lock`)."""
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
        # ANOTHER RUN holds this project's page state. Nothing was read and nothing spent — and it is a
        # gap, not a skip: the coverage this lane would have produced is simply absent.
        echo(f"  whoxy: {e}")
        s.record(RunResult("whoxy", ["whoxy", "reverse=whois"], Status.BLOCKED, None, 0.0, None, 0,
                           note=f"another run holds this project's whoxy page state — {e}",
                           meta={"eligible": len(anchors), "attempted": 0, "completed": 0,
                                 "coverage_incomplete": True}))
        return
    except Exception as e:
        # review-B1.6b21: only LockBusy was caught, so a machinery failure the lock deliberately
        # PROPAGATES — a read-only filesystem, a filesystem without lock support — aborted the whole
        # OSINT run with no Whoxy terminal at all. `outcome()` never saw the gap, and best-effort is the
        # provider contract: one lane failing must not take the session with it.
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
    """Turn one paginator Outcome into this lane's terminal.

    review-B1.6b13#3: this was an `if/elif` chain, so whichever branch matched first ERASED the others —
    an invalid knob hid a simultaneous provider refusal, a failure hid a simultaneous limit, and
    `account_busy` reported as LIMITED though it is a gap by contract. Every fact is now recorded
    INDEPENDENTLY and the status is chosen afterwards, with gaps dominating limits."""
    # review-B1.6b13#5: a rejected page-one request was ATTEMPTED and never touched, so counting touched
    # anchors reported `attempted=0` for a run that spent a credit on every anchor.
    # review-B1.6b14#6: anchors we actually SENT a request for. `anchors - unopened` reported a
    # replay-only lifecycle as having attempted every anchor while issuing zero requests.
    attempted = len(out.requested)
    # review-B1.6b13#8: pages and anchors are different units. A known page remainder is pages; an
    # unopened anchor has no knowable page count at all, and adding them invents a denominator.
    pages_left, unopened = out.pages_left_known, len(out.unopened)
    # review-B1.6b13 (closing note): an unusable page increments `fail_classes["parse"]` AND
    # `evidence_invalid`, so adding both counted one malformed response twice.
    # review-B1.6b23#1: an unconsumed page is a failure of THIS lane to deliver coverage it holds, and
    # `failed` is what `OsintSession.outcome()` folds into the verdict.
    failed = sum(out.fail_classes.values()) + out.publish_failed + out.pages_unconsumed
    pol = pol or whoxy_page.SpendPolicy()

    limits = dict(out.limit_classes)
    limit_why = out.limit_reason or pol.limit
    gap_why = out.fail_reason or pol.gap
    # review-B1.6b14#2: status was chosen from `gap_why` alone, so a lane could publish nothing, journal
    # nothing, or reject every page and still report SUCCESS. Every real failure gets a reason.
    if out.publish_failed and not gap_why:
        gap_why = f"{out.publish_failed} page(s) could not be stored"
    if out.evidence_invalid and not gap_why:
        gap_why = f"{out.evidence_invalid} page(s) were unusable and were not owned"
    # review-B1.6b22: the paginator now KEEPS the outcome when its own machinery fails, so the terminal
    # must be able to explain a run that holds real pages and still did not finish.
    # review-B1.6b23#3: `gap_why or ...` hid EVERY machinery failure behind an earlier provider one — a
    # transport error followed by our accounting blowing up reported only the transport error. The first
    # cause still leads the sentence; the rest are appended, because both happened.
    # review-B1.6b26: the check was on the COMBINED string, which never matched once there were two
    # failures — so the first reason, already carried by `fail_reason`, was rendered a second time
    # inside the appendix. Each entry decides for itself whether it has been said.
    machinery_why = "; ".join(m for m in out.machinery if m not in gap_why)
    if machinery_why:
        gap_why = (f"{gap_why} · page state machinery also failed ({machinery_why})" if gap_why
                   else f"page state machinery failed ({machinery_why})")
    # review-B1.6b23#1: a page whose ingestion failed is owned and out of the page remainder, so nothing
    # else in this terminal can say its rows are missing.
    if out.pages_unconsumed:
        why = f"{out.pages_unconsumed} page(s) were read but not ingested"
        gap_why = f"{gap_why} · {why}" if gap_why else why
    if out.stop_cause in ("ledger_unwritable", "publish_failed", "scheduler_invariant"):
        gap_why = gap_why or f"page state machinery failed ({out.stop_cause})"
    if out.stop_cause == "account_busy":
        # agreed contract: another project holding the account is a GAP, not a soft limit — the pages we
        # could not buy are simply missing, and nothing about this account refused us.
        gap_why = gap_why or "another project is spending this account; the remainder was not bought"
    if out.stop_cause.startswith("provider_stop:"):
        gap_why = gap_why or out.stop_cause
    if not out.persisted:
        gap_why = gap_why or "page state was NOT persisted — paid pages will be bought again"
    # review-B1.6b14#1: only a KNOWN page remainder activated the boundary, so two anchors we never
    # opened at all — the larger loss — reported SUCCESS. Units stay separate in the reporting.
    has_remainder = bool(pages_left or unopened)
    left_desc = " and ".join(x for x in ((f"{pages_left} page(s)" if pages_left else ""),
                                         (f"{unopened} anchor(s)" if unopened else "")) if x)
    # review-B1.6b19: `limit_origin` was a single value and provider won first, so a quota AND a reserve
    # together reported `operator_limit=False` beside `spend_stop_kind="operator_reserve"` — metadata
    # contradicting itself, with the operator's own boundary dropped. They are independent facts and one
    # run can hit both: the provider refused what was left, and we had withheld some of it anyway.
    provider_why = out.limit_reason or pol.limit or ""
    operator_why = ""
    # review-B1.6b20: a remainder ALONE activated the policy's boundary, so a run our own machinery
    # stopped — a failed publish, an unwritable ledger — reported a provider or operator limit it never
    # reached. The policy explains a remainder only when its allowance was actually spent; the scheduler
    # counts that, and nothing else can know it. Page-proven limits stay independent of this.
    bounded = has_remainder and out.allowance_exhausted
    if bounded and pol.stop_kind in ("operator_reserve", "run_budget"):
        operator_why = f"{left_desc} withheld by the operator ({pol.stop_kind})"
    elif bounded and pol.stop_kind == "provider_balance" and not provider_why:
        provider_why = f"{left_desc} not bought — the account balance is the boundary"
    provider_limit = bool(limits or pol.limit or provider_why)
    operator_limit = bool(operator_why)
    limit_why = limit_why or provider_why or operator_why

    counts = (f"{attempted}/{out.anchors} anchor(s) attempted · {out.pages_bought} page(s) bought"
              f" · {out.pages_replayed} replayed · {out.domains} domain(s)"
              + (f" · {out.requests_issued} request(s) issued" if out.requests_issued else "")
              + (f" · {pages_left} page(s) remaining" if pages_left else "")
              + (f" · {unopened} anchor(s) never opened" if unopened else "")
              + (f" · {out.pages_unconsumed} page(s) not ingested" if out.pages_unconsumed else "")
              + (f" · {out.error_bodies} error body(ies) kept" if out.error_bodies else ""))
    # the balance outcome's class counts too: a lane stopped before its first page has no page-level
    # class, and reporting a gap with no class tells an operator only that something went wrong.
    cls = next(iter(out.fail_classes), None) or next(iter(limits), None) or (pol.error_class or None)
    meta = {"eligible": out.anchors, "attempted": attempted, "completed": out.anchors_touched,
            # `failed` and `truncated_pages` are what `OsintSession.outcome()` folds into the verdict.
            # review-B1.6b13#2: EVERY remainder went into `truncated_pages`, and any value there is a
            # gap — so a quota, which is a soft limit by contract, produced complete_with_gaps. Only a
            # remainder nothing else explains belongs there.
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
            # review-B1.6b14#3: `provider_limit` was set only inside the limit-ONLY status branch, so a
            # transport failure plus a quota reported the gap and lost the limit entirely. A limit and a
            # gap are independent facts; both are recorded before any status is chosen.
            # review-B1.6b14#4: an OPERATOR boundary is a limit too, and the session verdict could not
            # see it — a withheld remainder folded as `complete`.
            "provider_limit": provider_limit, "operator_limit": operator_limit,
            "provider_limit_reason": provider_why or None,
            "operator_limit_reason": operator_why or None,
            # both, when both happened — a scalar origin could only ever name one of them.
            "limit_origin": ("+".join(k for k, on in (("provider", provider_limit),
                                                      ("operator", operator_limit)) if on) or None)}

    # GAPS DOMINATE: a limit may only lift an otherwise-clean lane. An unusable control is our own
    # defect and outranks both.
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


def _asn_expand(s: OsintSession, profile, echo, timeout: int) -> None:
    """Profile ASN seeds → CIDR candidates (verify-ownership; high-risk = active scanning)."""
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


def _porch_pirate(s: OsintSession, apex: str, echo, timeout: int) -> None:
    """Public Postman API leaks → INTEL (endpoints), not scope."""
    pp = s.raw_path("porch-pirate", f"{apex}.txt")
    r = exec_tool("porch-pirate", ["porch-pirate", "-s", apex, "--urls"],
                  raw_path=pp, timeout=timeout)
    s.record(r)
    if r.raw_path:
        n = 0
        for u in set(re.findall(r"https?://[^\s\"'<>]+", r.raw_path.read_text())):
            s.intel("postman-endpoint", u, "porch-pirate")
            n += 1
        if n:
            echo(f"  porch-pirate[{apex}]: {n} postman endpoints (intel)")


def _rdap_org(obj: dict) -> str:
    """Pull an org/name from an RDAP object's entities (vcard fn/org)."""
    for ent in obj.get("entities") or []:
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) > 3 and field[0] in ("fn", "org"):
                    val = field[3]
                    if isinstance(val, str) and val.strip():
                        return val.strip()
    return ""


def _rdap(s: OsintSession, profile, echo, timeout: int) -> None:
    """Resolved apex IPs -> RDAP netblock/org -> CIDR/org CANDIDATES (suggest-only). Never adds
    scope or scans; a resolved IP may be a CDN/shared host, so everything is verify-ownership."""
    import socket
    ips: set[str] = set()
    for apex in profile.apex_domains:
        try:
            ips.update(socket.gethostbyname_ex(apex)[2])
        except Exception as e:
            # review-B0r4#2: a silent `continue` meant an apex we could not resolve contributed NOTHING
            # to the verdict — the RDAP lane then reported clean completion over an unexamined apex.
            s.note_failure("rdap", f"{apex}: resolve failed — {e}")
            continue
    for ip in sorted(ips)[:20]:                       # bound RDAP lookups
        try:
            data = _http(f"https://rdap.org/ip/{ip}", timeout=min(timeout, 30))
            raw = s.raw_path("rdap", f"{ip}.json")
            raw.write_text(data)
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


def _key_health(s: OsintSession, echo) -> None:
    """Surface which keys THIS OSINT run uses (set vs missing) so thin OSINT is explained, not
    silent. Only keys quarry osint actually consumes — not the run-phase keys (shodan/github)."""
    status = {"whoxy (reverse-whois)": bool(secrets.whoxy()),
              "projectdiscovery/chaos (asnmap)": bool(secrets.chaos())}
    have_ = [k for k, v in status.items() if v]
    missing = [k for k, v in status.items() if not v]
    s.notes.append("OSINT keys set: " + (", ".join(have_) or "none"))
    if missing:
        s.notes.append("OSINT keys missing (those sources are skipped/limited): " + ", ".join(missing))
    echo(f"  key-health: {len(have_)} key(s) set, {len(missing)} missing")


def run(profile, scope, project_dir: Path, echo=print, timeout: int = 1800) -> Path:
    """Run the OSINT pre-flight. Returns the report path. Never edits scope.

    Output lands under <project_dir>/osint/. `timeout` is the per-tool ceiling; fast lookups
    (whois/dig/HTTP) use shorter caps.
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
    _asn_expand(sess, profile, echo, timeout)
    _rdap(sess, profile, echo, timeout)
    _key_health(sess, echo)
    if have("porch-pirate"):
        for apex in profile.apex_domains:
            _porch_pirate(sess, apex, echo, timeout)
    else:
        sess.record(skipped("porch-pirate", "not installed (optional)"))
    return sess.finalize(profile)
