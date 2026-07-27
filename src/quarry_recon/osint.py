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
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import osint_report, secrets
from .contract import (ProviderBodyError, is_provider_limit, whoxy_envelope,
                       whoxy_reverse_page)
from .runner import RunResult, Status, have, run as exec_tool, skipped

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
            entry["outcome"] = dict(meta)
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
        limits, gaps = [], list(self._lane_failures)
        for tr in self._tool_runs:
            out = tr.get("outcome") or {}
            entry = {"tool": tr["tool"], "why": tr.get("note", ""), **out}
            # review-B0r3#2: a limit and a gap are INDEPENDENT facts and one tool result can carry BOTH —
            # query 1 fails or is page-limited, query 2 exhausts the credits. The old if/elif recorded only
            # the limit, so a genuine gap vanished behind an expected boundary. Never `elif` these.
            if out.get("provider_limit"):
                limits.append(entry)
            if (out.get("failed") or out.get("truncated_pages")
                    or tr.get("status") in ("failed", "partial", "timed_out", "blocked")):
                gaps.append(entry)
        # gaps DOMINATE: a limit may only lift an otherwise-clean session.
        verdict = ("complete_with_gaps" if gaps
                   else "complete_with_limits" if limits else "complete")
        return {"verdict": verdict, "provider_limits": limits, "gaps": gaps}

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


def _whoxy(s: OsintSession, emails: set[str], org_names: list[str], echo, timeout: int) -> None:
    """Reverse-whois by registrant EMAIL (from whois) and by ORG_NAMES (profile anchor).

    review-B0#4: there is no first-N cap here any more. `[:5]` on each list was exactly the hidden
    membership cap this migration exists to remove — it silently dropped anchors with no remainder and no
    accounting. EVERY anchor is now queued; ordering decides what is asked FIRST, and the provider's own
    balance decides how many are asked at all. Whatever the credits do not reach is reported, not hidden.

    review-B0#2/#6: every query's outcome is counted and the lane ALWAYS records a lifecycle. Three failed
    queries used to produce no manifest record at all, and one failure among two successes recorded a flat
    SUCCESS. `attempted` counts requests actually SENT, `completed` those that returned a usable answer;
    they are different numbers and the exhausted-on-the-first-call case proves it (attempted 1,
    completed 0)."""
    key = secrets.whoxy()
    if not key:
        s.record(skipped("whoxy", "no Whoxy key in secrets.yaml"))
        return
    # ORDER (not membership): registrant emails are the stronger ownership signal, so they go first; org
    # names are noisier anchors. Deterministic within each group.
    queries = [("email", e, f"registrant email {e}") for e in sorted(emails)]
    queries += [("company", o, f"org name '{o}'") for o in sorted(org_names or [])]
    if not queries:
        s.record(skipped("whoxy", "no registrant email / org-name anchors to pivot on"))
        return
    eligible = len(queries)
    attempted = completed = failed = 0
    truncated_pages = 0
    limit_reason = limit_class = ""
    for param, val, label in queries:
        if limit_class:
            break                                            # credits are spent; asking again just fails
        attempted += 1
        try:
            q = urllib.parse.quote(val)
            data = _http(f"https://api.whoxy.com/?key={key}&reverse=whois&{param}={q}",
                         timeout=min(timeout, 60))
            # review-B0r2#3: the old name was a lossy 40-char slug, so `Acme Inc` and `Acme-Inc` (and any
            # two anchors sharing a normalised prefix) collided — the later response OVERWROTE the earlier
            # one while the earlier candidates kept pointing at that same raw_ref, i.e. provenance that
            # silently names the wrong evidence. Identity = digest over (query type, anchor, page).
            ident = hashlib.sha256(f"{param}\x00{val}\x00page=1".encode()).hexdigest()
            slug = re.sub(r"[^a-z0-9]+", "_", val.lower())[:32]
            raw = s.raw_path("whoxy", f"{param}-{slug}-{ident}.json")
            raw.write_text(data)
            # `status` is the authority. Whoxy reports failure — including a spent balance — inside an
            # HTTP 200, so reading the results key directly turned an exhausted account into "0 domains"
            # (a false EMPTY: no error, no event, silently lost coverage).
            obj = whoxy_envelope(json.loads(data))
            doms, total, truncated = whoxy_reverse_page(obj, page=1, param=param, value=val)
            for d in doms:
                s.candidate(d, "apex", "whoxy-revwhois", "in-scope-likely",
                            f"reverse-whois on {label}", raw_ref=str(raw))
            completed += 1
            if truncated:
                truncated_pages += 1
                echo(f"  whoxy[{label}]: {len(doms)} of {total} domains — MORE PAGES not fetched")
            else:
                echo(f"  whoxy[{label}]: {len(doms)} domains")
        except ProviderBodyError as e:
            if is_provider_limit(e.error_class):
                limit_class, limit_reason = e.error_class, e.reason
                echo(f"    whoxy[{label}]: {e.reason} — provider {e.error_class}, "
                     f"{eligible - attempted} query(ies) not sent")
            else:
                failed += 1
                echo(secrets.redact(f"    whoxy[{label}]: {e.reason} ({e.error_class})"))
        except Exception as e:
            failed += 1                                       # HTTP/transport/JSON — a real failure
            echo(secrets.redact(f"    whoxy[{label}]: {e}"))  # error may echo the key= URL
    not_sent = eligible - attempted
    counts = (f"{attempted}/{eligible} attempted · {completed} completed · {failed} failed"
              + (f" · {not_sent} not sent" if not_sent else "")
              + (f" · {truncated_pages} truncated page(s)" if truncated_pages else ""))
    cmd = ["whoxy", "reverse=whois"]
    if limit_class:
        # a LIMIT, not a failure: the lane behaved correctly and the provider stopped us. The class is
        # carried STRUCTURALLY (meta), not only in free text, so a consumer can act on it.
        s.record(RunResult("whoxy", cmd, Status.LIMITED, None, 0.0, None, completed,
                           note=f"provider limit ({limit_class}): {limit_reason} — {counts}",
                           meta={"error_class": limit_class, "provider_limit": True,
                                 "eligible": eligible, "attempted": attempted,
                                 "completed": completed, "failed": failed, "not_sent": not_sent,
                                 "truncated_pages": truncated_pages, "coverage_incomplete": True}))
    elif failed and completed:
        s.record(RunResult("whoxy", cmd, Status.PARTIAL, None, 0.0, None, completed,
                           note=f"partial: {counts}",
                           meta={"eligible": eligible, "attempted": attempted,
                                 "completed": completed, "failed": failed,
                                 "truncated_pages": truncated_pages, "coverage_incomplete": True}))
    elif failed:
        s.record(RunResult("whoxy", cmd, Status.FAILED, None, 0.0, None, 0,
                           note=f"every reverse-whois query failed: {counts}",
                           meta={"eligible": eligible, "attempted": attempted,
                                 "completed": 0, "failed": failed, "coverage_incomplete": True}))
    elif truncated_pages:
        # review-B0r2#2: a page-limited answer is INCOMPLETE COVERAGE, not a clean success. Whoxy pages at
        # 100 results and charges a credit per page, so fetching the rest is credit-budget work (B1); until
        # then the shortfall must be visible instead of being reported as the whole answer.
        s.record(RunResult("whoxy", cmd, Status.PARTIAL, None, 0.0, None, completed,
                           note=f"page-limited: {counts}",
                           meta={"eligible": eligible, "attempted": attempted, "completed": completed,
                                 "failed": 0, "truncated_pages": truncated_pages,
                                 "coverage_incomplete": True}))
    else:
        s.record(RunResult("whoxy", cmd, Status.SUCCESS, 0, 0.0, None, completed,
                           note=counts,
                           meta={"eligible": eligible, "attempted": attempted,
                                 "completed": completed, "failed": 0}))


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
