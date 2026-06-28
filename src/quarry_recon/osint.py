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
from .runner import have, run as exec_tool, skipped

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
        self.notes: list[str] = []

    def raw_path(self, source: str, name: str) -> Path:
        p = self.raw / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def record(self, result) -> None:
        # redact secret values from the recorded command/note (same choke point as store.Run.record)
        self._tool_runs.append({"tool": result.tool, "status": str(result.status.value),
                                "note": secrets.redact(result.note),
                                "cmd": secrets.redact(" ".join(result.cmd))})

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


def _whois(s: OsintSession, apex: str, echo, timeout: int) -> set[str]:
    """Returns full registrant EMAILS (for whoxy reverse-whois)."""
    emails: set[str] = set()
    try:
        p = subprocess.run(["whois", apex], capture_output=True, text=True,
                           timeout=min(timeout, 30), stdin=subprocess.DEVNULL)
        raw = s.raw_path("whois", f"{apex}.txt")
        raw.write_text(p.stdout)
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
    return emails


def _dmarc(s: OsintSession, apex: str, echo, timeout: int) -> None:
    try:
        p = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{apex}"],
                           capture_output=True, text=True, timeout=min(timeout, 15),
                           stdin=subprocess.DEVNULL)
        raw = s.raw_path("dmarc", f"{apex}.txt")
        raw.write_text(p.stdout)
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


def _whoxy(s: OsintSession, emails: set[str], org_names: list[str], echo, timeout: int) -> None:
    """Reverse-whois by registrant EMAIL (from whois) and by ORG_NAMES (profile anchor)."""
    key = secrets.whoxy()
    if not key:
        s.record(skipped("whoxy", "no Whoxy key in secrets.yaml"))
        return
    # (param, value, label) queries: emails first, then org-name anchors
    queries = [("email", e, f"registrant email {e}") for e in sorted(emails)[:5]]
    queries += [("company", o, f"org name '{o}'") for o in (org_names or [])[:5]]
    if not queries:
        return
    for param, val, label in queries:
        try:
            q = urllib.parse.quote(val)
            data = _http(f"https://api.whoxy.com/?key={key}&reverse=whois&{param}={q}",
                         timeout=min(timeout, 60))
            raw = s.raw_path("whoxy", f"{param}-{re.sub(r'[^a-z0-9]+','_',val.lower())[:40]}.json")
            raw.write_text(data)
            obj = json.loads(data)
            doms = obj.get("domainsList") or [d.get("domain_name")
                                              for d in obj.get("search_result", [])]
            for d in (doms or []):
                s.candidate(d, "apex", "whoxy-revwhois", "in-scope-likely",
                            f"reverse-whois on {label}", raw_ref=str(raw))
            echo(f"  whoxy[{label}]: {len(doms or [])} domains")
        except Exception as e:
            echo(secrets.redact(f"    whoxy[{label}]: {e}"))  # error may echo the key= URL


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
        except Exception:
            continue
    for ip in sorted(ips)[:20]:                       # bound RDAP lookups
        try:
            data = _http(f"https://rdap.org/ip/{ip}", timeout=min(timeout, 30))
            raw = s.raw_path("rdap", f"{ip}.json")
            raw.write_text(data)
            obj = json.loads(data)
        except Exception as e:
            echo(f"    rdap[{ip}]: {e}")
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
