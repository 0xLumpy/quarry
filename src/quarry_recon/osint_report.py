"""Renderers for the OSINT pre-flight: human review report + suggested profile.

The report is the product a human reviews. `target.suggested.yaml` is the live profile copied
verbatim with COMMENTED candidate blocks appended — the human uncomments approved entries into
their real target.yaml. Scope is never auto-edited.
"""
from __future__ import annotations

from datetime import datetime, timezone


def _by_type(cands, t):
    return [c for c in cands if c["type"] == t]


def render(session, profile, cands, intel, manual_todo) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    apexes = _by_type(cands, "apex")
    apex_scope = [c for c in apexes if c["scope_hint"] != "noise"]
    apex_noise = [c for c in apexes if c["scope_hint"] == "noise"]
    cidrs = _by_type(cands, "cidr")
    asns = _by_type(cands, "asn")
    orgs = _by_type(cands, "org")

    o = []
    A = o.append
    A(f"# {profile.target} — OSINT pre-flight report")
    A(f"_{ts} · run `quarry osint -t {profile.path or 'targets/<t>.yaml'}`_\n")
    A("> Candidates are **review-only** — nothing here is in scope until you copy it into "
      "`target.yaml`. Approve into `target.suggested.yaml` (uncomment), or edit the profile by "
      "hand. See `docs/target-prep.md`.\n")

    A("## Summary")
    A(f"- apex candidates: {len(apex_scope)} (+{len(apex_noise)} noise)")
    A(f"- CIDR: {len(cidrs)}  ·  ASN: {len(asns)}  ·  org context: {len(orgs)}")
    A(f"- intel (endpoints/secrets/emails — testing leads, not scope): {len(intel)}\n")

    if apex_scope:
        A("## Apex candidates  → review, add good ones to `APEX_DOMAINS`")
        A("| domain | scope hint | confidence | sources | why |")
        A("|--------|-----------|-----------|---------|-----|")
        for c in apex_scope:
            A(f"| `{c['value']}` | {c['scope_hint']} | {c['confidence']} | "
              f"{','.join(c['sources'])} | {c['reason']} |")
        A("")

    if cidrs or asns:
        A("## ASN / CIDR  ⚠️ verify ownership before adding (enables ACTIVE IP scanning)")
        for c in asns + cidrs:
            A(f"- `{c['value']}` ({c['type']}) — {c['confidence']} — {','.join(c['sources'])} — {c['reason']}")
        A("")

    if orgs:
        A("## Org context")
        for c in orgs:
            A(f"- {c['value']}  ({','.join(c['sources'])})")
        A("")

    if intel:
        A(f"## Intel — testing leads, NOT scope ({len(intel)})")
        for i in intel[:40]:
            A(f"- [{i['kind']}] {i['value']}  ({','.join(i['sources'])})")
        if len(intel) > 40:
            A(f"- … +{len(intel) - 40} more in intel.jsonl")
        A("")

    if apex_noise:
        A("## Noise (ignored — e.g. 3rd-party DMARC processors)")
        A("  " + ", ".join(f"`{c['value']}`" for c in apex_noise) + "\n")

    A("## Manual to-do (automation can't reach these — check by hand, then add to profile)")
    for label, how in manual_todo:
        A(f"- **{label}** — {how}")
    A("")

    A("## How to apply")
    A("1. Review the candidates above; confirm ownership + program scope.")
    A("2. Open `target.suggested.yaml` (this profile + commented candidates) and uncomment the "
      "approved entries, **or** edit `target.yaml` directly.")
    A("3. ASN/CIDR enable active scanning — only add ranges you've verified are owned + in scope.")
    A(f"4. Run the recon: `quarry run -t {profile.path or 'targets/<t>.yaml'}`")
    return "\n".join(o) + "\n"


def suggested_yaml(profile, cands) -> str:
    apex = [c for c in cands if c["type"] == "apex" and c["scope_hint"] != "noise"]
    cidr = [c for c in cands if c["type"] == "cidr"]
    asn = [c for c in cands if c["type"] == "asn"]

    base = profile.path.read_text() if (profile.path and profile.path.exists()) else \
        f"TARGET: {profile.target}\nAPEX_DOMAINS:\n  - {profile.apex_domains[0]}\n"

    o = [base.rstrip(), "",
         "# ════════════════════════════════════════════════════════════════════",
         "# OSINT candidates — REVIEW ONLY. Uncomment approved entries into the",
         "# sections above (or copy to target.yaml). Nothing here is in scope yet.",
         "# ════════════════════════════════════════════════════════════════════"]
    if apex:
        o.append("# APEX_DOMAINS candidates (confirm ownership + program scope):")
        for c in apex:
            o.append(f"#   - {c['value']:<32} # {c['scope_hint']} · {c['confidence']} · {','.join(c['sources'])}")
    if asn:
        o.append("# ASN candidates — VERIFY OWNERSHIP (enables active scanning):")
        for c in asn:
            o.append(f"#   - {c['value']:<32} # {','.join(c['sources'])}")
    if cidr:
        o.append("# CIDR candidates — VERIFY OWNERSHIP (enables active scanning):")
        for c in cidr:
            o.append(f"#   - {c['value']:<32} # {','.join(c['sources'])}")
    if not (apex or asn or cidr):
        o.append("# (no scope candidates found)")
    return "\n".join(o) + "\n"
