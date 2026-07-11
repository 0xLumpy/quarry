"""OOB evidence substrate (Phase 1) — import out-of-band callbacks into a run's store.

Parses interactsh-client ``-json`` (JSONL) into ``oob_interaction`` rows. Phase 1 is IMPORT-based and
UNCORRELATED by default: an interaction is real signal (something reached the collector) but Quarry does
not own the token namespace yet, so it does NOT attribute a source/target/param — that arrives in Phase 2
when Quarry issues + owns the callback session. Never fabricate attribution.

interactsh-client ``-json`` record keys (confirmed from a live session, 2026-07-11):
``protocol · unique-id · full-id · q-type · raw-request · raw-response · remote-address · timestamp``.
``unique-id`` = the registered session (the correlation prefix Phase 2 will map to a source); ``full-id``
= the exact subdomain that was hit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _interaction_id(rec: dict) -> str:
    """Stable dedup id for one interaction (same session can produce many; distinguish by full-id +
    timestamp + protocol + remote)."""
    basis = "|".join(str(rec.get(k, "")) for k in
                     ("unique-id", "full-id", "protocol", "timestamp", "remote-address"))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def parse_interactsh(text: str) -> list[dict]:
    """interactsh-client ``-json`` (JSONL) -> oob_interaction rows. Defensive: skips malformed/empty
    lines. UNCORRELATED by default — Phase 1 owns no token namespace, so no source attribution."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if not isinstance(rec, dict) or not rec.get("protocol"):
            continue
        out.append({
            "id": _interaction_id(rec),
            "protocol": rec.get("protocol"),
            "interaction_domain": rec.get("full-id"),
            "correlation_id": rec.get("unique-id"),      # session id; Phase 2 maps its prefix -> source
            "q_type": rec.get("q-type"),
            "remote_address": rec.get("remote-address"),
            "timestamp": rec.get("timestamp"),
            # Phase-1 stance: evidence WITHOUT attribution (do NOT guess a source)
            "correlation": "uncorrelated",
            "source_tool": None,
            "target_url": None,
            "param": None,
            "payload_class": "unknown-oob",
            "sources": ["oob-import"],
        })
    return out


def import_file(run, path) -> dict:
    """Copy the raw import to ``raw/oob/``, parse it, add oob_interaction rows to the store. Returns
    ``{parsed, added, by_protocol}``; each row's ``raw_ref`` points at the stored raw file."""
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="replace")
    # content-hash prefix: two DIFFERENT files sharing a name (e.g. interact.jsonl) must not clobber
    # each other's raw evidence — otherwise earlier oob_interaction.raw_ref rows point at the wrong
    # file. Identical content re-import maps to the same raw file (raw_ref stays stable).
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    raw = run.raw_path("oob", "import", f"{digest}-{src.name}")
    raw.write_text(text, encoding="utf-8")
    rows = parse_interactsh(text)
    added = 0
    by_protocol: dict[str, int] = {}
    for row in rows:
        row["raw_ref"] = str(raw)
        if run.add("oob_interaction", row):
            added += 1
            by_protocol[row["protocol"]] = by_protocol.get(row["protocol"], 0) + 1
    return {"parsed": len(rows), "added": added, "by_protocol": by_protocol}
