"""The declared per-entity corpus envelope (distinct keys and bytes) a Run enforces, and the durable
remainder it records for identities refused past it."""
from __future__ import annotations

from .remainder import Remainder

#: bump when any threshold below changes; the versioned fixtures pin these exactly.
ENVELOPE_VERSION = 3

#: distinct materialized keys one Run holds per entity log.
MAX_KEYS_PER_ENTITY = 100_000

#: published peak-RSS ceiling for folding one entity at the key cap; gated by the large fixture.
RSS_BUDGET_MB = 160

#: hard ceiling on one materialized record's serialized bytes; a single record larger than this is refused.
MAX_BYTES_PER_KEY = 65_536

#: ceiling on the summed serialized bytes of one entity's merged corpus; growth past it is refused. Not a
#: disk budget: the normalized log is append-only, so its on-disk size tracks novel observations, not this.
MAX_CORPUS_BYTES_PER_ENTITY = 32 * 1024 * 1024

ENVELOPE_LANE = "store.envelope"


def declaration() -> dict:
    """The published envelope, carried in every manifest so the bound a run enforced is on the record."""
    return {"version": ENVELOPE_VERSION, "max_keys_per_entity": MAX_KEYS_PER_ENTITY,
            "rss_budget_mb": RSS_BUDGET_MB, "max_bytes_per_key": MAX_BYTES_PER_KEY,
            "max_corpus_bytes_per_entity": MAX_CORPUS_BYTES_PER_ENTITY}


def overflow_remainder(entity: str, refused: int, *, by_kind: dict | None = None) -> Remainder:
    """A durable remainder for identities refused past the per-entity envelope: `unschedulable` under the
    current bound, `project_progress` because a raised bound (bigger host / v0.4 store) advances them."""
    detail = {"entity": entity, "envelope_version": ENVELOPE_VERSION,
              "max_keys_per_entity": MAX_KEYS_PER_ENTITY}
    if by_kind:
        detail["refused_by_kind"] = {k: int(v) for k, v in sorted(by_kind.items()) if v}
    r = Remainder(lane=ENVELOPE_LANE, unit=f"{ENVELOPE_LANE}:{entity}", measure="keys",
                  model="project_progress", now=0, terminal={"unschedulable": int(refused)}, detail=detail)
    r.validate()
    return r
