# Quarry tests

Offline, hermetic pytest suite — the C18 CI gate.

## Run

```bash
pip install -e ".[dev]"     # package + pytest
pytest -m offline           # the CI gate: hermetic, network-denied
pytest                      # all offline tests (integration/live are opt-in, none yet)
```

Locally without an install: `PYTHONPATH=src pytest -m offline`.

## Markers

| marker | meaning |
|---|---|
| `offline` | hermetic — no network, no external binary. **The CI gate.** A `conftest` autouse fixture hard-blocks sockets for these, so an offline test that reaches for the network fails loud. |
| `requires_tool` | needs a real binary on PATH (skips when absent). |
| `integration` | runs a real external binary against fixtures (no live target). |
| `live` | contacts the live range/network. Never in offline CI. |

Plain `pytest` **excludes** `live`/`integration`/`requires_tool` by default (they are opt-in via explicit
`-m`). Network denial has two layers: a per-test autouse fixture (local dev) and a session-wide guard armed
by `QUARRY_OFFLINE_CI=1` (set in CI) that is installed before collection, so it also blocks **import-time**
network. Both block sockets, resolvers, UDP, **and subprocess spawn** (a scanner launched via `exec_tool`
would otherwise bypass the socket patches).

## Scope (dual-run transition)

This suite is being grown from the high-risk code first (file-output status adapters, profile/identifier
validation, netguard classification, evidence-preservation + RoE regressions). The legacy
`notes/verify-quarry.sh` still runs the full check set and **invokes this pytest gate** (check `[142]`),
so both are green until pytest reaches parity. New offline-testable behavior should land here, not only in
the shell script.
