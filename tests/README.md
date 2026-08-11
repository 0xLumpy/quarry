# Quarry tests

Pytest development workflow for Quarry. The current `offline-ci` job is a useful hermetic lane, but it is
not by itself release proof. The authoritative lane taxonomy, required evidence, and promotion rules are
in the [release-gate contract](../docs/releases/RELEASE-GATES.md).

## Run

```bash
pip install -e ".[dev]"     # package + pytest
pytest -m offline           # current CI selection: offline-marked, network/subprocess denied
pytest                      # default selection: excludes live/integration/requires_tool
pytest -m integration       # real local binaries/processes against fixtures; no live target
```

Locally without an install: `PYTHONPATH=src pytest -m offline`. Set `QUARRY_OFFLINE_CI=1` to arm the
session-wide deny guard before collection, as the current CI workflow does.

## Markers

| marker | meaning |
|---|---|
| `offline` | Current `H0` candidate: no network or external binary. The present CI workflow positively selects this marker. |
| `requires_tool` | Capability annotation for a test that needs a real binary; not a standalone safety lane. |
| `integration` | Current `H1` candidate: runs a real external binary/process against local fixtures, never a live target. |
| `live` | Current `L0` candidate: contacts an explicitly authorized range/network. Never run by offline CI. |

Plain `pytest` **excludes** `live`/`integration`/`requires_tool` by default (they are opt-in via explicit
`-m`). Network denial has two layers: a per-test autouse fixture (local dev) and a session-wide guard armed
by `QUARRY_OFFLINE_CI=1` (set in CI) that is installed before collection, so it also blocks **import-time**
network. Both block sockets, resolvers, UDP, **and subprocess spawn** (a scanner launched via `exec_tool`
would otherwise bypass the socket patches).

The repository still has tests outside a complete one-primary-lane classification. Consequently,
`pytest -m offline` deselecting them is not evidence that the whole required suite passed, and plain
`pytest` running an unmarked test does not retroactively classify it as `H0`. Until classification,
OS-level isolation, collection evidence and the other required gates are implemented, the release gate
remains open. The measured current-HEAD baseline and its limitations are recorded in the
[current audit](../docs/audit/CURRENT-HEAD.md#evidence-baseline).

## Other verification

`scripts/verify-quarry.sh` is a mixed diagnostic harness: it includes checks with external prerequisites
and may report `SKIP`. It is useful during development, but a skipped or unavailable required check is not
a release-gate pass. New offline-testable behavior belongs in pytest with the correct marker and in the
corresponding gate evidence, not only in the shell script. Private historical-run regression is governed
separately by the [golden-corpus contract](../docs/design/GOLDEN-CORPUS.md).
