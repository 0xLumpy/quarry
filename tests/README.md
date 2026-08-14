# Quarry tests

Pytest development workflow for Quarry. Collection now enforces exactly one primary execution lane for
every test before marker deselection. This closes the structural marker gap, but the current Python guard
and diagnostic manifest are not release evidence. The authoritative isolation, evidence, and promotion
requirements are in the [release-gate contract](../docs/releases/RELEASE-GATES.md).

## Run

```bash
pip install -e ".[dev]"     # package + pytest
pytest                      # positive H0 default (`-m offline` from pyproject.toml)
pytest -m offline           # explicit equivalent of the default H0 selection
pytest -m integration       # H1: named real tools against synthetic/local fixtures
pytest -m corpus            # C0: controlled private-corpus runner; currently no nodes
pytest -m packaging         # P0: package/supply verification; currently no nodes
pytest -m live              # L0: explicitly authorized live range; currently no nodes
```

Locally without an install: `PYTHONPATH=src pytest`. Set `QUARRY_OFFLINE_CI=1` to arm the session-wide
Python network tripwire before collection, as the current CI workflow does.

## Markers

Each collected node must have exactly one primary marker:

| Primary marker | Lane | Meaning |
|---|---|---|
| `offline` | `H0-hermetic` | Repository fixtures only; no network or undeclared external binary. The default and current CI select this marker positively. |
| `integration` | `H1-tool-integration` | Named real tool against synthetic/local fixtures; no live target. Release evidence additionally requires an attested identity. |
| `corpus` | `C0-private-corpus` | Controlled private-corpus replay. |
| `packaging` | `P0-package-supply` | Candidate package and supply-chain verification. |
| `live` | `L0-authorized-live` | Explicitly authorized range/network; never selected by H0 CI. |

Secondary markers refine a lane; they do not classify a test:

| Secondary marker | Rule |
|---|---|
| `requires_tool("name")` | Names one stable real-tool capability; valid only on reviewed H1/P0 nodes. |
| `synthetic_process` | Permits the constrained absolute current-interpreter child shape used by reviewed H0 fixtures; it takes no arguments and is H0-only. |

The collection hook runs before `-m` deselection and fails on an unmarked node, multiple/duplicate primary
markers, an unnamed H1 tool, duplicate/invalid capability names, or a secondary marker in an incompatible
lane. A canonical `quarry.pytest-taxonomy.v1` diagnostic records the complete pre-deselection node list,
the post-selection counts, named capabilities, collector identity, and synthetic-process nodes.

## Exact structural diagnostic

At audited source `14298c1dfb51ffcb8afd5a39c83c598015a15781` (Git tree
`2ed4a821d3d3a13c98c44193f7d2585c049f0efc`), CPython 3.13.12 with pytest 9.0.3 collected **7,787**
nodes: **7,716 H0 + 71 H1**, with zero C0/P0/L0 nodes. Forty H0 nodes carry `synthetic_process`. The
canonical default-selection manifest has SHA-256
`98faf27745eab7168b6456056ba75762d7b63622fa1104c3839fb6e21cd8d1aa`.

The H1 capability index names `bwrap`, `cat`, `git`, `head`, `ls`, `printf`, `seq`, `setsid`, `sh`,
`sleep`, and `true`; counts overlap when one node requires multiple tools. The 71 H1 nodes comprise 14
Git nodes, 4 bwrap nodes, and 53 shell/coreutils-backed migration-debt nodes. That debt must move to
constrained H0 fixtures where semantics permit; it is not erased by assigning those nodes to H1.

This manifest is a provenance-bound development diagnostic, not an accepted candidate artifact. It does
not bind an accepted `0.3.10` candidate identity, an OS-isolation profile, or the complete verification-job
map, and it occupies no release evidence slot. `A-TAXONOMY` therefore remains `open`, and `RG00` remains
`OPEN`.

## Guard boundary

The H0 guard blocks ordinary Python socket, resolver, UDP, and subprocess entry points. The
`QUARRY_OFFLINE_CI=1` layer installs the network hooks before collection; the per-test autouse layer
provides the same runtime tripwire locally. An H0 `synthetic_process` node may start only a narrowly
validated current-interpreter child with constrained argv, environment, working directory, and descriptor
inheritance.

These controls are tripwires for tracked tests, not OS containment. A reviewed child can use its own
network API, and Python monkeypatches cannot prove that an escaped/native process has no route. Release
evidence still requires an OS-isolated H0 runner plus candidate-bound collection and job-map records. The
current limitations are recorded in the
[current audit](../docs/audit/CURRENT-HEAD.md#evidence-baseline).

## Other verification

`scripts/verify-quarry.sh` is a mixed diagnostic harness: it includes checks with external prerequisites
and may report `SKIP`. It is useful during development, but a skipped or unavailable required check is not
a release-gate pass. New offline-testable behavior belongs in pytest with the correct marker and in the
corresponding gate evidence, not only in the shell script. Private historical-run regression is governed
separately by the [golden-corpus contract](../docs/design/GOLDEN-CORPUS.md).
