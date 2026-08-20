# Quarry tests

Pytest development workflow for Quarry. Collection enforces exactly one primary execution lane for every
test before marker deselection. CI positively selects H0, H1, and P0 in separate jobs; it never selects
the live lane. These development jobs are not candidate release evidence. The authoritative isolation,
evidence, and promotion requirements are in the
[release-gate contract](../docs/releases/RELEASE-GATES.md).

## Run

```bash
pip install -e ".[dev]"     # package + pytest
pytest                      # positive H0 default (`-m offline` from pyproject.toml)
pytest -m offline           # explicit equivalent of the default H0 selection
pytest -m integration       # H1: named real tools against synthetic/local fixtures
pytest -m corpus            # C0: controlled private-corpus runner; currently no nodes
pytest -m packaging         # P0: package/supply verification (requires a built candidate)
pytest -m live              # L0: explicitly authorized live range; currently no nodes
```

Locally without an install: `PYTHONPATH=src pytest`. Set `QUARRY_OFFLINE_CI=1` to arm the session-wide
Python network tripwire before collection, as the current CI workflow does.

## Markers

Each collected node must have exactly one primary marker:

| Primary marker | Lane | Meaning |
|---|---|---|
| `offline` | `H0-hermetic` | Repository fixtures only; no network or undeclared external binary. The default and H0 CI job select this marker positively. |
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

At audited source `19ab50cbdc2415c78e9bb5651dec2e072bb3a71b` (Git tree
`8311829d62be4b7099979e2c0e2f476c2f94fc34`), CPython 3.13.12 with pytest 9.0.3 collected **7,867**
nodes: **7,796 H0 + 71 H1**, with zero C0/P0/L0 nodes. Forty H0 nodes carry `synthetic_process`. The
canonical H0-selection manifest has raw-file SHA-256
`732f26bfb49c48ad2bce556d782d43b3952b9dd1b661e5312a30705994c0938b`.

The H1 capability index names `bwrap`, `cat`, `git`, `head`, `ls`, `printf`, `seq`, `setsid`, `sh`,
`sleep`, and `true`; counts overlap when one node requires multiple tools. The 71 H1 nodes comprise 14
Git nodes, 4 bwrap nodes, and 53 shell/coreutils-backed migration-debt nodes. That debt must move to
constrained H0 fixtures where semantics permit; it is not erased by assigning those nodes to H1.

The committed Linux development runner produced this manifest from a private export of the exact commit,
inside its frozen bubblewrap profile, and bound it to the formal verification-job map and a candidate
identity. The result is still a collect-only development diagnostic, not an accepted candidate artifact:
the package is non-nominated `0.3.9`, the mounted host `/usr` runtime is untrusted and has no complete
dependency-closure attestation, and the summary explicitly declares `authority: none` and
`promotion_eligible: false`. It occupies no release evidence slot. `A-TAXONOMY` therefore remains `open`,
and `RG00` remains `OPEN`.

## Guard boundary

The H0 guard blocks ordinary Python socket, resolver, UDP, and subprocess entry points. The
`QUARRY_OFFLINE_CI=1` layer installs the network hooks before collection; the per-test autouse layer
provides the same runtime tripwire locally. An H0 `synthetic_process` node may start only a narrowly
validated current-interpreter child with constrained argv, environment, working directory, and descriptor
inheritance.

These controls are tripwires for tracked tests, not OS containment. A reviewed child can use its own
network API, and Python monkeypatches cannot prove that an escaped/native process has no route. The
separate development runner now provides a candidate-bound OS-isolated collection diagnostic, but it does
not execute the H0 suite or provide a trusted release-image/runtime closure. Release evidence still
requires those properties plus an accepted candidate-bound gate record. The current limitations are
recorded in the
[current audit](../docs/audit/CURRENT-HEAD.md#evidence-baseline).

## Other verification

`scripts/verify-quarry.sh` makes no target contact. Optional local binaries can still produce `SKIP`, so
its output is a development diagnostic rather than a release-gate pass. Authorized live fixture checks
live in `scripts/verify-quarry-live.sh`, which refuses to run without both an explicit approval flag and a
canonical `RANGE_APEX`; CI never invokes it. New offline-testable behavior belongs in pytest with the
correct marker and corresponding gate evidence. Private historical-run regression is governed separately
by the [golden-corpus contract](../docs/design/GOLDEN-CORPUS.md).
