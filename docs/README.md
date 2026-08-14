# Quarry documentation

Quarry is an offensive bug-bounty recon framework: a methodology engine intended to map a target's attack
surface while recording provenance and coverage. Its current integrity release is specifically closing
paths that infer or flatten claims without sufficient evidence; see the
[current audit](audit/CURRENT-HEAD.md).

Start with the [main README](../README.md) for what Quarry is and a first install. This manual is the
operator reference, organised by task.

## Start

- [Installation](installation.md) — install on a blank host, verify with `doctor`, keep tools current.
- [Quickstart](quickstart.md) — the shortest path from `init` to a first run and its verdict.
- [Target preparation](target-prep.md) — OSINT to find authorized scope; [OSINT broadening](osint-broadening.md) for wider targets.
- [Target reference](target-reference.md) — every `target.yaml` field and mode.

## Operate

- [Running](running.md) — plan, run, phases, and the flag axes (`--passive`, `--timeout`, `--unbound`).
- [Campaigns](campaigns.md) — `--settle`: continuing a run across resumable work.
- [Outputs and coverage](outputs-and-coverage.md) — the output tree, entities, reports, and the run verdict.
- [Out-of-band](oob.md) — blind-XSS and OOB callbacks, and who owns each session.
- [Errors and recovery](errors-and-recovery.md) — what a symptom means and the safe next action.

## Configure

- [Configuration](configuration.md) — machine settings (`config.yaml`): concurrency, budgets, spending.
- [Secrets](secrets.md) — the credentials Quarry owns (`secrets.yaml`), their delivery boundary, and the
  limits of current text masking.
- [External integrations](external-integrations.md) — outside-tool keys, self-hosted OOB, notifications, operator-supplied data.
- [Tuning](tuning.md) — goal-based recipes for changing the settings above.

## Understand

- [Architecture](architecture.md) — how evidence moves through the phases, and the ownership boundaries.
- [Tools](tools.md) — every actionable tool Quarry integrates, credited to its upstream project.
- [Example run](example.md) — a complete, command-by-command worked campaign.

## Develop and release

- [Governance](governance/README.md) — authority, status language, and the accepted product contract.
- [Current-HEAD audit](audit/CURRENT-HEAD.md) — verified closures, reopened invariants, and release blockers.
- [Market baseline](audit/MARKET-BASELINE-2026-08.md) — sourced comparison with BBOT, reconFTW,
  ProjectDiscovery, and OWASP Amass/OAM.
- [v0.3.10 ledger](releases/v0.3.10.md) — the sole in-tree scope ledger and documentation projection for
  the pending release; accepted external attestations are result authority.
- [Release gates](releases/RELEASE-GATES.md) — hermetic, integration, corpus, package, fault, and publication evidence.
- [Roadmap](roadmap.md) — future sequencing and the deferred reporting prototype.
- [Golden corpus](design/GOLDEN-CORPUS.md) — private attestation and synthetic fixture rules.

Design rationale (quota, scheduling, evidence, Dalfox, Shodan) lives under [`design/`](design/) — internal,
not part of the operator path.
