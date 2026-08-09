# Quarry documentation

Quarry is an offensive bug-bounty recon framework: a deterministic methodology engine that maps a target's
attack surface, records provenance and coverage, and never asserts a finding it did not observe.

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
- [Secrets](secrets.md) — the credentials Quarry owns (`secrets.yaml`) and how they are redacted.
- [External integrations](external-integrations.md) — outside-tool keys, self-hosted OOB, notifications, operator-supplied data.
- [Tuning](tuning.md) — goal-based recipes for changing the settings above.

## Understand

- [Architecture](architecture.md) — how evidence moves through the phases, and the ownership boundaries.
- [Tools](tools.md) — every actionable tool Quarry integrates, credited to its upstream project.
- [Example run](example.md) — a complete, command-by-command worked campaign.

Design rationale (quota, scheduling, evidence, Dalfox, Shodan) lives under [`design/`](design/) — internal,
not part of the operator path.
