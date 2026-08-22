# Contributing to Quarry

Thanks for helping improve Quarry. Changes must preserve its core rule: broad
reconnaissance is acceptable only when actions, omissions, evidence, and
coverage are represented truthfully.

## Before opening a change

- Work only with synthetic fixtures or systems you are explicitly authorized
  to assess. Pre-release CI never authorizes live contact.
- Open a private security advisory for scope escapes, credential exposure,
  installation boundary failures, or evidence-integrity bypasses; do not file
  those details publicly.
- Keep behavior changes narrow. Explain any compatibility, policy, evidence,
  migration, and resource-envelope consequences.
- Add a regression that exercises the semantic failure, including its fault or
  cancellation boundary where relevant.

## Development setup

Quarry supports the finite Linux/Python matrix recorded in
`release/evidence/support-matrix-v1.json`. For ordinary development:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev,ci]'
.venv/bin/python -m pytest -m offline
```

Every test must have exactly one primary lane. Use `offline` for hermetic tests,
`integration` for an attested real tool against a synthetic local fixture,
`corpus` for controlled private-corpus replay, `packaging` for package/supply
checks, and `live` only for a separately authorized range. See
`tests/README.md` for marker and isolation rules.

Before submitting, run the affected tests, the offline suite, and the committed
quality/security checks used by CI. Update user-facing documentation and the
`Unreleased` section of `CHANGELOG.md` when behavior changes. Generated or
content-bound release inputs must be regenerated with their documented tool;
never hand-edit a digest to make a gate pass.

The initial quality boundary is intentionally explicit: fatal Ruff rules run
across Python sources and tests, mypy covers the listed release-integrity
modules, Bandit high-severity findings must equal the reviewed expiring
exception manifest, detect-secrets rejects additions outside its audited
baseline, and the package job audits declared dependencies. Broader legacy
lint/type debt is not presented as already clean.

## Review and release integrity

Reviewers may require fault injection, cross-version replay, exact artifact
hashes, or an independent read-only audit for authority-sensitive changes.
Commits do not close release gates by assertion. Candidate nomination,
candidate-bound evidence, detached approval, tagging, and publication follow
`docs/releases/RELEASE-PROCESS.md` and the canonical release-gate contract.
