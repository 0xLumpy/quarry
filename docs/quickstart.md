# Quickstart

The shortest path from nothing to a first run, on one authorized apex with default modes. Assumes
[installation](installation.md) is done and `quarry doctor` is clean.

## 1. Create a project

```bash
quarry init acme
```

Creates `~/projects/acme/target.yaml`. A bare project name (`-t acme`) resolves there from anywhere.

## 2. Set authorized scope

Edit `~/projects/acme/target.yaml` and **replace** the template's placeholder apex with the one you are
**authorized** to test:

```yaml
APEX_DOMAINS:
  - acme.com      # replaces the template's example.com
```

`quarry init` only fills the apex automatically when the project name is itself a domain, so replace
`example.com` by hand. That single line is a valid profile. Everything else is optional — see
[target-reference.md](target-reference.md) for every field and mode.

## 3. Broaden scope (optional, wider targets)

```bash
quarry osint -t acme
```

Discovers candidate apexes, ASNs, and CIDRs from passive sources and writes them to
`osint/latest/target.suggested.yaml`. It **never edits scope**.

## 4. Confirm candidates

Review `osint/latest/osint-report.md`, confirm each candidate is authorized and in scope, and uncomment
the approved entries from `target.suggested.yaml` into `target.yaml`. See [target-prep.md](target-prep.md).

## 5. Preview

```bash
quarry policy            # the effective coverage bounds this run will apply
quarry plan              # what would run, on this host, without scanning anything
```

## 6. Run

```bash
quarry run -t acme
```

The nine phases execute in order, writing evidence under `~/projects/acme/recon/<run-id>/`.

## 7. Check the outcome

```bash
quarry status -t acme
```

The run ends with a verdict: `complete`, `complete_with_limits` (an expected provider/operator bound was
hit), or `complete_with_gaps` (something failed — coverage needs attention).

## 8. Read the results

Open the ranked manual-validation queue and the coverage summary:

```
~/projects/acme/recon/<run-id>/reports/HOTLIST.md
~/projects/acme/recon/<run-id>/manifest.json
```

See [outputs-and-coverage.md](outputs-and-coverage.md) for what everything means, and
[example.md](example.md) for a full command-by-command trace.
