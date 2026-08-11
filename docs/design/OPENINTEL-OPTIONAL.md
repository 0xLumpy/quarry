# openintel-subs — advanced optional passive source (our plan)

> **Current status (audited 2026-08-11 at `4e4825c`): implementation present; release verification
> open.** `vertical.openintel` is a registered source backed by an operator-local dataset, while the
> executable is intentionally not managed as a registered install/update tool. `BUILT` below refers to
> the cited historical milestone, not current gate closure. See `C-TOOLS`, `C-OUTPUT-CONTRACT`, and
> `C-SOURCE-REGISTRY` in the [release gates](../releases/RELEASE-GATES.md).


**What / why (historical snapshot):** extra PASSIVE subdomain coverage from a LOCAL OpenINTEL top1M subs
DB (then measured at about 40M names from five years of OpenINTEL forward DNS over Umbrella/Tranco
top-lists). A different dataset than subfinder → **coverage** bucket. It used a self-contained Go binary
plus an approximately 2.5 GB operator-local SQLite `subs.db`; that local build path is not a repository
or installation contract.

**Design decision (2026-07-05; current configuration home corrected): advanced opt-in, SILENT unless
configured.**

- **Registered source, not a managed tool**: it appears as `vertical.openintel` in `sources.yaml` but is
  not in `tools.yaml`; `install` and `update` do not provision it.
- Configure the non-secret local paths in `config.yaml`:
  ```yaml
  openintel:
    binary: /opt/openintel-subs/openintel-subs-linux
    db:     /opt/openintel-subs/subs.db
  ```
- `settings.openintel()` reads `config.yaml` and retains backward compatibility with the legacy
  `secrets.yaml` block. An entirely unconfigured lane is silent. If both paths are configured but either
  is unusable, the lane records `SKIPPED` so configuration failure is observable.
- `doctor` shows an `openintel-subs (advanced)` line only when both path settings are present, with ✓/✗
  based on path presence; it is invisible otherwise.
- In `vertical` it runs `openintel-subs query -d <apex> -s -b <db>`, in-scope hosts → `subdomain`
  (`sources:[openintel]`, raw_ref). Configured execution uses the common runner and records its result. A
  non-clean result produces no normalized hosts and does not abort the phase, but remains visible in run
  evidence rather than being converted to a clean empty.

**Why this shape:** Lumpy can use it for his own runs; a published-tool user never has to care (no
noise, no missing-dep spam). Advanced users who build/obtain the DB can flip the switch.

**Getting the DB:** user-provided (the binary + subs.db). Not auto-downloaded — the raw OpenINTEL
feeds are research-grade parquet (TB-scale, `openintel.nl/data`), impractical to fetch/build in an
install. FUTURE option (if we ever host a pre-built, daily-rebuilt subs.db): `quarry install/update`
could fetch it, but only after the package/source identity, archive-fetch, provenance, and rollback gates
apply to that corpus; that infrastructure does not exist now.

**Other OpenINTEL datasets (looked 2026-07-05):** CT-forward-DNS → already covered (crt.sh +
certspotter) · reverse-DNS → dnsx `-ptr` · ccTLD apex lists → minor OSINT-breadth · **Zonestream
(real-time zone changes) → worth revisiting for a future continuous-monitoring / gungnir phase.**
openintel-subs (top1M subs) was the one unique practical addition selected in that review.
