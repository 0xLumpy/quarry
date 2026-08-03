# openintel-subs — advanced optional passive source (our plan)

> **Verified state 2026-08-03 (`2bcd00a`): BUILT** — the silent opt-in lane exists as designed (`vertical.openintel`, local dataset, never a registered tool).


**What / why (for us):** extra PASSIVE subdomain coverage from a LOCAL OpenINTEL top1M subs DB
(~40M subs from 5 yrs of OpenINTEL forward-DNS on the Cisco Umbrella/Tranco top1M). A different
dataset than subfinder → **coverage** bucket. It's a self-contained Go binary + a ~2.5 GB SQLite
`subs.db` (in `~/workspace/Methodology/openintel-subs-dist/`).

**Design decision (2026-07-05): advanced opt-in, SILENT unless configured.**
- **NOT a registered tool** (not in `tools.yaml`) → `install` / `update` / `doctor` ignore it.
- Configured via `secrets.yaml`:
  ```yaml
  openintel:
    binary: /opt/openintel-subs/openintel-subs-linux
    db:     /opt/openintel-subs/subs.db
  ```
- `secrets.openintel()` → `{}` unless the block is set. `vertical` runs it ONLY when **both**
  `binary` and `db` are set AND present; otherwise it's silently skipped (no message, no warning).
- `doctor` shows an `openintel-subs (advanced)` line **only when configured** (✓/✗ on path presence);
  invisible otherwise.
- In `vertical` it runs `openintel-subs query -d <apex> -s -b <db>`, in-scope hosts → `subdomain`
  (`sources:[openintel]`, raw_ref). Best-effort — any failure yields nothing, never breaks the run.

**Why this shape:** Lumpy can use it for his own runs; a published-tool user never has to care (no
noise, no missing-dep spam). Advanced users who build/obtain the DB can flip the switch.

**Getting the DB:** user-provided (the binary + subs.db). Not auto-downloaded — the raw OpenINTEL
feeds are research-grade parquet (TB-scale, `openintel.nl/data`), impractical to fetch/build in an
install. FUTURE option (if we ever host a pre-built, daily-rebuilt subs.db): `quarry install/update`
could fetch it — but that's infra we'd run; not now.

**Other OpenINTEL datasets (looked 2026-07-05):** CT-forward-DNS → already covered (crt.sh +
certspotter) · reverse-DNS → dnsx `-ptr` · ccTLD apex lists → minor OSINT-breadth · **Zonestream
(real-time zone changes) → worth revisiting for a future continuous-monitoring / gungnir phase.**
openintel-subs (top1M subs) is the one unique practical add today.
