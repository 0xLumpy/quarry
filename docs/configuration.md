# Configuration

Machine settings live in `~/.config/quarry/config.yaml`. They tune *how hard this host works* —
concurrency, budgets, provider spending — and apply to every project run from the machine.

Everything is optional; a blank value means the built-in default. Per-engagement settings (scope, rate
limits, modes) belong in the project's `target.yaml`, not here — see [target-reference.md](target-reference.md).

`quarry policy` prints the effective **policy bounds**, who set each, and what is held. A rejected value on
a *registered policy bound* falls back to its default and is surfaced there — a typo never silently loosens
a bound. Other invalid values (profile, concurrency, `WEB_PORT_PREFILTER`) also fall back to their default,
but quietly.

Everything sits under a top-level `PERFORMANCE:` map:

```yaml
PERFORMANCE:
  PROFILE: balanced
  HTTPX_THREADS: 200
  JS_FETCH_BUDGET_S: 1800
```

---

## Concurrency vs. rate

**Concurrency** — how many local lanes a tool runs — is a machine property and lives here. **Rate** — the
request rate a program's rules of engagement cap — is an engagement property and lives in `target.yaml`
under `RATELIMIT`. Note: with no `RATELIMIT` set, more workers **can** hit the target harder (more requests
in flight). Concurrency never *exceeds* a configured rate cap, but absent one it does raise real pressure.

## Scaling profile

| Key | Default | Effect |
|-----|---------|--------|
| `PROFILE` | `auto` | `safe` \| `balanced` \| `aggressive` \| `auto`. Only `safe` goes *below* a tool's own default; the others add lanes on bigger hosts. Multiplies every scaled concurrency value below. |

Blank per-tool concurrency is scaled from CPU count under the profile (`cores × factor`, floored at 4,
capped per tool). Set an explicit number to override the scaling entirely.

## Per-tool concurrency

| Key | Default | Effect |
|-----|---------|--------|
| `NUCLEI_CONCURRENCY` | scaled (cap 100) | nuclei local template concurrency (`-c`) |
| `HTTPX_THREADS` | scaled (cap 300) | httpx threads (`-t`) |
| `FFUF_THREADS` | scaled (cap 300) | ffuf threads (`-t`) |
| `KATANA_CONCURRENCY` | scaled (cap 50) | katana concurrency (`-c`) |
| `ARJUN_THREADS` | scaled (cap 40) | arjun threads (`-t`) |
| `DALFOX_WORKERS` | 30 | dalfox `--workers` per target (override-only, never scaled) |

## Batch / parallelism

| Key | Default | Effect |
|-----|---------|--------|
| `KATANA_PARALLELISM` | 10 | katana parallel hosts (`-p`) |
| `NUCLEI_BULK_SIZE` | 25 | nuclei hosts per template batch (`-bs`) |
| `NUCLEI_CHUNK_HOSTS` | 50 | live hosts per resumable nuclei invocation |
| `ARJUN_TARGETS` | 5 | concurrent arjun processes, at most one per host |
| `DALFOX_TARGETS` | 4 | dalfox `--max-concurrent-targets` |
| `DALFOX_CHUNK` | 40 | candidates per resumable dalfox batch |
| `PROVIDER_MAX_PAGES` | 5 | cursor pages per free-provider request |

## Coverage policy

Bounds on how far a lane reaches. `0` usually means "no limit" — but read each row: `SUBFINDER_MAX_TIME: 0`
is the 1440-minute maximum, not unbounded.

| Key | Default | Effect |
|-----|---------|--------|
| `NUCLEI_MAX_HOST_ERROR` | 0 (never drop) | connection errors before nuclei drops a host (`-mhe`). **Changing this invalidates nuclei resume state** — the next run rescans. |
| `SUBFINDER_MAX_TIME` | 60 | **minutes** per apex. `0` becomes the 1440-minute maximum (subfinder treats a literal 0 as "cancel"). Reaching the limit is reported as *partial*, not success. |
| `WILDCARD_ZONES_PER_RUN` | 5 | wildcard zones differentiated per run |

## Throughput budgets (seconds)

Every `*_BUDGET_S` is a wall-clock **ceiling in seconds**, and `0` (the default) means unbounded. A budget
bounds how long a lane runs — **never which input is eligible**. The budget is checked **between items**, so
an in-flight item finishes. Whatever it does not reach is counted; a resumable (`project_progress`) lane
picks it up on a later run, others repeat their prefix. Set one only to time-box a lane on a large target.

```yaml
PERFORMANCE:
  JS_FETCH_BUDGET_S: 1800     # ~30 min downloading JS this run (an in-flight item may run over); rest resumes
```

| Key | Lane it bounds |
|-----|----------------|
| `JS_FETCH_BUDGET_S` | crawl — JS file download |
| `SOURCEMAP_BUDGET_S` | crawl — source-map recovery |
| `CONTENT_FFUF_BUDGET_S` | content — ffuf sweep |
| `VHOST_BUDGET_S` | probe — vhost differentiation |
| `ARJUN_BUDGET_S` | params — arjun param discovery |
| `A1D_BUDGET_S` | enrich — A1d recursive brute |
| `WILDCARD_BUDGET_S` | vertical — wildcard differentiation |
| `SHODAN_HOST_BUDGET_S` | probe — free per-IP Shodan record lane (costs no credit; only time bounds it) |

## Acquisition byte ceilings

Byte governors on native acquisitions. All three `*_MAX_BYTES` default to `0` (unbounded) — paid and hostile
evidence is kept **whole**. The always-on host guard is the free-space reserve: an acquisition stops before
the artifact filesystem falls below it, keeps the partial it has, and records a typed truncation (an
`incomplete` acquisition), never a silent success.

| Key | Default | Effect |
|-----|---------|--------|
| `ACQUIRE_RESPONSE_MAX_BYTES` | 0 | ceiling on a single response (0 = unbounded) |
| `ACQUIRE_RUN_MAX_BYTES` | 0 | cumulative acquired bytes this run (0 = unbounded) |
| `ACQUIRE_PROJECT_MAX_BYTES` | 0 | cumulative acquired bytes across the project (0 = unbounded) |
| `ACQUIRE_FREE_RESERVE_BYTES` | 1 GiB | minimum free space kept on the artifact filesystem |

## Provider spending

Paid lanes (Shodan, Whoxy). A **reserve** is credits the run will not touch. A malformed **reserve** or
**page-budget** value issues *no paid request at all* — it fails closed. The exception is
`SHODAN_PAGE_TTL_DAYS`: a malformed value falls back to 7 days and does **not** block a request.

| Key | Default | Effect |
|-----|---------|--------|
| `SHODAN_CREDIT_RESERVE` | 0 | query credits held back (0 = spend what is available) |
| `SHODAN_MAX_PAGES` | 0 | pages per pivot (0 = until exhausted; the credit balance is the bound) |
| `SHODAN_PAGE_TTL_DAYS` | 7 | how long a purchased page substitutes for a fresh one. Past it, the page is kept as history and never silently re-bought. |
| `WHOXY_CREDIT_RESERVE` | 0 | reverse-whois credits held back (Whoxy charges one credit per page) |
| `WHOXY_PAGE_BUDGET` | 0 | pages this run may buy (0 = unbounded) |

## Toggles and paths

| Key | Default | Effect |
|-----|---------|--------|
| `WEB_PORT_PREFILTER` | `true` | SYN-check each host's public IPs before httpx and probe only open ports; `false` sends httpx at every port. This is **not** the infra port scan (that is `MODES.PORTSCAN` + `CIDR`). |
| `openintel` `{binary, db}` | unset | Extra passive subdomain source. A **top-level** key (not under `PERFORMANCE`); both paths must exist or it stays unused. |

```yaml
# top-level, beside PERFORMANCE:
openintel:
  binary: /opt/openintel-subs/openintel-subs-linux
  db:     /opt/openintel-subs/subs.db
```

---

Credentials (API keys, webhooks) are **not** here — they live in `secrets.yaml`. See
[secrets.md](secrets.md) and, for standing up the external services behind them,
[external-integrations.md](external-integrations.md).
