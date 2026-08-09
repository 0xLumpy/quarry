# Tuning

Goal-based recipes for changing the three configuration files. Each names the smallest set of knobs, the
consequence, and how to verify before running. For the full reference see [configuration.md](configuration.md)
and [target-reference.md](target-reference.md).

Verify any policy change with `quarry policy` (bounds) or `quarry plan` (what would run) before a run.

## Reduce pressure on the target

The program caps request rate. Set it in the profile, not the machine config:

```yaml
# target.yaml
RATELIMIT:
  HTTP: 5      # req/s for httpx, katana, nuclei, dalfox, ffuf
  DNS:  100    # qps for puredns
```

Consequence: `HTTP` bounds httpx, katana, nuclei, dalfox and ffuf; `DNS` bounds puredns. The infra port
scan uses `RATELIMIT.PORTSCAN`, and paid provider lanes have their own controls. Lowering concurrency alone
does **not** cap rate — these do.

## Use more local CPU / RAM

```yaml
# config.yaml
PERFORMANCE:
  PROFILE: aggressive     # a fixed higher concurrency multiplier (`auto` is the host-sized default)
```

Or override a single tool: `HTTPX_THREADS: 250`. Consequence: faster on your host; with no `RATELIMIT`
set, more workers can also hit the target harder.

## Increase Dalfox throughput

```yaml
# config.yaml
PERFORMANCE:
  DALFOX_WORKERS: 60      # per target (default 30)
  DALFOX_TARGETS: 8       # concurrent targets (default 4)
```

Consequence: more parallel XSS probing; bounded by `RATELIMIT.HTTP` if set.

## Time-box a large target overnight

```yaml
# config.yaml
PERFORMANCE:
  JS_FETCH_BUDGET_S: 3600
  A1D_BUDGET_S: 3600
  ARJUN_BUDGET_S: 1800
```

Consequence: each lane is checked between items against that many seconds (an in-flight item finishes), then
stores its remainder. Membership is never dropped — only deferred. Continue resumable lanes with
`quarry run -t acme --settle`.

## Widen free-tool work for one run

```bash
quarry run -t acme --unbound
```

Consequence: every registered free-work volume ceiling lifts to unbounded for this process. It obtains no
new sources and never changes scope, rate, spending, concurrency, or tool enablement.

## Remove the outer process timeout

```bash
quarry run -t acme --timeout 0
```

Consequence: no outer per-tool kill. A tool's own internal budget still applies. Use for a slow, trusted
run; a hung tool will not be force-stopped.

## Spend more provider budget

```yaml
# config.yaml
PERFORMANCE:
  SHODAN_CREDIT_RESERVE: 0     # spend all available query credits
  SHODAN_MAX_PAGES: 0          # pages per pivot until the balance runs out
  WHOXY_PAGE_BUDGET: 20        # up to 20 reverse-whois pages (1 credit each)
```

Consequence: paid lanes reach further. A malformed reserve or page-budget value fails closed (spends
nothing); `SHODAN_PAGE_TTL_DAYS` is the exception and falls back to 7 days.

## Enable content discovery

```yaml
# target.yaml
MODES:
  CONTENT_DISCOVERY: "light"    # off | light | balanced | deep
  CONTENT_RECURSION: 1          # for balanced/deep
```

Consequence: ffuf runs candidate-driven path discovery over live in-scope hosts.

## Run an authorized infrastructure scan

```yaml
# target.yaml
CIDR:
  - 198.51.100.0/24     # authorized + in scope
MODES:
  PORTSCAN: true        # needs true AND CIDR
```

Consequence: naabu → nmap runs on the confirmed ranges. Both gates are required; CIDR alone never scans.

## Arm consent-sensitive work

```yaml
# target.yaml
MODES:
  BLIND_XSS: true             # stored payload; can fire in someone else's browser
  DEEP_EVIDENCE: true         # downloads heapdumps — the GET forces generation
  SECRET_VERIFICATION: true   # sends discovered target creds to their providers
```

Consequence: these contact third parties or store impact — a deliberate engagement decision. Off by
default; arm only with explicit authorization. See [target-reference.md](target-reference.md).
