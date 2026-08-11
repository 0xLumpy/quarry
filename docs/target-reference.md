# Target reference

A project's scope and engagement rules live in `~/projects/<name>/target.yaml`, created by `quarry init`.
This page is the field-by-field reference. For *finding* the values (OSINT to fill `APEX_DOMAINS`, `CIDR`,
`ASN`), see [target-prep.md](target-prep.md).

> **Scope is authorization, not ownership.** Only add an apex/CIDR/ASN you have confirmed is **authorized
> and in program scope**. Ownership is supporting evidence; explicit authorization is the gate.

Empty sections skip cleanly — the minimum viable profile is one `APEX_DOMAINS` entry.

## Scope fields

| Field | Effect |
|-------|--------|
| `TARGET` | engagement name (required) |
| `APEX_DOMAINS` | in-scope apex roots (required). Discovery is anchored here by suffix match. `*.` is stripped to the root. |
| `OOS` | out-of-scope patterns — **regex against the full host**. Retained passively but ineligible for planned active contact. Prefer anchored patterns; a loose one silently drops in-scope hosts. Actual-peer/connect-time enforcement is tracked separately. Add from the CLI with `quarry oos`. |
| `CIDR` | in-scope IP ranges. Empty: no range expansion, no infra port scan. Setting it makes tlsx SAN, Caduceus, and reverse DNS *eligible* on the ranges (active runs, when the tool is installed). |
| `ASN` | ASN seeds. **Context only** — `quarry osint` expands them to CIDR candidates, but active range scanning still needs an explicit `CIDR`. An ASN alone never triggers a scan. |
| `ORG_NAMES` | organisation names. Anchor `quarry osint` broadening (ASRank ASN discovery, reverse-WHOIS) and seed cloud-bucket candidates. |
| `BRANDS` | short brand names. Seed cloud-bucket candidates during active recon (do not broaden OSINT). |
| `NOTES` | free-form list, recorded in the run manifest. |

```yaml
OOS:
  - '^jobs\.'                    # exclude jobs.*
  - '\.partner\.example\.com$'   # an out-of-scope branch
```

## RATELIMIT — pressure on the target

Blank means each tool's own default. Set these only when a program's rules of engagement cap you. (This is
target pressure; local concurrency is machine config — see [configuration.md](configuration.md).)

| Sub-key | Effect |
|---------|--------|
| `HTTP` | req/s for httpx, katana, nuclei, dalfox, ffuf |
| `DNS` | qps for puredns / massdns |
| `PORTSCAN` | naabu packet rate |

## PORTS

| Sub-key | Effect |
|---------|--------|
| `HTTP` | HTTP probe ports. Blank → the full methodology set (94 ports). |

## LIMITS

| Sub-key | Default | Effect |
|---------|---------|--------|
| `WAYMORE_RESPONSES` | 5000 | archived responses fetched per apex (`0` = all — heavy) |

## MODES

Booleans unless noted. These are the **shipped defaults**, not a "safe mode": screenshots, takeover
checks, and contacting in-scope hosts that resolve to private addresses are all on by default. The last
group is **consent-sensitive** — it arms active or credential-using work and stays off unless you set it.

| Mode | Default | Effect |
|------|---------|--------|
| `PASSIVE_ONLY` | `false` | no active probing or scanning at all — only passive sources run |
| `HEADLESS` | `false` | katana headless SPA crawl (chromium; RAM-heavy) |
| `SCREENSHOTS` | `true` | gowitness screenshots of live hosts |
| `TAKEOVER` | `true` | collect CNAMEs and run subdomain-takeover templates |
| `PORTSCAN` | `false` | infra port scan (naabu top-1000 → nmap). Needs `true` **and** `CIDR`. Distinct from the web-port SYN prefilter, which is machine config. |
| `BLOCK_PRIVATE_TARGETS` | `false` | when `false`, in-scope names resolving to private / CGNAT / ULA addresses are contacted and recorded as leads. Scanner-self, loopback, link-local and metadata destinations remain protected by policy; complete connect-time enforcement across every lane is an open `v0.3.9` release gate. |
| `CONTENT_DISCOVERY` | `"off"` | ffuf content discovery intensity: `off` \| `light` \| `balanced` \| `deep` |
| `CONTENT_RECURSION` | `0` | recursion depth for balanced/deep content discovery (capped at 5) |
| `JS_AST` | `false` | AST analysis of downloaded JS bundles (local, memory-hungry) → path/sink observations |
| `SECRET_VERIFICATION` | `false` | **sends discovered target credentials to their providers** to verify them. Off by default — this contacts third parties with found secrets. |
| `BLIND_XSS` | `false` | arm dalfox `--blind-oob` — a stored payload that can fire later in someone else's browser. A deliberate engagement decision. |
| `DEEP_EVIDENCE` | `false` | download heavy artifacts (heapdumps and similar) — the GET itself forces generation, so it is impact, not passive |
| `JS_CHUNK_BRUTE` | `0` | guess N webpack chunk ids (each guess requests a path no bundle named; capped at 3000) |

```yaml
MODES:
  PASSIVE_ONLY: false
  SCREENSHOTS: true
  TAKEOVER: true
  CONTENT_DISCOVERY: "light"    # ffuf content discovery on
  PORTSCAN: true                # infra scan — also needs CIDR set above
```

---

Run against the profile with `quarry run -t <name>` (a bare name resolves under `~/projects`). Preview the effective coverage
policy (the machine bounds, not a scope preview) with `quarry policy`. See
[running.md](running.md).
