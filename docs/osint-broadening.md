# Manual OSINT broadening

`quarry osint` automates the programmatic OSINT (ASN expansion, reverse-WHOIS, Azure/M365 tenant,
DMARC, RDAP netblock candidates, Postman leaks). Some of the richest scope-expansion sources are
**web UIs or API-gated** and can't be automated cleanly — on **larger targets** they're worth doing
by hand. This is the playbook.

**The rule never changes:** these surface *candidates*. **Confirm each is in program scope /
authorized before adding anything** to `target.yaml`, and never active-scan a range you haven't
verified is in scope. Authorization — not ownership — is the gate: in a bug-bounty context an
in-scope asset may not be one you "own", and an asset you own may be out of scope.

---

## 1. ASN / IP ranges
- **bgp.he.net** — search the org name *and* free-form descriptions; note ASNs, related
  subsidiaries, country, and announced prefixes.
- **asrank.caida.org** (CAIDA ASRank) — map parent/child/sibling ASN relationships around the org.
- **ARIN / RIPE** (and other RIRs) — RDAP UI or full-text search by org/handle to confirm netname,
  registration, and inetnum relationships.
- → For each confirmed range, add to `CIDR` / `ASN` in the profile. `quarry osint` already emits
  RDAP CIDR *candidates* for resolved IPs — treat those as a starting point, not gospel (a resolved
  IP is often a CDN/shared host, not target-owned).

## 2. Acquisitions / subsidiaries / brands
- **Crunchbase · Tracxn · Pitchbook · OCCRP Aleph · SEC EDGAR** — find acquired companies,
  subsidiaries, and legal entities.
- → New brands/apexes feed back in: add them to `APEX_DOMAINS` / `BRANDS` / `ORG_NAMES` and **re-run
  `quarry osint`** so reverse-WHOIS and tenant discovery expand from the new seeds.

## 3. Ad / analytics relationships
- **builtwith.com** (Relationships tab) — shared Google Analytics / NewRelic / Ads IDs link
  sibling properties that share infrastructure or ownership.
- → Candidate apexes; verify before adding.

## 4. Cloud certificate sweep
- **Caduceus** over *confirmed in-scope* ASN ranges + **merklemap.com** — surface hostnames from
  certificates on cloud/edge IPs in scope. Best run once you've confirmed some ranges (§1).
- → Hostnames feed subdomain/scope review.

---

## Feeding results back
1. Collect confirmed apexes / ASNs / CIDRs / brands from the above.
2. Add the **verified** ones to `target.yaml` (or paste into `target.suggested.yaml` for review).
3. Re-run `quarry osint` if you added new seeds (it expands from them).
4. Then run recon against the confirmed scope.

*(A future `quarry osint --import` will parse collected candidates into `target.suggested.yaml`
automatically — for now it's copy-by-hand, deliberately, so a human confirms every scope addition.)*
