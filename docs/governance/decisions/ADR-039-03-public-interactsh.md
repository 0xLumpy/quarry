# ADR-039-03: public Interactsh is the default OOB backend

**Status:** accepted

**Decision date:** 2026-08-11

**Applies to:** Nuclei, Dalfox and Quarry-owned out-of-band probes

## Context

Out-of-band evidence is essential for blind SSRF, blind XSS and related findings. A public Interactsh
backend makes that capability available without requiring every operator to maintain infrastructure, but
the service operator can observe callbacks and associated data.

## Decision

Keep public Interactsh as the default. Operators can disable OOB acquisition or configure a self-hosted
backend for an engagement. The default must be visible in preflight, manifests and operator documentation;
it must not be described as a private channel.

## Required controls

- Record each OOB owner, backend class and session identity without storing authentication material in
  operational telemetry.
- Prove that an owner disabled by policy emits no callback-bearing request.
- Keep mappings, sessions and callback evidence owner-private and integrity-protected.
- Persist correlation state before egress, use sufficient token entropy, and retain unknown callbacks
  without falsely attributing them.
- Route late callbacks through certified revisions; never append them to a sealed base run.

## Consequences

Callback data leaves the local system under the default policy. Operators handling confidential targets
must make an explicit engagement choice to accept that transfer, disable OOB, or provide a self-hosted
backend. This ADR accepts the public default; it does not accept undocumented transfer, credential
exposure, false correlation, or broken opt-out behavior.
