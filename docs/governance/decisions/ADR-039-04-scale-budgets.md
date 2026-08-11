# ADR-039-04: scale-oriented execution budgets

**Status:** accepted

**Decision date:** 2026-08-11

**Applies to:** large discovery, scanning, resolver and campaign workloads

## Context

Quarry is intended for high-scale reconnaissance. Fixed short deadlines, small universal caps, or silent
sampling can discard the evidence and coverage the framework exists to collect. Conversely, a computed
multi-day timeout without progress, checkpointing or cancellation is not an operable scale contract.

## Decision

Allow workload-scaled and potentially long execution budgets. Do not reduce a valid workload solely to
make a run finish quickly. Every budget remains explicit, observable and bounded when configured, and
unfinished work retains a truthful disposition.

## Required controls

- Chunk and checkpoint large lanes at stable work-unit boundaries.
- Enforce operator/global ceilings and meaningful progress or stall policies separately from legitimate
  long runtime.
- Bound aggregate memory, disk, processes, file descriptors and outstanding work across concurrent runs.
- Make cancellation settle child processes and evidence streams before returning.
- Persist replayable remainder where possible; otherwise report terminal evidence loss rather than
  calling key-only metadata resumable.
- Publish the supported workload/resource envelope and bind benchmarks to exact fixtures and hardware.

## Consequences

Some authorized runs may take hours or days. That is acceptable when progress and evidence are durable and
the operator can reason about completion. Starvation, indefinite teardown, unbounded resource growth and
false completion remain defects under this ADR.
