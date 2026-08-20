# Changelog

All notable user-visible changes to Quarry are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
use semantic versioning. An `Unreleased` section is planning information, not a
nomination, tag, package, or release-gate result.

## [Unreleased]

### Added

- Candidate-bound release schemas, scope manifests, support/resource contracts,
  and deterministic evidence validation for the planned `0.3.10` integrity
  release.
- Private vulnerability reporting, contribution, project-license, and
  pointer-last release-process documentation.
- Separate H0, H1, and P0 pull-request jobs with immutable action references,
  package validation, dependency audit/SBOM output, and reviewed static-analysis
  and secret-scan baselines.

### Changed

- Runner, repository, revision, campaign, installer, resource, report, Nuclei,
  OOB, and network-policy paths are being hardened around explicit authority,
  bounded evidence, and fail-closed settlement.
- The development verification harness is target-free; explicitly authorized
  live-fixture diagnostics moved to a separate fail-closed script.
- `0.3.10` remains unreleased until the in-tree nomination prerequisites and
  external accepted aggregate are complete.

## [0.3.9]

- Baseline release preceding the `0.3.10` integrity program. Historical detail
  predating this tracked changelog remains available in Git history.

[Unreleased]: https://github.com/0xLumpy/quarry/compare/v0.3.9...HEAD
[0.3.9]: https://github.com/0xLumpy/quarry/releases/tag/v0.3.9
