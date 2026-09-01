# Changelog

All notable changes to CLIVE are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-01

### Fixed

- Ensured the canonical agent specification actually uses CLIVE-native finding domains (`Vulnerability`, `Logic`, `Integrity`, `Runtime`, `Configuration`) as the primary classification layer.
- Ensured OWASP, CWE, and other taxonomies are optional external mappings rather than audit boundaries or completeness criteria.
- Confirmed machine-readable findings use `domains` and `external_mappings` rather than vulnerability-specific classification fields.
- Corrected final self-check numbering and made the required reasoning order explicit: source behavior first, CLIVE domains second, optional external mappings last.

### Unchanged

- Source-only audit authority and static-only guard.
- Provenance-before-severity discipline.
- Independent severity and confidence.
- Attack/trigger-path tracing.
- Finding consolidation and composition analysis.
- Automatic provisional security-context derivation.
- Evaluation/remediation separation.

## [1.0.0] - 2026-09-01

### Initial public release

- Introduced **CLIVE — Code Logic, Integrity & Vulnerability Evaluator** as a personal OpenAI Codex custom agent.
- Added a source-only review constitution covering exploitable vulnerabilities, runtime defects, logic defects, software/security-control integrity, and security regressions.
- Added provenance-before-severity and independent severity/confidence rules.
- Added CLIVE-native finding domains: Vulnerability, Logic, Integrity, Runtime, and Configuration.
- Defined OWASP, CWE, and other taxonomies as optional external annotations rather than audit boundaries.
- Added mandatory attack/trigger-path tracing and finding-composition analysis.
- Added automatic provisional security-context derivation using Observed, Inferred, and Unknown evidence states.
- Added optional operator-authored `SECURITY_CONTEXT.md` support and candidate-context generation.
- Added Daybreak Blue with high reasoning as the default model configuration.
- Added a read-only default sandbox and static-only `PreToolUse` guard.
- Added personal install/uninstall scripts for macOS, Linux, and Windows PowerShell.
- Added deterministic configuration and capability-guard validation.
- Added MIT licensing and public documentation.
