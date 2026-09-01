# aiohttp 3.9.1 → 3.9.2 A/B Evaluation

This directory contains a controlled source-review comparison between:

- an established Claude security-review subagent; and
- CLIVE 1.0.0.

The evaluators reviewed authentic source-only snapshots of aiohttp 3.9.1 and 3.9.2.

The primary ground-truth issue was **CVE-2024-23334 / GHSA-5h86-8mv2-jq9f**, a static-resource path traversal fixed in aiohttp 3.9.2.

## Summary

Both reviewers:

- detected the primary traversal behavior in Candidate A (`v3.9.1`);
- identified the `follow_symlinks=True` precondition;
- traced the request-controlled path to file serving;
- did not reproduce the same direct traversal finding in Candidate B (`v3.9.2`);
- identified the static-directory-index XSS later fixed in aiohttp 3.9.4.

CLIVE returned a smaller finding set:

| Snapshot | Claude | CLIVE |
|---|---:|---:|
| Candidate A | 12 findings | 5 findings |
| Candidate B | 10 findings | 5 findings |

Finding count is descriptive only. This evaluation prioritizes supported paths, provenance, patched-version discrimination, and internal consistency over raw finding volume.

## Files

- [`methodology.md`](methodology.md) — experiment design and prompt
- [`source-manifest.md`](source-manifest.md) — exact upstream tags and commits
- [`ground-truth.md`](ground-truth.md) — post-freeze advisory comparison
- [`scorecard.md`](scorecard.md) — qualitative A/B assessment
- [`manifest.json`](manifest.json) — machine-readable evidence manifest
- [`reports/`](reports/) — publication copies of all four reports
- [`report-hashes.txt`](report-hashes.txt) — hashes of publication copies

## Important qualification

The project identity (`aiohttp`) was visible to both models. Frontier models may contain historical parametric knowledge of public vulnerabilities.

Accordingly, this evaluation demonstrates **source-supported vulnerable/patched discrimination**, not guaranteed de novo discovery on an unseen codebase.

## CLIVE version note

The evaluation itself used CLIVE 1.0.0.

CLIVE 1.0.1 subsequently corrected the finding-classification/output contract so CLIVE-native domains are primary and OWASP/CWE are optional external mappings.

That patch does not change the source-only reasoning, provenance, severity/confidence, attack-path, composition, or tool-boundary methodology evaluated here. The frozen 1.0.0 report format is preserved as evidence.
