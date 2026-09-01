# Methodology

## Objective

Evaluate whether CLIVE preserves the useful behavior of an established security-review subagent on a realistic source target with known vulnerable and patched states.

The comparison focuses on:

- known-vulnerability detection;
- patched-version discrimination;
- provenance and source-to-sink reasoning;
- precondition handling;
- confidence and severity discipline;
- false-positive restraint;
- source-only epistemic discipline;
- finding composition.

This is a focused case study, not a general benchmark of either model.

## Blinding model

The project identity was intentionally visible: both evaluators could determine that the source was aiohttp.

The prompts did **not** reveal:

- which candidate was vulnerable;
- which candidate was patched;
- the CVE/GHSA identifier;
- the relevant vulnerable feature as a hint;
- the security patch;
- the other evaluator's report.

The two snapshots were labeled only:

- `candidate-a`
- `candidate-b`

The version/status mapping was revealed only after all four reports had been captured and SHA-256 hashed.

## Workspace isolation

The candidate directories were outside the CLIVE Git repository.

They were generated with `git archive`, so the evaluation copies did not contain a `.git` directory or repository history.

This prevented the reviewers from consulting:

- commit history;
- commit messages;
- tags;
- patch commits;
- release-note history through Git.

Only the `aiohttp/` package tree was exported, which also excluded project-level GitHub metadata, test material, and documentation from the candidate workspace.

The aiohttp source itself was not renamed or rewritten.

## Snapshot creation

```bash
git archive v3.9.1 aiohttp | tar -x -C ../candidate-a
git archive v3.9.2 aiohttp | tar -x -C ../candidate-b
```

See `source-manifest.md` for exact release commits.

## Canonical substantive request

Both reviewers received the same substantive audit request:

```text
Perform an independent source-only evaluation of
aiohttp/web_urldispatcher.py and only the local callers and dependencies
needed to understand its behavior.

Evaluate concrete vulnerabilities, runtime defects, logic defects,
integrity failures, and security-relevant configuration issues.

Trace each entry or trigger through the relevant path to its sink or
failure point. Establish provenance where it materially affects
exploitability. Distinguish facts established from source from conclusions
that would require runtime confirmation.

Do not execute code, use the network, or remediate anything.

If no finding is justified, say so.
```

The parent session was instructed to invoke the dedicated reviewer and return the specialist report without summarizing, rewriting, or remediating it.

Each candidate/evaluator pair ran in a fresh session.

## Evidence freezing

The four raw reports were hashed before the candidate mapping and ground truth were examined.

Those hashes are in `report-hashes-original.txt`.

The publication reports are privacy-sanitized copies as described in `SANITIZATION.md`. Their separate hashes are in `report-hashes-published.txt`.

## Interpretation limits

Because `aiohttp` remained identifiable, either model could possess historical knowledge of public aiohttp vulnerabilities.

The benchmark therefore asks whether the output is substantiated against the presented source and whether the reviewer distinguishes the patched snapshot. It does not claim that recognition of a known CVE constitutes blind de novo discovery.

## CLIVE 1.0.1 note

The experiment used CLIVE 1.0.0.

A post-test 1.0.1 patch corrected the classification/output contract:

- native domains: `Vulnerability`, `Logic`, `Integrity`, `Runtime`, `Configuration`;
- optional external mappings: OWASP, CWE, or other requested taxonomies.

The reasoning methodology exercised here was not changed by that patch.
