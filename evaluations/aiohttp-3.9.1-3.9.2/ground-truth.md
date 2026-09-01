# Ground Truth

Ground truth was reviewed only after all four evaluator reports were captured and SHA-256 hashed.

## Primary issue: CVE-2024-23334 / GHSA-5h86-8mv2-jq9f

Authoritative references:

- https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f
- https://github.com/advisories/GHSA-5h86-8mv2-jq9f
- https://github.com/aio-libs/aiohttp/pull/8079/files

The reviewed advisory identifies:

- affected versions: `>= 1.0.5, < 3.9.2`;
- patched version: `3.9.2`;
- weakness: path traversal (`CWE-22`);
- relevant condition: static-resource serving with `follow_symlinks=True`;
- impact: reading files outside the intended static root.

Therefore:

- Candidate A (`v3.9.1`) is expected to contain the vulnerable direct traversal behavior.
- Candidate B (`v3.9.2`) is expected to contain the fix.

Both Claude and CLIVE satisfy this primary vulnerable/patched discrimination.

## Secondary known issue: CVE-2024-27306 / GHSA-7gpw-8wmc-pm8g

References:

- https://github.com/aio-libs/aiohttp/security/advisories/GHSA-7gpw-8wmc-pm8g
- https://nvd.nist.gov/vuln/detail/CVE-2024-27306

The vulnerability is XSS in aiohttp-generated static-file index pages and is fixed in 3.9.4.

Both Candidate A and Candidate B predate that fixed version.

Both evaluators identified the underlying unescaped static-index behavior and conditioned practical exploitability on the ability of a lower-trust actor to influence filesystem names / indexed content.

## Compressed sibling symlink mechanism

Both evaluators also identified a path in which a validated static asset can later be replaced by a `.gz` sibling without equivalent confinement checks.

A later reviewed advisory, CVE-2024-42367 / GHSA-jwhx-xcg6-8xhj, describes the same compressed-file/symlink mechanism. Its reviewed affected range is `>= 3.10.0b1, < 3.10.2`.

Accordingly, this evidence package treats the 3.9.x reports as **source-supported and externally corroborated in mechanism**, but does not claim the evaluators discovered CVE-2024-42367 in 3.9.x.

## Evaluation principle

A public CVE match is useful ground truth, but finding count is not a quality metric by itself.

The comparison favors:

- correct vulnerable/patched discrimination;
- complete and source-supported attack/trigger paths;
- accurate provenance;
- explicit deployment/configuration preconditions;
- defensible severity and confidence;
- internal consistency;
- restraint where exploitability cannot be established.
