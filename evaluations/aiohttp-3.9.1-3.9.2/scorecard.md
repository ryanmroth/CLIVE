# A/B Scorecard

## Result

CLIVE passes the primary test.

Both reviewers detected the primary Candidate A traversal and both recognized that the direct traversal condition was fixed in Candidate B.

## Comparison

| Criterion | Claude | CLIVE | Result |
|---|---|---|---|
| Candidate A primary traversal detected | Pass | Pass | Tie |
| `follow_symlinks=True` precondition recognized | Pass | Pass | Tie |
| Request-controlled input traced to file-serving sink | Pass | Pass | Tie |
| Candidate B direct traversal fix recognized | Pass | Pass | Tie |
| Candidate A issue not blindly carried into B | Pass | Pass | Tie |
| Static-index XSS identified in A and B | Pass | Pass | Tie |
| Runtime/deployment uncertainty stated | Pass | Pass | Tie |
| Source-only/no-remediation posture maintained in report | Pass | Pass | Tie |
| Finding selectivity | 12 A / 10 B | 5 A / 5 B | CLIVE more selective |
| Candidate A composition consistency | Internal tension noted | No unsupported stronger chain | CLIVE advantage in this run |

## Finding-set size

### Candidate A

- Claude summary: 12 findings, including one chain.
- CLIVE summary: 5 findings, no additional chain.

### Candidate B

- Claude summary: 10 findings.
- CLIVE summary: 5 findings.

Finding count is reported for transparency only.

## Source-centered reporting

Claude's Candidate A report directly names CVE-2024-23334 and the upstream fixed version.

Claude's Candidate B report explicitly says the source matches its recollection of the upstream 3.9.2 fix.

CLIVE's reports do not rely on the CVE identity. Candidate A describes the vulnerable source path directly; Candidate B records direct dot-segment traversal as confined by the visible checks.

This does not establish absence of parametric memory. It does show a more source-centered returned report in this particular comparison.

## Composition consistency

Claude Candidate A creates a High chain from traversal → out-of-root directory indexing → XSS.

The same report separately states that an out-of-root directory reaches `_directory_as_html()` and raises `ValueError`, resulting in a 500.

Claude Candidate B later explicitly reasons that the analogous `ValueError` condition pre-empts the chain.

This creates an internal tension in the Candidate A composition result.

CLIVE Candidate A runs its composition pass and reports no additional materially stronger chain.

This is a qualitative consistency observation, not dynamic proof of either exploit path.

## Provisional conclusion

For this first case study:

- Known-vulnerability recall: **tie**
- Patched-version discrimination: **tie**
- Source-centered presentation: **CLIVE advantage**
- Low/informational recall: **Claude advantage**
- Finding selectivity: **CLIVE advantage**
- Composition consistency: **CLIVE advantage in this run**

No change to CLIVE's core reasoning methodology is justified solely from this result.

CLIVE 1.0.1 changes the classification/output contract after this test but does not alter the reasoning rules evaluated here.
