![alt text](https://github.com/ryanmroth/CLIVE/blob/main/assets/cover.png?raw=true)

# CLIVE

**Code Logic, Integrity & Vulnerability Evaluator**

CLIVE is a personal, source-only security and correctness evaluator for OpenAI Codex.

Install CLIVE once under `~/.codex/` and invoke the same canonical evaluator from any local repository:

```text
Hey CLIVE, can you look at this code for me?
```

CLIVE is designed to behave like an independent senior reviewer rather than a generic vulnerability scanner. It evaluates exploitable vulnerabilities, runtime and logic defects, failures of software/security-control integrity, security regressions, and composed attack paths. It does **not** remediate code or execute the target project.

This is a community project and is not an official OpenAI product.

## What CLIVE means

**C**ode  
**L**ogic  
**I**ntegrity  
**V**ulnerability  
**E**valuator

The name reflects the review scope:

- **Code** — source and configuration are the evidence base.
- **Logic** — correctness, edge cases, state transitions, failure paths, and transaction behavior.
- **Integrity** — preservation of intended state, trust boundaries, authorization guarantees, security controls, and operational invariants.
- **Vulnerability** — attacker-exploitable weaknesses and composed attack paths.
- **Evaluator** — CLIVE weighs provenance, reachability, confidence, severity, and impact rather than merely recognizing suspicious patterns.

## Why CLIVE exists

Many automated code-review workflows are optimized to produce findings. CLIVE is optimized to produce **defensible findings**.

Its core rules require it to:

- trace a concrete attack or trigger path rather than flag a sink in isolation;
- establish input provenance before rating exploitability;
- keep severity separate from confidence;
- distinguish source-proven facts from runtime assumptions;
- consolidate repeated instances of the same root cause;
- perform a deliberate composition pass for multi-step attack chains;
- recognize security regressions in diffs, including removed controls;
- report exact file/line evidence and a specific remediation recommendation;
- avoid style-only review noise;
- remain independent from remediation.

## Installation model

CLIVE is a personal Codex custom agent installed once:

```text
~/.codex/
├── agents/
│   └── clive.toml
└── hooks/
    └── clive_guard.py
```

Nothing needs to be installed into each source repository.

## Model

The default configuration uses:

```toml
model = "gpt-daybreak-blue-latest"
model_reasoning_effort = "high"
```

Daybreak Blue is the intended model access path for this defensive secure-code-review workflow and requires separate entitlement.

If your Codex environment does not have Daybreak Blue, you may edit the `model` field to a model available to you. Different models may produce materially different review behavior.

## Source-only operating model

CLIVE is deliberately constrained to static repository evidence. It must not:

- modify source or configuration;
- apply patches or remediate findings;
- run tests, builds, linters, scanners, interpreters, containers, migrations, or project binaries;
- execute proof-of-concept payloads;
- make network requests;
- use apps/connectors/MCP tools;
- spawn additional agents.

The custom agent defaults to a read-only sandbox and uses a `PreToolUse` hook that allows a narrow set of static inspection commands while denying representative execution, write, network, MCP, and subagent paths.

## Security-context model

A project-specific `SECURITY_CONTEXT.md` is optional.

CLIVE checks, in order:

1. `.codex/SECURITY_CONTEXT.md`
2. `SECURITY_CONTEXT.md` at the repository root

If an operator-authored context file exists, CLIVE treats it as authoritative project policy layered on top of its core evaluator rules.

If no context exists, CLIVE derives the minimum useful provisional context from static repository evidence instead of falling back to a generic checklist.

Derived context can include:

- application architecture and frameworks;
- reachable and privileged entry points;
- authentication and authorization boundaries;
- trust boundaries;
- persistence and security-relevant data flows;
- process, filesystem, deserialization, and parser surfaces;
- CI/CD and infrastructure-as-code trust boundaries;
- outbound dependencies and trusted upstreams;
- security-critical validators, guards, and wrappers.

CLIVE internally distinguishes derived statements as:

| State | Meaning |
|---|---|
| **Observed** | Directly supported by visible source or configuration |
| **Inferred** | Strongly suggested by the repository but not fully established |
| **Unknown** | Materially relevant but unavailable in static scope |

Derived context cannot invent business criticality, production deployment facts, compensating controls, or severity floors.

Only operator-approved project context may define project-specific severity floors.

### Generate a candidate context

CLIVE can also produce a candidate context for operator review:

```text
Have CLIVE establish a candidate SECURITY_CONTEXT.md for this repository.
Do not write any files; output the candidate for my review.
```

CLIVE must not persist the candidate itself.

See [`SECURITY_CONTEXT.template.md`](SECURITY_CONTEXT.template.md) for an optional starting point.

## Requirements

- OpenAI Codex with custom-agent/subagent support.
- Python 3 available locally for the static-only hook.
- Daybreak Blue access for the default model configuration.
- A Git repository is recommended for diff and branch review workflows.

Relevant OpenAI documentation:

- Custom agents/subagents: `https://developers.openai.com/codex/subagents`
- Hooks: `https://developers.openai.com/codex/hooks`
- Daybreak Blue: `https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest`

## Install

### macOS / Linux

Clone or download the repository, then run:

```bash
./install.sh
```

The installer creates only:

```text
~/.codex/agents/clive.toml
~/.codex/hooks/clive_guard.py
```

Restart Codex after installation.

Manual installation:

```bash
mkdir -p ~/.codex/agents ~/.codex/hooks
cp clive.toml ~/.codex/agents/clive.toml
cp clive_guard.py ~/.codex/hooks/clive_guard.py
chmod 700 ~/.codex/hooks/clive_guard.py
```

### Windows PowerShell

Run:

```powershell
./install.ps1
```

or copy the two files manually to:

```text
%USERPROFILE%\.codex\agents\clive.toml
%USERPROFILE%\.codex\hooks\clive_guard.py
```

Restart Codex afterward.

### Replacing an earlier development build

For a clean installation, remove any earlier development build before installing v1.0.0. The v1.0.0 package contains no migration or compatibility logic for unpublished development identities.

## Usage

Invoke CLIVE by name from any repository.

### Natural invocation

```text
Hey CLIVE, can you look at this code for me?
```

### Audit a branch against `main`

```text
Have CLIVE audit this branch against main. Do not remediate.
```

### Audit a directory

```text
Ask CLIVE to audit src/auth/. Do not remediate.
```

### Audit a specific file

```text
Have CLIVE perform a source-only security and correctness review of src/api/users.py.
```

### Audit a diff

```text
Have CLIVE audit the current diff for security regressions, logic defects,
integrity failures, and vulnerabilities. Do not remediate.
```

### Request machine-readable findings

```text
Have CLIVE audit src/auth/ and include per-finding machine-readable JSON.
Do not remediate.
```

## Finding model

Every finding is expected to include:

- one or more CLIVE-native finding domains;
- severity;
- confidence;
- exact location;
- optional external taxonomy mappings when they materially help;
- attack or trigger path;
- description;
- concrete impact;
- minimal evidence;
- immediate remediation recommendation;
- long-term remediation only when materially useful.

Finding IDs use the `CLIVE-###` prefix.

### Native finding domains

CLIVE classifies findings using its own behavioral domains:

- **Vulnerability**
- **Logic**
- **Integrity**
- **Runtime**
- **Configuration**

A finding may belong to more than one domain. These domains describe what the code is doing wrong; they do not constrain what CLIVE is allowed to find.

### External taxonomy mappings

OWASP, CWE, and other external taxonomies are **optional annotations, not audit boundaries**.

CLIVE may map a finding to CWE when a precise weakness identifier is useful, and to OWASP Top 10:2025 when an application-security category materially helps communicate the result. An operator or project context may request other mappings.

A valid CLIVE finding does not require an OWASP, CWE, or other external taxonomy label. CLIVE must never use a taxonomy as its completeness checklist or omit a finding because no mapping exists.

The intended reasoning order is:

```text
source evidence
    -> provenance and reachability
    -> behavior and impact
    -> CLIVE domain(s)
    -> optional external mappings
```

### Severity and confidence

Severity and confidence are intentionally independent:

- **Severity** describes consequence under the supported path and provenance.
- **Confidence** describes how completely the visible source establishes the finding.

Missing evidence does not automatically increase severity.

## Evaluation scope

CLIVE evaluates five native finding domains. These domains can overlap:

### Vulnerability

Examples include injection, broken access control, unsafe deserialization, SSRF, path traversal, sensitive-data exposure, cryptographic misuse, and unsafe trust-boundary transitions.

### Runtime

Examples include resource leaks, race conditions, unsafe error handling, cancellation failures, integer/boundary defects, transaction failures, and availability-impacting runtime behavior visible from source.

### Logic

Examples include inverted checks, stale or invalid state transitions, missing edge cases, broken rollback behavior, and fail-open logic.

### Integrity

Integrity is broader than the CIA-triad data-integrity property. In CLIVE, it includes preservation of intended:

- authorization and authentication guarantees;
- state and transactional correctness;
- trust boundaries;
- validation and canonicalization controls;
- failure semantics;
- security controls;
- configuration invariants.

### Configuration

Configuration findings cover security-relevant deployment, CI/CD, infrastructure, permission, exposure, and hardening defects when they have concrete security or operational impact. Configuration is not a catch-all for generic best practices.

## Attack and trigger paths

Every finding must include a concrete path.

For a security finding:

```text
attacker or controllable entry
    -> intermediate calls / transformations / guards
    -> vulnerable sink
```

For a runtime or logic defect without an attacker:

```text
trigger / input / state
    -> intermediate calls or state changes
    -> failure point
```

If CLIVE cannot establish a complete path, it must identify the missing evidence and reduce confidence rather than present an assumption as fact.

## Provenance before severity

CLIVE traces where material values originate before deciding exploitability.

A suspicious sink does not automatically imply a vulnerability. A value constrained to a UUID, enum, server constant, canonical token, or another non-expressive format cannot carry an arbitrary payload simply because a later call uses string construction.

If provenance is incomplete, CLIVE must make the assumption explicit.

## Finding composition

After evaluating individual findings, CLIVE performs a deliberate composition pass.

It looks for combinations in which one condition changes the exploitability or impact of another, including:

- weakened trust plus dangerous downstream consumption;
- disclosure of a prerequisite for another vulnerability;
- fail-open behavior plus an attacker-triggerable failure;
- expanded privilege or reachability plus a second defect.

A materially stronger chain is reported as its own finding and references its constituent findings.

## Diff review

When auditing a diff or branch, CLIVE evaluates not only added code but also security controls that were removed or weakened.

Examples include:

- removed authorization checks;
- weakened validation;
- disabled TLS verification;
- widened permissions;
- reduced logging or alerting;
- changed trust assumptions;
- modified CI/CD privilege boundaries.

## Output discipline

CLIVE should not:

- invent findings to make a report look complete;
- report style-only issues without concrete security or operational impact;
- claim runtime validation it did not perform;
- expose secret values in the report;
- inflate severity because evidence is uncertain;
- remediate its own findings.

Clean reviewed areas are valid positive signal and should be stated.

## Security and permission model

The agent configuration declares:

```toml
sandbox_mode = "read-only"
approval_policy = "never"
web_search = "disabled"
```

It also disables apps, multi-agent spawning, and automatic Skill/MCP dependency installation.

The static-only hook permits a deliberately narrow command set such as `rg`, `grep`, `cat`, `ls`, and constrained read-only Git operations. It blocks project/test/build execution, writes, network clients, MCP tools, and child-agent creation.

### Parent permission mode

Codex subagents may inherit or reapply the parent turn's current permission overrides. For the strongest defense in depth, invoke CLIVE from a **Read Only** parent turn and do not use broad bypass/yolo-style permissions for review sessions.

### Hook boundary

Hooks should be treated as a guardrail rather than an absolute sandbox boundary. CLIVE's posture relies on the combination of:

- parent permission mode;
- child read-only defaults;
- hook enforcement;
- explicit source-only instructions.

## What the hook allows

Representative allowed operations include:

```text
rg / grep
ls / pwd
cat / head / tail / nl / wc
stat / file / readlink / realpath
constrained read-only git diff/show/grep/ls-tree/ls-files/cat-file/rev-parse
```

Representative denied operations include:

```text
python / node / shell project execution
pytest / npm test / build tools
package managers
network clients
repository scripts or binaries
apply_patch / edit / write tools
MCP tools
subagent spawning
shell pipelines, redirection, and command substitution
```

If an evidence-gathering operation is blocked, CLIVE must not bypass the guard. It should use another permitted static operation or lower confidence and identify the missing evidence.

## Validation

The repository includes a deterministic smoke test for the agent configuration and representative hook allow/deny behavior:

```bash
python3 validate.py
```

Expected result:

```text
PASS: CLIVE v1.0.1 agent configuration and static-only guard validated.
```

The validator checks configuration, the native-domain/external-mapping contract, and capability-guard behavior. It does not establish vulnerability-detection quality for every language, framework, or repository. Operators should evaluate CLIVE against representative code from their own environments.

## Updating

Pull or download a newer release and run the installer again. The installer replaces only CLIVE's two canonical personal files:

```text
~/.codex/agents/clive.toml
~/.codex/hooks/clive_guard.py
```

It does not modify source repositories or other Codex agents/hooks.

## Uninstall

macOS/Linux:

```bash
./uninstall.sh
```

Windows PowerShell:

```powershell
./uninstall.ps1
```

Uninstall removes only the two CLIVE files.

## Repository contents

```text
.
├── clive.toml
├── clive_guard.py
├── SECURITY_CONTEXT.template.md
├── install.sh
├── uninstall.sh
├── install.ps1
├── uninstall.ps1
├── validate.py
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

Only `clive.toml` and `clive_guard.py` are installed into `~/.codex/`.

## Design principles

1. **Exploitability over pattern matching.**
2. **Provenance before severity.**
3. **Source truth over runtime fiction.**
4. **Uncertainty changes confidence, not automatically severity.**
5. **Logic and integrity matter alongside vulnerabilities.**
6. **One evaluator sees the whole finding set.**
7. **Evaluation and remediation are separate authorities.**
8. **Project context is helpful, not mandatory.**
9. **Persistent project context requires operator approval.**
10. **Taxonomies annotate findings; they do not define the audit universe.**

## Limitations

- CLIVE is static/source-only by design and cannot prove runtime exploitability.
- The hook is a defense-in-depth guardrail, not an absolute sandbox boundary.
- Review quality depends on available source context and model behavior.
- Large repositories may receive a deep review of security-critical surfaces rather than a shallow full-tree review.
- Cross-repository provenance is available only when sibling repositories are visible and within operator-authorized scope.
- External runtime controls not represented in source may need operator context or dynamic verification.

## Responsible use

Use CLIVE only on source code and systems you own, operate, or are explicitly authorized to assess.

CLIVE is designed for defensive secure-code-review workflows and does not replace human security review, dynamic testing, threat modeling, or production validation where those are required.

## Contributing

Changes to CLIVE should be treated like changes to a security control. Prefer small, reviewable modifications with a regression case for behavioral rules that are added or corrected—especially rules affecting severity, confidence, provenance, tool restrictions, prompt-injection handling, logic analysis, or integrity analysis.

Before proposing a change, consider whether it:

- increases false positives;
- weakens the source-only boundary;
- changes severity without stronger evidence;
- fragments composition analysis;
- adds runtime claims CLIVE cannot verify.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT. See [`LICENSE`](LICENSE).
