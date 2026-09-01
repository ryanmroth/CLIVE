# Security Context

> Optional operator-approved project context for CLIVE.
> CLIVE does not require this file: when none exists, it derives a
> provisional context from static repository evidence. Do not put secrets here.

## System purpose

Describe what the system does and the security consequences of compromise.

## Deployment and reachability

- Internet-facing surfaces:
- Internal-only surfaces:
- Administrative surfaces:
- Background/worker surfaces:
- CI/CD execution surfaces:

## Trust boundaries

| Boundary | Lower-trust source | Higher-trust destination | Required controls |
|---|---|---|---|
| Example | Public HTTP client | API service | Authentication, authorization, schema validation |

## Attacker capabilities

Describe realistic attacker positions that should drive severity.

## Sensitive assets and data

List categories, never secret values.

## Security-critical controls

List helpers/guards CLIVE should trace rather than assume.

## High-risk patterns

Project-specific patterns requiring special attention.

## Stack-specific checks

Framework/runtime/IaC checks not already covered by CLIVE.

## Severity floors

Only define floors that reflect operator-approved business/security impact.

## Explicit scope exclusions

List only operator-authorized exclusions. An exclusion does not hide an
in-scope attack path that crosses an excluded component.

## Cross-repository provenance

List sibling repositories/services that may be consulted when available and
within the operator-authorized workspace.
