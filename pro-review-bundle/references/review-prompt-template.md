# GPT Pro Review Request

## Goal

State the intended outcome in plain language.

## Current State

Describe what is true now, including source-of-truth docs, repo paths, tracker IDs, and live-state evidence if relevant.

## Proposed Plan

Describe the plan Codex is considering. Keep it concrete enough to review.

## Stop-Lines / No-Touch Zones

List what must not be changed without separate approval: production, secrets, schema, data, routing, deploy, external writes, payments, auth, etc.

## Risks And Assumptions

List the main assumptions, known risks, and places where the plan may be stale or incomplete.

## Privacy Classification

Classify the bundle as `PUBLIC`, `INTERNAL`, `CLIENT-CONFIDENTIAL`, `PII`, `SECRET`, or `PRODUCTION-SENSITIVE`.

State what was summarized or redacted. Never include raw secrets.

## Questions For GPT Pro

1. What hidden flaw or missing edge case would make this plan fail?
2. Which assumption is weakest?
3. What should be simplified before implementation?
4. What should remain explicitly out of scope?
5. What evidence would you require before proceeding?

## Desired Output

Return a concise review with:

- verdict
- top failure modes
- weakest assumption
- missing evidence
- recommended changes
- out-of-scope items
- safer alternative
- pre-flight checklist
