# MaskRoute — Project Brief

## What it is

MaskRoute is a policy-aware privacy boundary for LLM applications and agents.

It detects sensitive information, replaces it with reversible tokens, and controls where original values may be disclosed.

## Core problem

LLM applications may handle data that should not be sent unchanged to external services:

- personal data;
- credentials and secrets;
- internal IDs;
- client or employee data;
- confidential project or brand names;
- business-sensitive context.

Simple redaction often destroys useful context.

Example:

```text
Ivan Petrov, +7 912 123-45-67
→
⟦PERSON_1⟧, ⟦PHONE_1⟧
```

The LLM can still reason about the entities without seeing their real values.

## Key idea

MaskRoute applies policy at every egress boundary.

The same value may be:

- masked for an external LLM;
- blocked from web search;
- restored for a trusted internal tool;
- redacted from logs.

The LLM never decides whether disclosure is allowed.

## Policy actions

- `ALLOW` — send the original value.
- `PSEUDONYMIZE` — replace with a stable token.
- `REDACT` — replace with a non-reversible placeholder.
- `BLOCK` — stop the operation.
- `ALLOW_WITH_MINIMIZATION` — disclose only what the destination needs.

## v0.1

- Python SDK;
- deterministic + NLP detectors;
- custom sensitive entities;
- reversible pseudonymization;
- scoped token vault;
- destination-based policies;
- LLM request/response protection;
- tool-call restoration;
- web-search minimization example;
- safe audit events;
- RU/EN benchmark and tests.

## Non-goals

v0.1 is not:

- a full DLP platform;
- a compliance product;
- IAM or authorization;
- a secrets manager;
- a complete prompt-injection defense;
- a SaaS control plane.

## Success criteria

Measure:

- detection precision/recall;
- secret leakage rate;
- restoration correctness;
- policy enforcement correctness;
- task-quality degradation;
- latency overhead.

MaskRoute does not claim perfect detection or automatic legal compliance.