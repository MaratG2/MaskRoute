# MaskRoute — Threat Model

## Assets

Protect:

- sensitive input data;
- secrets and credentials;
- business-confidential context;
- token-to-value mappings;
- policy configuration.

The token vault is trusted and sensitive.

## Trust model

Trusted:

- host application;
- MaskRoute policy engine;
- token vault;
- explicitly trusted internal tools/services.

Untrusted by default:

- external LLMs;
- web-search providers;
- third-party AI APIs;
- external agent tools.

Trust is configurable per destination.

## Security goals

- forbidden raw values do not cross external boundaries;
- restoration requires deterministic policy approval;
- tool outputs are protected before returning to external models;
- logs and exceptions do not leak raw values;
- tokens are isolated by execution/session scope;
- the LLM cannot override disclosure policy;
- disclosure is minimized when possible.

## Threats

### T1 — Direct disclosure
Raw sensitive data is sent to an external model.

**Mitigation:** protect before egress.

### T2 — Sensitive tool arguments
The LLM needs an internal value for a tool call.

**Mitigation:** the LLM uses tokens; the trusted gateway restores only after policy approval.

### T3 — Tool-response leakage
An internal tool returns raw sensitive data that is forwarded to the LLM.

**Mitigation:** protect tool output before external egress.

### T4 — Log leakage
Raw values appear in logs or traces.

**Mitigation:** masked logging by default.

### T5 — Exception leakage
Raw payloads appear in errors or telemetry.

**Mitigation:** sanitize exceptions before external reporting.

### T6 — Unauthorized restoration
A component tries to resolve a token for a forbidden destination.

**Mitigation:** token possession is not authorization; policy decides.

### T7 — Token guessing
A model fabricates tokens such as `⟦SECRET_10⟧`.

**Mitigation:** only tokens present in the current scope may resolve.

### T8 — Cross-session leakage
One session resolves another session's token.

**Mitigation:** isolate vault mappings by scope.

### T9 — Detection false negative
Sensitive data is missed.

**Mitigation:** combine detectors, support custom rules, measure recall.

### T10 — Detection false positive
Safe data is masked and task quality drops.

**Mitigation:** measure precision and downstream utility.

### T11 — Contextual re-identification
Identity can be inferred after direct identifiers are masked.

**Mitigation:** document the limitation; later support contextual minimization.

### T12 — Web-search context leakage
A search query exposes confidential surrounding context.

**Mitigation:** send only minimum necessary search terms.

### T13 — Public entity, confidential relationship
A public brand is safe alone but sensitive in context.

**Mitigation:** separate entity sensitivity from contextual sensitivity.

### T14 — Prompt-injection restoration attempt
Prompt content asks the model to reveal token mappings.

**Mitigation:** the model has no vault access; policy is outside the model.

### T15 — External tool as exfiltration channel
An agent tries to send protected values through a third-party tool.

**Mitigation:** enforce policy on all external tool arguments.

## Out of scope for v0.1

- compromised host OS/application;
- malicious administrators;
- memory scraping;
- dependency supply-chain compromise;
- full prompt-injection defense;
- legal compliance determination.

## Fundamental limitation

MaskRoute can only protect data it detects or that the application marks explicitly.

Detection recall below 100% is a design assumption and must be measured.