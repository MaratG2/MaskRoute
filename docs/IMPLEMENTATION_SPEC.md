# MaskRoute — Codex Implementation Specification

**Status:** v0.1 implementation hand-off; no code or security guarantees exist yet.  
**Companion:** [`PROJECT_DEFINITION.md`](PROJECT_DEFINITION.md) is the authoritative product definition.  
**Priority:** if the two documents disagree, follow `PROJECT_DEFINITION.md` and record the conflict before changing behavior.  
**Scope:** build and evaluate one secure-by-design *mediated* agent workflow, not a general-purpose DLP platform.

## 1. Expected outcome

Deliver a small installable Python package named `maskroute`, a synthetic travel-support demo, a minimal handwritten comparison implementation, adversarial tests, and reproducible benchmark results.

The reference interaction:

1. A trusted application knows an authenticated user and a private booking reference. It optionally receives mixed natural-language text with a name or phone number.
2. MaskRoute substitutes scoped references for sensitive data. Only the resulting protected content goes to the **mediated** external LLM interface.
3. The LLM proposes `lookup_booking(booking_ref=<protected reference>)`.
4. MaskRoute checks the issued reference, registered tool, exact input schema/field, policy and trusted host authorization. Only then does the trusted booking tool receive the original booking reference.
5. The booking tool returns a structured result with explicitly classified fields. MaskRoute protects private fields *before* any further model call; unknown fields are denied/withheld.
6. The LLM may request `search_baggage_policy` for an independently approved public airline and a fixed topic. Trusted code builds the limited public search query. The external search never receives a booking reference or private context.
7. A final plain-text answer may restore approved values only for the authenticated user's authorized display surface.

Use deterministic local model/search/tool stubs in CI. A real OpenAI-compatible provider integration may be an opt-in demo with user-provided credentials; it must **not** be required by tests or benchmarks.

### Definition of done

- `pip install -e .` works on Python 3.11+.
- `pytest`, Ruff lint/format check, and type checking pass locally and in CI.
- A runnable demo displays an allowed lookup, allowed limited search, and denied disclosure.
- Required adversarial tests pass and inspect actual mock-sink payloads.
- No tests, samples, metrics or documentation use employer data, internal code or real customer information.
- Benchmarks/report document both advantages and shortcomings relative to baselines; no fabricated results or implied security certification.

## 2. Trust boundary and invariant

```text
Trusted host application (identity, raw values, authorizer)
       │
       ▼
ProtectionSession
  ├─ explicit labels / optional best-effort detector
  ├─ scoped value ↔ opaque-reference registry
  ├─ model message assembly + issuance tracking
  ├─ registered tool schemas + disclosure policy
  ├─ trusted host authorizer
  ├─ structured tool-output filter
  └─ sanitized decision events
       │                            ▲
       ▼                            │
Mediated external LLM ── tool proposal (untrusted)
                                    │
                           validate + authorize
                                    │
                         ┌──────────┴─────────┐
                         ▼                    ▼
               Trusted booking tool    Public search builder
               approved fields only    approved public data only
```

**Enforcement is limited to paths actually routed through MaskRoute.** It does not intercept unrelated HTTP clients, provider-hosted web browsing, other logging layers, unconstrained tools, or host compromise. For explicitly marked values in these mediated paths, tests should establish *no forbidden disclosure in tested cases*. Free-text detection is best effort and may miss sensitive content.

The most important distinction: a reference being present in a session **is not** proof that the model was issued it, nor that the authenticated user can use it for this action.

## 3. Proposed minimal modules

| Module | Responsibility |
|---|---|
| `session.py` | Scope lifecycle; compose/send model-bound content; coordinate decisions |
| `references.py` | In-memory value registry, reference issuance, typed metadata, cleanup |
| `protection.py` | Explicit values/spans; optional lightweight regex/exact-match detection |
| `policy.py` | Destination/operation/field checks and trusted host authorization interface |
| `tools.py` | Strict tool-call parsing, registration, approved restoration, result filtering |
| `audit.py` / `errors.py` | Non-sensitive decision events and safe error types |
| `adapters/` | Optional single OpenAI-compatible adapter, isolated from core |

Avoid a framework, plugin system, distributed storage, policy DSL or class hierarchy unless the tests demonstrate a concrete need.

## 4. Data contracts

The following are **implementation targets**, not claims of an already existing API. Improve names if it makes the integration safer or simpler; document any departure.

### `ProtectionSession`

- Created by trusted host code with a verified `principal`/execution context and required authorization callback; fail closed if the callback is missing.
- One in-memory registry for the duration of a conversation/execution. Stable references for the same exact value and label within that scope; no cross-session linking.
- Supports creation, multiple authorized turns, and explicit `close()` / context-manager teardown. Closed-session references must be rejected. Do not promise secure RAM zeroization in Python.
- For v0.1, keep one session's operations serial; avoid shared concurrent mutable state. Independent sessions must remain isolated.

### `SensitiveValue` / `SensitiveSpan`

- Trusted code marks values or character spans with `kind` and `classification` (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`). The SDK must not treat labels supplied by the LLM as authoritative.
- Structured-value protection is deterministic. Span annotation validates boundaries and rejects overlaps/out-of-range offsets. Document that unlabeled repeated occurrences are **not** magically protected.
- An optional separate API (name it so its uncertainty is visible, e.g. `protect_text_best_effort`) uses local email/phone regexes and explicit application dictionaries. No model-based or enterprise-scale PII detection in v0.1.
- Expose detection misses/false positives in evaluation; do not imply best-effort output is safe for high-assurance use.

### `ProtectedRef`

- An opaque random reference with a type hint for model usability, backed by at least 128 bits of CSPRNG randomness. The format is not an authorization mechanism.
- Registry metadata: original value, kind, classification, scope, provenance, current state (issued/closed), and optionally the authorized resource identifier. Raw values must not appear in the reference, logs, error strings or object `repr`.
- Issue references to a particular model conversation **only when placed into a mediated outbound message**. Do not mark a ref issued merely because its string appears in untrusted text. Literal text resembling a token cannot create an issued reference.
- Unknown, guessed, unissued, revoked/closed, wrong-type or cross-scope references are rejected. Same-scope-but-unissued references are explicitly tested.
- Identity equivalence is exact per explicitly labeled value in v0.1, **not** full named-entity coreference (e.g. `Ivan` versus `Ivan Petrov`).

### Model-message construction

- Accept typed protected references / protected text and explicitly declared public text; do **not** build a security guarantee around arbitrary f-string interpolation of raw data.
- Ensure application developers deliberately opt into a best-effort free-text path; the protected-message interface should not silently transmit unknown raw fields as if certified safe.
- The LLM has no registry or authorizer access. All structured tool requests from the model are untrusted input.

### Tool registration and authorization

- Register only known tool names with closed input schemas (strict validation, reject extra fields and unexpected nesting), one destination identifier/class, and an explicit map from **argument field → permitted reference kind**.
- Before restoring a field: validate current scope, issued status, expected kind, exact tool+field permission and current host authorization for `(principal, action, resource, context)`.
- Authentication/authorization context must come from trusted host code, never from model arguments. A yes/no callback failure, timeout or exception means **DENY**.
- A permitted restoration is not permission to perform unrelated business actions. Business tools enforce their own authorization where appropriate.
- Never run a generic recursive string replacement over JSON, code, URLs or arbitrary model output. Unknown tool names/arguments fail closed.

### Tool output and final response

- Register explicit output field handling (`PUBLIC`, protected, or forbidden). Unknown fields are blocked/withheld by default. Nested or untyped payloads are rejected in v0.1 rather than silently forwarded.
- Return protected results to a model, and sanitize exceptions. The model must never receive raw confidential values from a trusted tool just because the tool was authorized to read them.
- Final display is a **separate authorization decision**. If implemented, restore only to an authorized user's *plain-text* response surface; do not interpolate secrets into Markdown links, HTML, URLs, tool calls or arbitrary generated structures.

### Events and errors

- Emit events such as `ALLOW`, `DENY`, `RESTORE`, `PROTECT` with reason codes, destination/tool and reference *kind*; exclude original values and mappings. Avoid including opaque handles by default.
- Errors use stable codes (e.g. `UNKNOWN_TOOL`, `UNISSUED_REFERENCE`, `UNAUTHORIZED`, `INVALID_SCHEMA`, `UNCLASSIFIED_OUTPUT`, `SESSION_CLOSED`) and sanitized messages; don't include potentially raw provider/tool exception payloads.
- Exceptions/errors destined for the LLM or telemetry must not echo raw inputs.

## 4a. Intended developer-facing usage (illustrative)

The package should make the safe path straightforward. This snippet shows **desired API semantics**, not mandatory final method names:

```python
with ProtectionSession(principal=verified_user, authorizer=host_authorize) as session:
    booking = session.protect_value(
        "BK-FAKE-101", kind="BOOKING", classification="CONFIDENTIAL"
    )
    # Public text is a deliberate assertion by trusted application code.
    message = session.prepare_model_message([
        PublicText("Look up my booking "), booking,
        PublicText(" and check its baggage rules."),
    ])
    model_reply = model_stub(message)          # Sees reference, not raw ID
    result = session.execute_tool_call(model_reply.tool_call)
    # result is protected again before any further model call.
```

Tools are registered on trusted setup code before the call. No unregistered tool or field may be executed or restored. `protect_text_best_effort(...)` is a separate, explicitly weaker entry point for unlabeled user text. Tool execution may use async internally; the contract and tests matter more than sync/async spelling.

## 5. Reference demo: precise operations

Synthetic fixture data (invent names/IDs, no real identities):

- `principal=traveler_a` owns booking `BK-FAKE-101`; `traveler_b` owns `BK-FAKE-202`.
- The internal lookup returns an airline reference explicitly certified by the host as public, along with private passenger/contact fields.
- Register only two permitted operations:

| Tool | Source → destination | Allowed model arguments | Private data policy |
|---|---|---|---|
| `lookup_booking` | Agent → trusted booking service | One issued `BOOKING` ref | Restore only to `booking_ref` after host authorization |
| `search_baggage_policy` | Agent → external search stub | Approved airline ref and fixed enum topic | Trusted query builder reveals only allowlisted public airline name + topic |

A search request such as `web_search(query="BK-FAKE-101 acquisition private details")` must fail: there is no registered generic search tool. Even if the airline name is public, the fact that it is being searched is shared with the search provider; document that.

For `lookup_booking`, add one **intentionally unexpected** output field such as `payment_token` in a hostile fixture. The output filter must refuse to forward it to the model unless explicitly classified/allowed. Tests should verify that output is withheld, not merely redacted in the UI after the external call.

The internal lookup may return a known public airline as an issued public handle. The external search builder independently checks it is approved for the external destination; a host label of `PUBLIC` alone does not authorize every external action.

## 6. Detector behavior and exact limits

- Build only a small local detector for emails, phone-like strings and exact dictionary entries. It is optional and not part of the hard security invariant.
- The deterministic path protects precisely the values/spans the trusted application identifies. It does not discover unknown aliases, contextual disclosure, secrets embedded in screenshots, or indirect identification.
- Do not pass arbitrary model-generated search text into an LLM classifier and call its answer an authorization decision.
- Unknown structured data fails closed; a best-effort natural-language detector can still miss information. Document these different guarantees prominently.

## 7. Stack, quality, and proposed layout

Recommended defaults: Python 3.11+, `pyproject.toml`, strict Python typing, `pytest`, `ruff`, `mypy` (or equivalent). Prefer standard library core; use Pydantic v2 only if it materially simplifies strict tool schema validation. Do not require a running database, GPU, model service or external network in the test suite. Pick one optional provider adapter rather than several.

```text
maskroute/
  AGENTS.md
  pyproject.toml
  README.md
  src/maskroute/
    __init__.py
    session.py
    references.py
    protection.py
    policy.py
    tools.py
    audit.py
    errors.py
    adapters/                # optional real provider demo only
  examples/travel_support/
    demo.py
    fixtures.py
  baseline/
    travel_support.py
  tests/
    test_references.py
    test_policy.py
    test_tools.py
    test_outputs.py
    test_detection.py
    test_demo.py
  benchmarks/
    run.py
    report.md               # real measured results, no placeholders
  docs/
    PROJECT_DEFINITION.md
    IMPLEMENTATION_SPEC.md
  .github/workflows/ci.yml
```

Keep README short: purpose, honest limitations, installation, a working 20-line usage example, test instructions, architecture overview, comparison references and link to measured benchmark. Do not claim production certification, GDPR/152-FZ compliance, zero leaks, or novel information-flow research.

## 8. Adversarial acceptance tests

All cases below should use synthetic data and a mock sink that records the **actual external request/response payload**. Inspect raw outbound LLM/search payloads and tool-call arguments, not only final rendered text.

| ID | Scenario | Expected behavior |
|---|---|---|
| S01 | Explicit booking value goes to model | Only protected ref, never raw ID |
| S02 | Same exact value in same scope | Stable ref; another scope gets unrelated ref |
| S03 | Valid authorized booking lookup | Correct internal resolution and successful tool result |
| S04 | Same-scope reference never issued to model | Deny |
| S05 | Fabricated/altered/wrong-kind reference | Deny |
| S06 | Reference copied from another session or after close | Deny |
| S07 | Correct ref but wrong user/resource/action | Host authorization denies; no tool side effect |
| S08 | Unknown tool, wrong field, extra key, nested JSON | Deny before tool handler |
| S09 | Protected ref inserted into external search/query/URL | Deny; no private raw value at search sink |
| S10 | Approved public airline and fixed baggage topic | Search gets only approved public terms |
| S11 | Internal tool outputs private and unknown fields | Private fields re-protected; unknown fields withheld |
| S12 | Prompt/tool-output injection requests mappings | No access to registry or bypass of policy |
| S13 | Missing/throwing authorizer, provider/tool failure | Deny or sanitized error; no unsafe retry |
| S14 | Logging, exception and trace paths | No raw protected values in emitted events or errors |
| S15 | Final authorized plain-text rendering | Only approved scoped values restored; no link/URL substitution |
| S16 | Mixed text with known undetected entity | Demonstrate/measure false negative; document limitation |

Do not count a test that merely checks a mocked return value as proof of non-disclosure; inspect captured sink payloads. Add tests for conflicting/overlapping explicit spans, token-like user text, unexpected binary or nested results, and session isolation.

## 9. Evaluation and benchmark contract

Compare the **same** synthetic tasks and threat fixtures against:

1. Unprotected model/tool workflow.
2. Blanket redaction.
3. Minimal handwritten reference-ID + authorization implementation.
4. MaskRoute implementation.
5. A relevant existing open-source solution **if its supported API fits the scenario**; document exclusions rather than inventing a weak comparison.

Measure:

- `legitimate_task_success` (allowed work actually completes);
- `forbidden_sink_disclosures` (raw protected values recorded at unapproved external sinks);
- `false_denials` (authorized operations incorrectly rejected);
- `reference_roundtrip_correctness` and `cross_scope_rejections`;
- `integration_effort` (app-side code, setup steps and observable policy complexity; qualitative trade-offs documented);
- `p50/p95` incremental overhead of core SDK operations with fixed hardware/test environment;
- for optional free-text detection only, entity-level precision/recall/F1 over labeled synthetic RU/EN fixtures.

**Release gate for v0.1:** all expected-valid deterministic scenarios succeed; all enumerated forbidden paths are rejected, with no protected raw value in recorded forbidden sink payloads; reproducible tests and benchmark instructions are published. These are finite-test results, not universal security guarantees. Do not fabricate numbers to populate a portfolio page.

## 10. Implementation order for Codex

1. **Baseline first.** Implement the tiny handwritten reference-ID + authorization travel scenario with fake tools and tests, without importing MaskRoute. Preserve it for fair comparison.
2. **Core registry + explicit protection.** Add session lifecycle, typed references, deterministic issuance, isolation and tests S01–S06.
3. **Tool gateway.** Add strict tool schemas, host authorizer, field-level disclosure and actual mock-tool execution. Pass S07–S10.
4. **Return path.** Add classified tool-output protection, sanitized errors/audit, authorized plain-text rendering. Pass S11–S15.
5. **Optional detection.** Add local email/phone/exact-match detection with explicit best-effort naming and measured limitations. Pass S16.
6. **End-to-end demonstration and measurement.** Add one runnable recorded demo, comparison harness, p50/p95 benchmark and documented failures. Optional real-model adapter only after deterministic gates pass.
7. **Publishability.** Package metadata, README, type checking, CI, minimal license decision for owner review, no real data; verify clean install and run instructions.

At each stage, run tests and show concrete results. Do not add a framework, database, dashboard, provider abstraction or policy language for imagined future customers. Do not push to a public repository or deploy external services without explicit authorization.

## 11. Decisions to record instead of guessing silently

These are implementation-level choices Codex may resolve through short experiments/ADRs, not invitations to redesign the product:

- Token syntax and behavior when model output changes token formatting; the reference's type hint must not carry authority.
- Strict schema implementation (Pydantic vs small manual validators), based on simplicity and test quality.
- Synchronization model: serial session operations initially; async provider/tool adapter optional.
- What constitutes a trusted `PUBLIC` field and how the host attests it in the demo.
- How to handle model text containing token-looking substrings without accidentally treating them as issued refs.
- Behavior when one result field is unclassified (withhold field or reject entire result; must fail closed).
- When a project maintainer should select the OSS license (Apache-2.0 or MIT are candidates; don't assume permission to publish).

**Stop condition:** if the handwritten baseline performs the same tasks with comparable enforcement and meaningfully less complexity, document that finding. The objective is useful, testable engineering—not proving MaskRoute must win.

## 12. External references

- [Presidio](https://github.com/data-privacy-stack/presidio) — mature PII detection/anonymization; possible future adapter.
- [PIIGhost](https://github.com/Athroniaeth/piighost) — conversational PII aliases and agent restoration.
- [Privacy Guard](https://github.com/mehrantsi/privacy-guard) — reversible per-conversation privacy handling.
- [Hermes Privacy Gateway](https://github.com/saiteja-madha/hermes-privacy-gateway) — related agent privacy gateway.
- [Microsoft Agent Framework security / FIDES](https://learn.microsoft.com/en-us/agent-framework/agents/security) — more comprehensive research-grade information-flow control.
- [Pipelock](https://github.com/pipelab-org/pipelock) — wider network/MCP egress enforcement.

These are comparison targets and architecture references, **not evidence that MaskRoute is superior**. Recheck current APIs before claiming feature parity.
