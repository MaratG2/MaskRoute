# MaskRoute — Pinned Project Definition

**Status:** design frozen for an experimental OSS vertical slice; no implementation, security audit, or product validation yet.  
**Updated:** 23 October 2026.  
**Canonical document:** supersedes previous MaskRoute hand-offs and architecture drafts when they conflict.

## Product and audience

**MaskRoute is a small Python SDK for reversible protection of sensitive values in LLM workflows and controlled disclosure to approved agent tools.**

**Tagline:** *Keep the context. Control the disclosure.*

**For:** Python developers building assistants with private application data, external LLMs, and internal/external tools. Not an enterprise DLP platform, compliance service, generic agent firewall, or automatic confidentiality detector.

**Problem:** Blanket redaction ruins context; unrestricted reversible substitution may reveal private values to the wrong tool, field, or destination. Developers need a compact way to preserve useful references while making disclosure decisions in trusted code.

**Differentiation hypothesis:** focus on **typed, per-field disclosure at tool execution** with a clear, framework-light API, fail-closed handling and reproducible security/utility tests. This is a packaging and engineering-quality hypothesis, **not a novelty claim**.

## Reference scenario

A synthetic travel-support assistant handles an authenticated user's private booking and researches a carrier's public baggage rules.

- The trusted application has a structured booking reference and may receive a free-text message containing a name, phone number, and public airline name.
- **Explicit protection:** application-supplied values and labeled spans are protected deterministically. **Optional detected protection:** lightweight local regex/exact-match checks cover some free-text values, with measurable false negatives.
- The LLM sees opaque, typed references (for example, `⟦BOOKING_<random>⟧`) and proposes an operation; it never receives the application's raw booking reference through the mediated model call.
- For `lookup_booking`, a trusted host authorization callback approves the principal/resource/action. MaskRoute additionally checks tool registration, argument schema, reference issuance, field-level disclosure policy, and scope before placing the original reference in the approved field.
- For `search_baggage_policy`, a trusted query builder uses a **separately approved public airline identity** and a fixed topic. The model cannot pass arbitrary confidential text as a search query. A confidential or unapproved airline name is denied even if a provider could technically search it.
- Model-bound tool results undergo field-aware protection again. Unknown/unclassified fields are withheld from the external model until the host classifies or explicitly approves them.
- Final-user rendering is separately authorized. Never automatically substitute references inside arbitrary URLs, tool calls, or untrusted output surfaces.

An isolated web search still discloses its search terms to the search provider. Pseudonymized context may still reveal identity through indirect clues.

## Architecture and security contract

```text
Trusted application: raw values, authenticated context, data labels
        |
        v
MaskRoute protection session
  - scoped reference registry + issued-to-model tracking
  - optional local text detector (best effort)
  - tool/schema registration + disclosure policy
  - host authorization callback + sanitized decision events
        |
        v
External model: protected context only
        |
        v
Proposed structured tool call (untrusted)
        |
        v
Validate: issued reference + scope + exact tool/field +
          host principal/resource/action approval + destination
        |                                 |
   approved tool                         DENY
        |
        v
Classify/protect tool output before another model call
```

**Non-negotiable rules:**

1. **A reference is not authority.** Use unpredictable opaque reference IDs; don't rely on randomness alone. A reference must be **issued to this model conversation**, belong to the current protection scope, and point to a resource the authenticated principal may use for the requested action. A reference that merely exists in the vault is insufficient. Unknown, unissued, expired, cross-scope, or unauthorized references are denied.
2. **The host owns identity and business authorization.** MaskRoute calls a trusted application-provided authorizer; it cannot independently establish user privileges. The model, user-entered text, and remote tool results cannot declare themselves trusted or override policy. A permitted disclosure does not by itself authorize a consequential business action.
3. **Reveal values only in approved typed fields.** Parse the tool call against a closed schema; reject unrecognized tools, arguments, nested payloads and disallowed reference use. No free-form recursive string substitution. External search accepts reviewed query templates and fixed topics, not arbitrary model-authored search strings.
4. **Default-deny at model-facing boundaries.** Unclassified tool-result fields must not silently become public. Tool outputs, exceptions and MaskRoute-owned events are protected before crossing the mediated external boundary. Do not log raw mappings.
5. **Coverage is limited to mediated integrations.** An SDK cannot prevent direct HTTP calls, unrelated logs, model-provider-hosted browsing, unwrapped MCP tools, images/audio, host compromise, or model inferences. Those need separate deployment controls. This project makes **no universal zero-leak, anonymity, or regulatory-compliance guarantee**.
6. **Explicit vs detected protection are different contracts.** For explicitly labeled values, tests can assert that MaskRoute's *own mediated operations* never reveal them to a forbidden sink. For free text, only measured best-effort detection is possible.

### Session lifetime

v0.1 uses a **conversation/execution-scoped, in-memory reference registry** with explicit creation and teardown; references persist across permitted turns within that scope but not across unrelated sessions. No persistent vault or cross-device identity linking.

## v0.1 implementation scope

**Build:** Python package; explicit value/span protection; tiny optional regex/exact-match detector; scoped registry; typed tool registration; host-authorization interface; approved internal-tool restoration; fixed-template public search example; protected tool responses; authorized plain-text final display; sanitized audit decisions; one end-to-end synthetic demo; hostile tests and measurements.

**Do not build:** dashboard/SaaS, managed proxy, generic shell/browser tools, custom NER model, long-term encrypted vault, complete policy language/IAM, network confinement, generalized semantic minimization, or automatic prompt-injection prevention.

**Implementation contract to test first:** Can a protected booking reference safely cross from a model-proposed typed tool argument into one specific authorized internal-tool field, while an external-search operation cannot receive it—even when the model fabricates or swaps references?

## Evaluation and decision gate

Test authorized booking lookup and public baggage search **and** abuse cases: same-scope but never-issued reference, wrong-user booking, cross-session reference, modified token, unsupported tool/field, nested JSON or URL smuggling, arbitrary search text, unclassified tool output, missing authorizer, model/provider errors, and sanitized logs. Include a mixed free-text example and document detector misses explicitly.

Measure **legitimate task success**, unauthorized disclosures in mediated calls, false denials, masking/restoration correctness, integration code complexity, and p50/p95 latency. Detection precision/recall applies **only** to the optional detection path. All datasets are synthetic and reproducible; a finite passing test suite is not a formal security proof.

Compare against (a) no masking, (b) blanket redaction, (c) a **minimal hand-written reference-ID + authorization implementation**, and (d) existing reversible-masking libraries **where they support the same scenario**. Do not handicap competitors.

**Go/no-go after the vertical slice:** if MaskRoute offers no meaningful improvement in safety, clarity, code reuse or testability over ordinary application code/existing OSS, publish the benchmark and engineering analysis rather than inflate a redundant package.

## Prior art and positioning limits

- [Presidio](https://github.com/data-privacy-stack/presidio): established PII detection/anonymization; use as an optional detector later, rather than recreating a full NER stack.
- [PIIGhost](https://github.com/Athroniaeth/piighost): mature pluggable detection, conversational aliases, agent-tool restoration; substantial direct overlap.
- [Privacy Guard](https://github.com/mehrantsi/privacy-guard): conversation vault with reversible aliases and tool-boundary restoration; substantial overlap.
- [Hermes Privacy Gateway](https://github.com/saiteja-madha/hermes-privacy-gateway): PII protection on model inputs/tool results and selected tool-argument restoration; direct overlap.
- [Microsoft FIDES / Agent Framework](https://learn.microsoft.com/en-us/agent-framework/agents/security): experimental integrity/confidentiality labeling, propagation and policy enforcement; broader information-flow controls than MaskRoute.
- [Pipelock](https://github.com/pipelab-org/pipelock): substantially broader mediated network/MCP egress security; not a direct SDK equivalent.

Their advertised capabilities are prior art, not proof that MaskRoute already outperforms them. MaskRoute is an **applied AI and software-security engineering** portfolio project, not evidence of advanced RAG or ML model training. Use no employer source code, architecture, data or internal policies.

## Next action

Stop revising the vision document. Build the **small hand-written baseline** and MaskRoute vertical slice against the same synthetic, adversarial test harness. Architecture choices not exposed by that experiment should stay undecided until needed.
