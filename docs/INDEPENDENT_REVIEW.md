# Independent security-oriented review of MaskRoute v0.1

Review date: 26 October 2026. Status: completed; both narrow fixes independently verified,
with the resource-identity reuse limitation retained. This is a separate AI code review, not an external human audit,
certification, formal proof, or claim of complete attack coverage.

## Scope and method

The reviewer read `AGENTS.md`, `docs/PROJECT_DEFINITION.md`, and
`docs/IMPLEMENTATION_SPEC.md` before inspecting the complete `src/maskroute` package, travel
integration, new project-management integration, and relevant tests. The canonical product
definition was used to distinguish mediated-path guarantees from trusted-host responsibilities.
No conflicting requirement was found that required a change to the canonical scope.

The review used code tracing, local synthetic reproductions, and actual recording-sink assertions.
It did not modify the SDK or existing tests, invoke an external provider, transmit project data,
commit, publish, or push. The reviewer owns this document only. The nine Python SDK files matched
`docs/validation/sdk_baseline_hashes.json` before fixes (9/9 SHA-256 matches).

No model-only exploit of reference issuance, field authorization, or tool-output confidentiality
was reproduced in the supported serial, correctly configured path. Two conditional host-integration
defects were reproduced below. Neither finding gives an untrusted model access to Python callbacks,
configuration objects, or private session attributes.

Unless explicitly marked current, source line numbers in this review refer to the original SDK
captured by the frozen hash manifest. The verified fixes changed only `tools.py`, `policy.py`, and
`session.py`; their current locations are recorded with each finding below.

## Findings

### R1 — Low: immutable configuration retains mutable nested collections

**Scope:** defensive correctness for host configuration; not a model-only policy bypass. Passing
mutable sets/lists violates the annotated `frozenset`/`tuple` types, but runtime constructors
accept them, and the otherwise frozen/snapshotted configuration then retains their live contents.

**Original evidence:** `src/maskroute/tools.py:16-31` freezes field objects without freezing their
collections. `ToolSpec.__post_init__` validates contents and copies the field/output dictionaries
at `tools.py:66-98`, but retains each rule object. `src/maskroute/policy.py:16-27` likewise retains
the rule sequence and each classification collection. Membership checks later read those live
objects (`src/maskroute/session.py:249-251`, `266-270`, `334-335`; `policy.py:38-45`).

**Reproduced result:** creating `choices = {"carry_on"}` and `allowed = {"confirmed"}`, supplying
them to `EnumField(choices)` and `PublicOutput(allowed)`, and registering the tool succeeds.
Adding `"new_value"` to both original sets after registration allows a subsequent model proposal
with that value and sends the JSON `{"state": "new_value"}` to the model. No new registration or
explicit policy replacement is required. The reproduction printed
`mutable_config_extended_after_registration=True`.

**Impact:** a host that reuses or mutates a setup collection can silently expand the accepted input,
public output, search allowlist, or disclosure classification. Existing correctly typed immutable
configurations are unaffected. A malicious model cannot itself mutate these objects through the
documented tool-call interface.

**Narrow remedy:** defensively normalize the documented nested rule collections at construction,
including policy rules, classifications, enum choices, public output vocabularies, and public
search values. A regression should mutate
the original host collections after registration and verify the boundary retains its original
decisions. This does not require a policy language or new public feature.

**Disposition: fixed and independently verified.** Current `tools.py:21-22`, `29-30`, `39-40`
copy the three field vocabularies to `frozenset`; current `policy.py:24-25`, `32-33` copy
classification sets and the rule sequence. The original reproduction now fails with
`INVALID_SCHEMA` and **zero model calls**. All five collection-mutation regressions pass.
This fix snapshots documented collection inputs; it does not turn trusted configuration into
an arbitrary untrusted-object validation interface.

### R2 — Low: callback lifecycle changes are not rechecked before disclosure

**Scope:** host callback reentrancy/lifecycle correctness, not a demonstrated remote exploit.
The architecture requires serial session use and trusted callbacks; an application that reenters
the same session from a callback is outside a strict non-reentrant interpretation of that contract.
The original documentation does not explicitly explain this consequence of a callback closing or
revoking the current session.

**Original evidence:** `_execute_tool_call` obtains an issued entry at
`src/maskroute/session.py:255`, calls the authorizer at `271-282`, then retains the raw value at
`283` and invokes the handler at `305-307` without rechecking lifecycle state. Final display has
the equivalent sequence at `381-396`. `close()` clears the registry and marks the session closed
at `402-405`, but the pending operation still holds its local `Entry` reference.

**Reproduced result using public APIs:** a trusted authorizer calls `app.close()` and returns
literal `True`. An already issued booking proposal still invokes the internal handler with the
original booking. Only afterward does inherited output-resource lookup raise `UNKNOWN_REFERENCE`.
Calling `app.revoke(ref)` in the authorizer gives the same handler side effect followed by
`REVOKED_REFERENCE`. A display authorizer calling `app.close()` then returning `True` still returns
the restored private string. Recorded booleans were:

```text
internal_invoked_after_close=True
internal_invoked_after_revoke=True
display_restored_after_close=True
```

**Impact:** cleanup or revocation from a host callback does not dominate that callback's affirmative
return. A reported denial can occur after an internal disclosure/side effect. There was no raw
value observed at the model or external-search sinks in these reproductions. Direct host disclosure,
malicious Python code, and concurrent shared-session use remain outside SDK coverage.

**Narrow remedy:** recheck that the session is open and all references remain current/issued/unrevoked
after callbacks and immediately before the handler or final display return. For multiple fields or
display references, check the entire set after the last callback so a later callback cannot revoke
an earlier reference unnoticed. Document non-reentrant callback expectations even with these checks.
Regression tests should inspect the actual handler and display boundaries, not only the raised code.

**Disposition: fixed and independently verified.** Current `session.py:238-243` defines the
session/open/reference check, called before handler effects at `307` and before returning display
text at `409`. The check covers all references after all authorization callbacks, including
references used in earlier fields. The original close reproduction now reports `SESSION_CLOSED`
and **zero internal calls**; revoke reports `REVOKED_REFERENCE` and **zero internal calls**;
display after callback closure reports `SESSION_CLOSED` without returning restored text. All six
two-reference lifecycle regressions pass. This is not a concurrency, callback rollback, or hard
timeout guarantee; no operation can undo effects performed by trusted callback code itself.

## Confirmed reuse limitation, not an authorization flaw

### L1 — Medium utility impact: one value/kind/classification cannot belong to two resources

`src/maskroute/references.py:40-45` keys stable identity by `(value, kind, classification)` and
rejects a second resource binding with `METADATA_CONFLICT`. In the project integration, two
authorized issues share the same fictional owner contact, while each output must inherit its own
issue authorization resource. The first issue succeeds; the second read executes but result
protection fails when binding that contact to its second issue.

The new public-API integration and strict expected-failure test demonstrate this denial:
`tests/test_project_reuse.py::test_project_allowed_tasks[maskroute-multi_issue_shared_contact]`.
The dedicated cause check confirms `METADATA_CONFLICT`, zero forbidden disclosures, and no research
call for that workflow. The handwritten comparison supports the legitimate workflow with its
resource-specific handles.

This is deliberate fail-closed behavior under the original registry identity design. It should
count as a false denial and a limit on reusable SDK value. It must not be hidden by widening the
contact's authorization resource, weakening per-issue display authorization, or treating an
expected failure as a successful positive test. Resource-qualified identity is a future design
decision; it is not implemented by this review or required as a feature-freeze fix.

## Boundary assessment

| Area | Assessment and evidence |
|---|---|
| Reference generation and scope | Each registry uses 128 CSPRNG bits per new handle (`references.py:49`). Registry lookup checks existence, revocation and issuance (`56-64`). Typed outbound references additionally require original object identity (`66-70`), rejecting reconstructed/foreign references. Randomness is not used as sole authority. |
| Issuance | `_assemble` records only registered typed references (`session.py:149-173`); literal reserved syntax is rejected in public text. `_transmit` issues after a successful provider callback (`184-196`). A throwing provider receives only protected content, does not issue new handles, and is not retried. The host adapter remains responsible for representing a real completed send. |
| Exact tool fields | `parse_call` requires exact dictionary shapes and plain string keys/values (`tools.py:101-109`). Execution requires exact field sets and validates each reference before the handler (`session.py:238-306`). Multi-reference tests check that one bad field prevents the whole handler. |
| Host authorization | Policy checks exact tool, field, kind, destination and classification; a separate fresh callback must return literal `True` (`session.py:220-228`, `255-297`). No-reference tools also require authorization. The host still owns business authorization and relationships among resource arguments. |
| Search | Public classification, an independently approved exact value, fixed topic/version enums and host authorization bound the two integrations' trusted query builders. There is no generic model-authored search string. Search terms and search intent remain visible to the provider. |
| Tool outputs | Unknown keys reject the entire result before result construction; forbidden, missing, nested, binary, or non-string values reject (`session.py:320-335`). Public text requires finite host-attested values. Protected fields receive fresh or stable scoped handles and host-configured resource provenance (`336-355`). A tool cannot self-classify by returning metadata keys. |
| Serialization | The SDK sends JSON only after constructing a protected result; `send_tool_result` checks the session owner and assembles each field before `json.dumps` (`session.py:198-208`). Result fields are copied into a read-only mapping (`protection.py:52-58`). There is no recursive string replacement. Raw JSON input and duplicate-key parsing are intentionally adapter responsibilities, documented in the architecture. |
| Immutable objects | Correctly typed `frozenset`/`tuple` rules, copied outer mappings, frozen string-bearing inputs, and copied string context are immutable for ordinary API use. R1 records the runtime hole for mutable nested configuration. Python reflection/private-attribute tampering is not a supported attacker capability. |
| Callback failures | Ordinary provider, handler and authorizer exceptions are discarded and replaced with constant codes, without a retained exception chain. Literal `True` is required. Synchronous timeout is measured after return, not a hard cancellation; a hung callback requires host I/O timeouts. R2 records lifecycle reentrancy separately. |
| Events/errors | Events contain fixed action/reason codes plus trusted schema metadata, not raw inputs, values, maps or handles. Unknown proposed tool names are not copied into events (`session.py:230-236`). Source tracing, process memory, arbitrary host logs and debugger capture of locals are outside this boundary. |
| Final display | The renderer validates conservative plain-text syntax, exact issued references, a host kind allowlist and separate display authorization (`session.py:369-400`). It performs one substitution pass and returns an object with hidden content representation. The host must use an inert text surface; no auto-linking, Markdown, HTML or URL reuse is authorized. R2 records callback closure behavior. |
| Optional detection | Detection remains explicitly best effort. Exact labeled values/spans do not authorize claims about unknown aliases, unlabeled repeated occurrences, encoded secrets, inferred identities, screenshots, or arbitrary model-generated raw text. |

## Verification performed by this reviewer

- `.venv/Scripts/python.exe -m pytest -q tests/test_references.py tests/test_tools.py tests/test_outputs.py`:
  **64 passed** in 0.26 seconds on the original SDK.
- `.venv/Scripts/python.exe -m pytest -q tests/test_independent_adversarial.py tests/test_project_reuse.py`:
  **93 passed, 1 xfailed** in 0.53 seconds on the original SDK. The xfail is the explicitly retained
  legitimate shared-contact denial, not a passed functionality gate. The independent adversarial
  tests were authored by a separate collaborator, not this reviewer.
- Executed the synthetic R1/R2 reproductions above; inspected handler/model recording lists and
  direct display equality, without printing raw protected values.
- Compared all nine Python SDK source hashes with the frozen validation manifest: **9/9 matched**
  before the implementation owner's fixes.
- After fixes, reran the original R1/R2 reproductions and inspected changed code. Then ran
  `.venv/Scripts/python.exe -m pytest -q tests/test_references.py tests/test_tools.py tests/test_outputs.py tests/test_independent_adversarial.py tests/test_project_reuse.py tests/test_review_regressions.py`:
  **168 passed, 1 xfailed** in 0.63 seconds. This includes the 11 collection/lifecycle regression
  cases authored by the implementation owner. The same legitimate resource-identity false denial
  remains expected and measured; this review did not turn it into a passing scenario.

No live provider integration, network isolation, timing attack analysis, exhaustive fuzzing,
concurrency guarantee, package supply-chain audit, or external human assessment was performed.
Passing finite tests supports only the enumerated mediated scenarios. No unresolved model-only
mediated disclosure was reproduced by this review. Preserve the measured reuse denial and the
original findings when interpreting the package's utility and the limited scope of these results.
