# Independent contract-first adversarial design

This is a separate AI review of the experimental v0.1 SDK, not an external human
review, penetration test, security audit, or certification. The initial case
design below was written after reading `AGENTS.md`, `PROJECT_DEFINITION.md`, and
`IMPLEMENTATION_SPEC.md`, and **before reading SDK implementation or existing
tests**. Test construction may subsequently consult public exports and the travel
application for API syntax. All identities, values, and destinations are fictional.

## Threat and observation model

An attacker controls proposed model tool calls, arbitrary text in public/tool
responses, and the shape of tool return values. Trusted host code supplies the
principal, authorizer, schemas, labels, and destination permissions. Fresh local
recording model/tool sinks capture the actual outbound payload and handler calls;
tests must inspect those records, not merely a return code. No external provider,
network request, real customer data, or unrestricted execution is involved.

The narrow invariant is that explicitly marked values cross only the exact
approved mediated boundary after every required check. A random token is not
authority. Successful legitimate operations are positive controls. These finite
cases do not establish a universal noninterference property.

## Frozen case catalogue

| ID | Adversarial variation | Expected observation |
|---|---|---|
| I01 | Registered value never placed in an outbound message | Tool cannot use it; no handler side effect. |
| I02 | Existing unissued token copied into literal public text | Literal appearance cannot confer issuance; no handler side effect. |
| I03 | Token copied into free text or a declared public tool-output field | Text/output cannot confer issuance; no handler side effect. |
| I04 | Message prepared but never sent | Preparation alone does not issue; no handler side effect. |
| I05 | Send fails before the stub records delivery | Conservative issuance interpretation: new reference remains unusable. |
| I06 | Stub records the message and then raises, simulating ambiguous/partial send | Raw value stays absent, exception is sanitized, and no handler executes; conservative interpretation denies newly attempted references after the failed call. |
| I07 | One reference was successfully issued, another later send fails | Earlier issuance remains usable; later attempted issuance must not widen authority. |
| I08 | Same token replayed across sessions or after closure | Deny; no handler side effect in the receiving scope. |
| I09 | A successfully issued reference is used again after host authorization changes | Recheck current host authorization; deny without executing. |
| M01 | Two references in one call, one unauthorized/unissued/wrong kind | Validate the entire call before any handler side effect; deny. |
| M02 | Two distinct references in approved fields | Both resources require current authorization, and only approved raw fields reach the handler. |
| M03 | Same issued reference reused in two fields, with only one field permitted | Per-field checks still deny the unpermitted placement. |
| M04 | Correct references swapped into fields of incompatible kinds | Deny before handler. |
| M05 | Reference wrapped in URL, JSON string, list, or nested object | Reject rather than recursively restore. |
| M06 | Valid arguments plus attacker-defined identity/destination/extra fields | Closed schema rejects; no handler side effect. |
| O01 | Tool returns known private field plus unknown field containing a secret | Unknown field is withheld or whole result denied before model send; private raw value never reaches model. |
| O02 | Declared public output contains a protected token plus injection instructions | Instructions and token cannot modify registry, policy, or issuance. |
| O03 | Known output field contains unexpected nested, sequence, bytes, or non-string object | Reject unsupported shape before model send, without coercion that reveals contents. |
| O04 | Tool raises an exception containing a protected value | SDK-facing error and events are sanitized; no unsafe model retry. |
| O05 | Tool output or field names impersonate classification/authorization metadata | Remote output cannot relabel itself or authorize another operation. |
| O06 | Private output value appears again in otherwise public output text | Explicitly known protected raw values must not cross a mediated model boundary; overlapping labels are tested without claiming general detection. |
| P01 | Valid explicit input, approved two-field tool, private output round trip | Positive control succeeds with raw values present only at the approved handler and authorized display. |

For I05-I07 the implementation spec does not describe transport acknowledgement
or partial-send semantics. The test interpretation is fail-closed transactionality
for **new** issuance on a failed send, while retaining issuance established by an
earlier successful call. If the implementation differs, report the behavior and
contract ambiguity instead of silently weakening a test.

## Trusted-host misuse and excluded claims

Passing a raw unknown secret as `PublicText`, labeling an unknown secret public,
writing a permissive authorizer, omitting business checks inside an authorized
tool, bypassing the SDK, or executing concurrent operations despite the documented
serial-session requirement is trusted-host misuse, not an attacker bypass. Such
cases may document limits but must not be counted as successful security tests.
O06 concerns an already explicitly protected value, not discovery of an unknown
secret. Encoded variants, semantic inferences, detector completeness, deployment
confinement, and exhaustive parser/resource-exhaustion testing remain outside this
bounded review.

## Execution record

Executed on 26 October 2026 with local Python 3.11.14. The independent reviewer
read public exports, public signatures/docstrings through introspection,
`examples/travel_support/application.py`, and package tooling configuration after
freezing this catalogue. The coordinator supplied the public tool-call envelope
spelling (`name` and `arguments`). No existing test fixture, baseline implementation,
or SDK implementation was used to derive attack cases. Pytest later displayed
implementation tracebacks while diagnosing two invalid positive-control fixtures.

The first run produced **39 passed, 2 failed in 0.67 seconds**. Both failures were
fixture errors: the test registered a required `private` output but its default
successful handler returned only `status`. The SDK correctly rejected that
incomplete result. The fixture was corrected to include all declared outputs;
output-shape attacks were also made complete so their rejection cannot be
attributed to missing fields. No expected denial was weakened and no SDK code was
changed. That corrected run produced **41 passed in 0.20 seconds**.

Four additional instances of already-designed I01/I05/I06/M02/M03 cases exercise
unissued private tool-return references after no send or failed sends, and the
same reference's host authorization in two distinct fields. Final focused run:

```text
.venv/Scripts/python.exe -m pytest tests/test_independent_adversarial.py -q
45 passed in 0.23s

.venv/Scripts/python.exe -m ruff check tests/test_independent_adversarial.py
All checks passed!

.venv/Scripts/python.exe -m ruff format --check tests/test_independent_adversarial.py
1 file already formatted

.venv/Scripts/python.exe -m mypy tests/test_independent_adversarial.py
Success: no issues found in 1 source file
```

All implemented attacks were rejected or withheld as intended; positive controls
reached the handler with exact approved raw fields and returned protected output
to actual recording model sinks. The suite found **no confirmed SDK bypass** in
these 45 cases. There were no forbidden raw values in the captured model payloads
or SDK decision events. This is a bounded test result, not proof of security.

Coverage qualifications:

- I04 has no separate public preparation API in v0.1, so it is not a distinct test;
  creating references/results without sending is covered by I01 and return-path
  issuance tests.
- The public `send_model` docstring explicitly says failed calls do not grant new
  issuance and never automatically retry. This resolves the catalogue's initial
  I05-I07 transport ambiguity; recorded partial sends were tested accordingly.
- Public tool outputs use a host-approved finite value set. I03/O02/O06 therefore
  test hostile replacement of those values, including token text, instructions,
  and already-protected raw values. They do not claim that an intentionally
  host-allowlisted secret can be detected or that arbitrary public free text is
  accepted. Deliberate host reclassification remains trusted-host misuse.
- Unknown output fields may be withheld or the whole result rejected; the tests
  accept either contract-compliant behavior and inspect any actual model send.
- The case runner does not reuse the travel fixture or its model/search stubs.
  It tests a two-reference synthetic tool with fresh payload recorders. External
  search integration, provider networking, exhaustive mutation/fuzzing, arbitrary
  Python object protocols, concurrency, and independent human review are not
  established by this suite.

The two owned files are `docs/INDEPENDENT_ATTACK_DESIGN.md` and
`tests/test_independent_adversarial.py`; the reviewer made no SDK, baseline, or
existing-test changes and performed no commit, push, or external-service action.
