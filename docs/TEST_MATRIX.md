# Acceptance coverage

All fixtures are synthetic. These tests inspect actual recording-sink payloads or verify that no
handler/sink was called. The shared benchmark has a deliberately smaller 15-attack comparison set;
it is not substituted for this acceptance suite. Test names identify checks, not formal proofs.

| ID | Primary tests and inspected boundary |
|---|---|
| S01 | `test_s01_s02_explicit_payload_stability_isolation`: model payload contains handle, not booking |
| S02 | Same test: exact stable identity, unrelated independent-session handles |
| S03 | `test_s03_s10_approved_fields_and_public_search`: exact actual internal booking argument |
| S04 | `test_s04_creation_not_issuance`, tool denial matrix: stored but unissued handle has no effect |
| S05 | Tool denial matrix: altered, wrong-kind and fabricated handles; typed object forgery test |
| S06 | Reference and tool denial matrices; result/display cross-session tests; close/revocation |
| S07 | Tool denial matrix, `test_s07_authorization_rechecked_context_is_trusted`: owner and revocation |
| S08 | `test_s08_closed_schemas`: wrong/extra fields, nested structures, arrays, forged principal |
| S09 | `test_s09_search_smuggling`: no request for private/unknown airline, URL, extra query or topic |
| S10 | `test_s03_s10_approved_fields_and_public_search`: only approved airline + finite topic at search |
| S11 | Output tests: actual JSON sent to model; unknown/binary/nested/forbidden output fully withheld |
| S12 | Injection tests: text cannot create authority; mapping dump and disclosure tool calls denied |
| S13 | Provider, tool, missing/throwing/late/non-boolean authorizer failures; no unsafe retry |
| S14 | Error, traceback-chain and audit inspection: no protected values or untrusted identifiers |
| S15 | Display tests: independent user/kind authorization; URL/markup/JSON/code rejected |
| S16 | `test_s16_measured_misses_and_false_positives_at_actual_sink`: known misses actually sent |

`tests/test_baseline.py` ran before the SDK existed. `tests/test_demo.py` also executes the same
task/threat harness for both implementations and optionally PIIGhost. `test_controls...` checks
that the unprotected workflow keeps utility while leaking, and redaction retains public-search
utility while losing booking restoration. Benchmarks count observations rather than hardcoded scores.
