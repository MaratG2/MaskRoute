# Implementation record

The 23 October canonical definition and the ZIP implementation specification govern this work.
The four pre-existing numbered documents are preserved as historical drafts. Where they differ,
v0.1 uses only a tiny optional local detector (not NLP/NER), enforces only mediated paths (not all
network egress), and requires independent authorization for external use of public data.
The two handoff documents do not conflict on these requirements.

Work follows specification section 10. Test counts below are actual local runs, recorded at the
corresponding milestone; subsequent regression counts may grow. No remote push or publication.

## Decisions before implementation

- Preserve the repository's existing MIT license; owner review is still required before publishing.
- Use Python 3.11 as the minimum and a local isolated virtual environment. Core has no dependencies.
- Establish packaging/test scaffolding in step 1 so the baseline can be executed immediately;
  final install verification and CI remain step 7.
- The handwritten baseline will independently implement the same two operations, scoped random
  handles, issuance, host authorization, fixed public search, and output filtering. It imports no SDK.

## Step 1 — handwritten baseline

Implemented before any SDK module. Python 3.11.14: **12 tests passed** (0.11 s on the second run).
Checks inspect recorded model/search payloads and actual internal arguments. Legitimate lookup and
search succeed; unissued, altered, cross-session, closed, wrong-owner, wrong-kind, malformed calls
and unknown outputs fail closed. Ruff fixes were mechanical formatting/context-manager changes.

## Step 2 — registry and explicit protection

**26 tests passed** (0.15 s). Added 128-bit random typed handles, exact-value stability, independent
scope isolation, teardown/revocation, span validation, and actual model-sink checks. Issuance occurs
only after a successful `send_model` call carrying the original typed reference object. A provider
failure leaves newly sent handles unissued and is not retried. Literal reserved token syntax in public
text is rejected; creating a token-looking string or constructing a new `ProtectedRef` grants nothing.
This deliberately replaces the illustrative prepare-then-send API, whose caller could forget to send.
An early mypy run caught a test-only comparison between differently typed empty sink lists; split
the assertion. Unlabeled repeated spans remain unprotected, as required by the explicit contract.

## Step 3 — tool gateway

**53 tests passed** (1.02 s). Closed manual string schemas reject extra/nested arguments; finite enums
and exact reference fields limit the two operations. Independent field/destination/classification
rules and host authorization must both pass. Public search also checks an exact airline allowlist.
Tests inspect internal arguments and external requests, including unauthorized resources, action
revocation, malformed and cross-session handles, URL/query smuggling and callback failures.
During this stage all handler output was discarded pending step 4's return filter.

The synchronous authorizer has a measured deadline: an exception, non-boolean response, or late
approval denies before tool execution. This cannot preempt a callback that never returns; the host
must impose its own I/O timeout. No worker thread is abandoned holding private authorization data.

## Step 4 — protected return path, errors, audit and display

**75 tests passed** (0.28 s). Output schemas are flat and explicit; an unknown or forbidden field
rejects the entire result before a model send. Private fields become typed references, and public
string outputs must belong to a host-attested finite vocabulary. This is narrower than arbitrary
trusted public text and suits this demo's fixed status/policy responses. Output handles remain
unissued until `send_tool_result` succeeds. Display returns a dedicated inert text object, checks
issued references, host-supplied permitted kinds and fresh host authorization, and rejects URL,
markup, code and JSON syntax conservatively. Audit records contain only codes/trusted identifiers.
Provider/tool/authorization errors discard exception chains and never automatically retry.
The baseline received the same fixed public search-response validation for comparison fairness.

## Step 5 — optional best-effort detection

**78 tests passed** (0.24 s); Ruff lint/format and strict mypy passed for 23 files. The first detector
test exposed a sentence-ending punctuation bug in the email regex; corrected it before this gate.
The 14 synthetic RU/EN messages contain 10 labeled entities: **6 true positives, 2 false positives,
4 false negatives** (precision 0.75, recall 0.60, F1 0.6667). Unknown names and obfuscated emails
remain visible at the captured model sink. Phone-like public numeric text is a false positive.
These deliberately small fixtures are illustrative, not a real-world accuracy estimate.

## Step 6 — demonstration and measurement

**83 tests passed** (0.69 s); strict mypy passed for 30 files. Added a deterministic model-driven
demo and one shared four-task/fifteen-attack harness. The optional PIIGhost 2.1.1 integration uses
supported masking/restoration APIs plus exactly the handwritten host enforcement. Both protected
baselines and MaskRoute completed 4/4 tasks, denied all 15 hostile paths, and had zero forbidden
disclosures in the shared cases. Unprotected retained task utility but disclosed private values;
irreversible redaction lost booking utility but retained the two independent public searches.

The first standalone demo invocation correctly exposed that pytest's source path was hiding the
need for installation. `python -m pip install -e '.[dev,comparison]'` succeeded, and the standalone
demo then succeeded with three model requests, one public search and a WRONG_KIND denial.

Ran 2,000 samples per timing with 100 warmups on Windows/Python 3.11.14, Ryzen 7 2700, 31.93 GiB RAM.
The generated `benchmarks/report.md` and `results.json` carry the measured final source fingerprint,
environment, per-case counts, p50/p95 core/workflow overhead and integration line counts.
The initial run found the handwritten boundary smaller and faster, with equal shared enforcement.
The stop/decision gate therefore records **no-go on expanding scope or claiming superiority**.
The remaining work is publication readiness and verification, not product expansion.

## Step 7 — package, docs, CI and final local verification

**84 tests passed** on Python 3.11.14 (0.77 s), including the optional OSS comparison and an added
actual malicious tool-output fixture. Ruff lint and format check passed; strict mypy passed for
30 files. Python 3.14.3 in a separate environment without the comparison extra: **83 passed,
1 optional test skipped** (0.38 s), strict mypy passed, standalone demo and four-control benchmark
smoke run succeeded. The README's Python example was executed successfully.

Built `dist/maskroute-0.1.0-py3-none-any.whl` and installed it with `--no-deps` into a fresh Python
3.11 environment. Verified import from that environment's `site-packages`, bundled `py.typed`,
zero mandatory dependencies, and the standalone demo. Editable installation also succeeded.
The sanitized recorded demo is `docs/DEMO_TRANSCRIPT.json`; no private display text is logged.

Added GitHub Actions for Windows/Linux and Python 3.11/3.14, running tests, Ruff, mypy, demo,
benchmark smoke and wheel build. **Hosted CI has not run**: this work is local and nothing was
committed, pushed, deployed or published. The Linux jobs are configured, not claimed as observed.
The pre-existing MIT license and four numbered design documents remain unchanged.

Final benchmark (2,000 samples, 100 warmups) records MaskRoute workflow p50/p95 **150.1 / 262.8 µs**,
handwritten **38.8 / 50.0 µs**, unprotected **20.9 / 23.9 µs**, and PIIGhost plus host checks
**6703.45 / 8078.7 µs**, including its asyncio runner lifecycle. Incremental mediated model-send
percentile differences versus the no-op provider are **4.7 / 6.0 µs**. These are measurements of
this integration/machine, not intrinsic library or real-network performance claims.

Shared gate: MaskRoute, handwritten, and PIIGhost plus host checks each complete **4/4** valid
tasks, correctly roundtrip **2/2** bookings, reject **15/15** enumerated forbidden paths, and record
**0** forbidden disclosures/false denials. Unprotected: 4/4 tasks, **26** exact-value/payload
disclosures. Blanket redaction: 2/4 tasks, zero disclosures, two false denials. The benchmark's
output-rejection scoring allows an earlier denial as well as withholding a completed lookup;
roundtrip correctness reads actual internal arguments separately from full-task success.

Measured code size (nonblank/noncomment physical lines, including docstrings): SDK **766**,
application setup **80**, handwritten boundary **105**, shared fixtures **45**, optional OSS
adapter **58** additional lines. The final JSON source fingerprint was verified against the current
Python files. The report documents finite-test limits, deployment/timeout limitations, API choices,
historical scope conflicts, OSS exclusions and the no-go expansion decision.

The authorized local implementation is complete. A useful next project decision is whether a
second distinct integration can demonstrate reuse benefits; publication and remote CI require a
separate authorized push. No real-provider adapter or production-security claim was added.

## Second validation milestone — 26 October 2026

The follow-up request explicitly authorizes a second application and independent review, with new
SDK features frozen. `VALIDATION_PLAN.md` records the experiment before implementation. The
project-management handwritten boundary was built first: **10 passed** (0.16 s). It shares only
fictional domain fixtures, host authorization and recording sinks with the SDK integration.

The public-API SDK wiring and shared experiment then yielded **58 passed, 1 xfailed** (0.43 s).
The expected failure is a valid task: reading two authorized issues with the same private owner
contact causes `METADATA_CONFLICT`. It remains a strict positive expected failure with a separate
cause/disclosure check. The handwritten version completes all four tasks; the SDK completes three.
Both reject all 19 defined hostile scenarios with zero measured protected-value disclosures.

A separate AI collaborator froze a contract-first adversarial catalog before source inspection and
implemented 45 checks: **45 passed** (0.23 s). A different AI reviewer inspected the implementation
and reproduced two conditional host-integration defects, not model-only bypasses. Eleven new
regressions **failed against the original SDK**, then passed after narrow configuration snapshots
and pre-disclosure lifecycle rechecks. No public API or registry identity change was made. Only
`policy.py`, `session.py` and `tools.py` changed inside the SDK. The reviewer independently verified
the original reproductions were blocked and ran **168 passed, 1 xfailed** (0.63 s).

Final local full suite: Python 3.11.14 **198 passed, 1 xfailed** (1.33 s); Python 3.14.3 **197 passed,
1 optional comparison skipped, 1 xfailed** (0.80 s). Ruff lint/format and strict mypy passed for
41 files. The updated wheel built successfully. See `VALIDATION_REPORT.md` for final packaging and
hosted CI status. An expected failure is not a successful legitimate-task gate.

The new 1,000-sample, 50-warmup common-workflow measurement records handwritten p50/p95
**95.8 / 147.9 microseconds** and MaskRoute **270.35 / 426.9 microseconds**. This includes local
stubs, scenario verification and teardown; no performance optimization was attempted. App wiring
is 101 nonblank/noncomment lines versus 153 handwritten, excluding 95 shared domain/sink lines and
232 benchmark infrastructure lines. Counts include docstrings and are not developer-time measures.
Current generated evidence is in `benchmarks/project_management/`. Original travel timing/detection
evidence is retained unchanged as historical; its old source fingerprint predates these fixes.

The recommendation is an engineering case study with experimental source, not positioning as a
maintained reusable security SDK. Configuration reuse exists, but the SDK fails one valid second
application task and independent human usability/security assessment has not been performed.

Final packaging verification reinstalled the updated wheel into the isolated clean environment,
confirmed import from `site-packages`, `py.typed`, zero mandatory dependencies, and ran the second
demo successfully. Both checkout demos and the reuse smoke also passed. The local Python 3.14
environment lacked pip; its pinned PIIGhost extra was installed using uv. The full 3.14 suite then
reported **198 passed, 1 xfailed** (1.47 s), with no skip; strict mypy and the five-control OSS
benchmark smoke also passed. The five-control smoke passed on Python 3.11 as well.

After reviewing the concrete 69-file upload manifest, the user explicitly approved public upload
to `codex/validation-reuse`, running the four hosted jobs and recording their results. This approval
does not authorize merging main or releasing a package. Hosted results are recorded separately in
`VALIDATION_REPORT.md` when available; earlier no-push statements describe their historical stages.

Hosted run **40298687653** passed all four jobs on source commit
`c1b808e4d7d188cb6c16da3d2cb57bca2c4ba2ef`. Ubuntu 24.04 used Python 3.11.17/3.14.8; Windows
2025 used Python 3.11.9/3.14.9. Each reported **198 passed, 1 xfailed**, with no comparison skip,
and passed every lint/type/demo/benchmark/package step. `validation/HOSTED_CI.json` records the
actual job evidence. No main merge or package release was performed. All six validation activities
are complete; the product recommendation remains a case study because the measured false denial
and maintenance/value uncertainty remain. Hosted success does not convert that limitation to success.

