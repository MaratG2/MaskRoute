# Second validation milestone

26 October 2026. Local evaluation complete; the user explicitly approved uploading the reviewed
implementation and workflow to `codex/validation-reuse` in the existing public repository and
recording the hosted CI results. Jobs are pending. The scope remains the small experimental
mediated-path SDK; no merge or package release is authorized.

## Six requested outcomes

| Outcome | Status | Evidence |
|---|---|---|
| Hosted Windows/Linux, Python 3.11/3.14 CI | Upload approved; results pending | Four-job workflow prepared; no hosted result is claimed |
| Independent implementation review | Complete, qualified | `INDEPENDENT_REVIEW.md`; separate AI reviewer, two fixes independently rechecked |
| Different second SDK integration | Implemented and evaluated | Project/issue ACLs, role-restricted notes, approved public dependency research; 3/4 valid tasks |
| Minimal handwritten counterpart | Complete, built first | `baseline/project_management.py`; 4/4 valid tasks |
| Security/complexity/developer-experience comparison | Complete within this synthetic experiment | `../benchmarks/project_management/report.md` and JSON; no human usability study |
| Publication positioning decision | Recommendation complete; nothing published | Prefer an engineering case study with experimental source; maintained SDK value is unproven |

## What changed

The project assistant uses three tools: `read_issue`, `read_notes`, and `research_dependency`.
Trusted host context binds a principal to an active project. Project membership, issue ACLs and
maintainer-only note access differ from the travel example. Issue titles, contacts and restricted
notes receive separate labels. Approved fictional technology, version and topic form the entire
external query; no private query prose is accepted. Every provider/tool remains a local recording
stub. The model in the demonstration is deterministic. All data is fictional.

The handwritten boundary was implemented and tested before SDK wiring. Both share domain data,
host authorization and sinks; they share no registry, issuance, schema or output-validation code.
The SDK wiring uses existing public APIs only. No feature was added to accommodate the new app.

## Findings that change the product assessment

| Comparison | Handwritten | MaskRoute |
|---|---:|---:|
| Legitimate workflows completed | 4/4 | 3/4 |
| False denials | 0 | 1 |
| Enumerated hostile paths rejected | 19/19 | 19/19 |
| Forbidden exact-value/payload disclosures observed | 0 | 0 |
| Application boundary/wiring lines | 153 | 101 |
| Function definitions in that code | 8 | 3 |
| Branch/loop AST nodes in that code | 33 | 0 |

The valid failing task reads two authorized issues with the same owner contact in one session.
MaskRoute identifies an entry by `(value, kind, classification)` and binds it to one resource.
The second issue's output therefore raises `METADATA_CONFLICT`. Its internal read has executed,
but the second result is withheld before model transmission and research is not reached. The
handwritten version includes resource in identity and completes the task. This is a safe false
denial, not an observed leak. The positive requirement remains a strict expected-failure test,
with a separate passing check for its precise cause and actual sink behavior. Do not count it as
a successful valid-task test or widen issue permissions to make it disappear.

Line counts exclude the common 95 lines of domain authorization/sinks and 232 lines of benchmark
adapters/scenarios. Counts are nonblank, noncomment physical lines including docstrings. SDK
internals are also excluded from the 101 wiring lines, so that saving does not measure total
maintenance burden. The SDK configuration contains three schemas, four disclosure rules and six
output fields. AST counts describe syntax, not calibrated risk or complexity scores.

Configuration reuse is demonstrated: no travel-specific SDK branch was needed. It centralizes
checks the handwritten application duplicates. However, resource identity blocks a realistic
multi-issue operation, and flat schemas/finite public output vocabularies constrain real issue
lists and research prose. Developer-experience findings are observations by the integration author.
No developer onboarding time, satisfaction, maintenance study or external user trial was measured.

## Independent validation and narrow fixes

Two separate AI collaborators provided independent work within the same environment. This is
stronger separation from the integration author, not an external human audit or certification.

The attack author froze `INDEPENDENT_ATTACK_DESIGN.md` before inspecting source/tests and added
45 contract-first checks. They inspect actual model payloads, handler arguments, authorization
requests and events. Coverage includes failed/partial sends, issuance, cross-scope/revoked handles,
multiple reference fields, nested carriers, malicious outputs, display and error behavior.
All 45 pass; this finite population does not prove general security.

The code reviewer reproduced two Low-severity host-integration defects in the original SDK:

1. Frozen configuration retained mutable nested collections. Enum, output/search allowlists,
   policy rules and classification collections now take defensive immutable snapshots.
2. A trusted authorization callback could close/revoke a session while a pending handler or display
   still proceeded. The SDK now rechecks the entire reference set and session state after all
   authorization callbacks, before the relevant disclosure.

Eleven regressions failed against the original code and pass after correction. The reviewer
independently reran the original reproductions: schema mutation denies with zero model calls;
callback close/revoke denies with zero handler calls; closed-session display returns no raw text.
These were not reproduced model-only bypasses. No raw protected values were printed in reports.
Only `src/maskroute/policy.py`, `session.py` and `tools.py` changed. No public API, registry identity,
automatic detector, policy language, persistence layer or generic external tool was added.
These are documented contract fixes during the feature freeze, not an architectural expansion.

`validation/sdk_baseline_hashes.json` records the original nine UTF-8/LF source hashes. The reviewer
confirmed all nine before fixes. Reuse reporting normalizes text newlines so Git checkout line
ending conversion does not falsely count as a source change. The original travel benchmark and
its source fingerprint remain historical pre-fix evidence, unchanged.

## Actual local checks and measurements

Milestone runs are preserved in `IMPLEMENTATION_LOG.md`:

- Handwritten first: 10 passed (0.16 s).
- Project application/shared matrix: 58 passed, 1 xfailed (0.43 s).
- Independently designed attacks: 45 passed (0.23 s).
- Fix regressions: 11 failed before corrections; all 11 passed after corrections.
- Independent post-fix review slice: 168 passed, 1 xfailed (0.63 s).
- Final full suite, Windows/Python 3.11.14: 198 passed, 1 xfailed (1.33 s).
- Initial full suite, Windows/Python 3.14.3 without comparison extra: 197 passed, 1 optional
  PIIGhost test skipped, 1 xfailed (0.80 s). After installing the pinned comparison extra:
  **198 passed, 1 xfailed (1.47 s)**. Strict mypy and the five-control OSS benchmark smoke also
  passed on Python 3.14.3; the same benchmark smoke passed on 3.11.14.
- Ruff lint and format checks passed; strict mypy passed for 41 source files.
- Updated wheel built and reinstalled with `--no-deps` into the isolated clean environment.
  Import resolved from `site-packages`; `py.typed` and zero mandatory dependencies were verified.
  The project-management demo ran successfully against the installed wheel. Both checkout demos
  and the reuse benchmark smoke run also passed after the fixes.

The generated reuse benchmark used Python 3.11.14 on Windows, 1,000 samples after 50 warmups.
The common successful maintainer workflow includes recording stubs, scenario checks and teardown:
handwritten p50/p95 **95.8 / 147.9 microseconds**; MaskRoute **270.35 / 426.9 microseconds**.
The p95 difference is 279 microseconds (about 0.28 ms). It is not a real-network latency estimate
or a reason to optimize. PIIGhost was not included in this second integration's performance claim.
Full trial counts, environment, source metrics and timings are in the generated JSON report.

## Hosted CI and next action

The existing repository `MaratG2/MaskRoute` is public and contains only the initial license; its
remote workflow lookup returned 404. The four configured jobs cover Windows/Linux and Python
3.11/3.14, installing dev/comparison extras and running tests, lint, format, typing, both demos,
both benchmark smoke runs and a wheel build. Workflow token permissions are read-only.

Running those jobs requires uploading the local implementation, not merely toggling existing CI.
`AGENTS.md` explicitly requires approval before publishing or pushing. The user approved the
reviewed 69-file manifest plus the manifest itself, a separate `codex/validation-reuse` branch,
the four CI jobs and recording their results. No merge, package release or visibility change was
approved. Until actual hosted results exist, Linux and hosted Windows verification remain pending.

The recommendation is to present **Designing and Evaluating Policy-Controlled Disclosure for LLM
Agents** as an engineering case study, with clearly experimental source if publication is approved.
This experiment supports discussion of trust boundaries, schema-driven disclosure, independent
attack design, safe false denials and maintenance trade-offs. It does not yet justify positioning
MaskRoute as a maintained general security library. Preserve the feature freeze; complete CI and
review the evidence before choosing any subsequent resource-identity redesign.
