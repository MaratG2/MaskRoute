# Project-management reuse evaluation

Generated from actual recording-sink trials by `python -m benchmarks.reuse`.
This second integration freezes SDK features and uses only existing public APIs.

| Implementation | Valid tasks / 4 | False denials | Rejected attacks / 19 | Disclosures |
|---|---:|---:|---:|---:|
| handwritten | 4 | 0 | 19 | 0 |
| maskroute | 3 | 1 | 19 | 0 |

Valid workflows: reviewer reads an issue and researches a public dependency;
maintainer also reads restricted notes; member uses a different active project; and
maintainer reads two authorized issues sharing one private contact before research.
Attacks cover project/issue relationship, role and issue ACL, multiple reference fields,
issuance/scope/lifecycle, malformed schema, output injection and fixed research terms.
Disclosures count exact protected-value/outbound-payload pairs. Neither test population
nor zero observed disclosures is a general confidentiality guarantee.

## Confirmed reuse limitation

The two-issue task fails in the SDK with METADATA_CONFLICT. Its identity key is exact
(value, kind, classification), while each entry holds only one authorization resource.
The same email legitimately belongs to two authorized issue results; the second output
is withheld before the model send. The handwritten code includes resource in identity.
This is a safe false denial, not an observed leak. The positive requirement remains a
strict expected-failure test. No resource permission was broadened to force success.

## Integration effort

```json
{
  "sdk_host_wiring": {
    "file": "examples/project_management/application.py",
    "nonblank_noncomment_lines_including_docstrings": 101,
    "function_definitions": 3,
    "branch_and_loop_nodes": 0,
    "sha256": "e058c0d6711e4132028694d71a0b974f258e97c9bd9ff6414f251143b166ae75"
  },
  "handwritten_boundary": {
    "file": "baseline/project_management.py",
    "nonblank_noncomment_lines_including_docstrings": 153,
    "function_definitions": 8,
    "branch_and_loop_nodes": 33,
    "sha256": "3122adce0b96cb1b34e1b874f0b7f7a5ca43552f3eb8a078371c49bca72f0762"
  },
  "shared_domain_authorization_and_sinks": {
    "file": "examples/project_management/fixtures.py",
    "nonblank_noncomment_lines_including_docstrings": 95,
    "function_definitions": 6,
    "branch_and_loop_nodes": 12,
    "sha256": "08239cbf729c553decfb9c269d2c08ccf5046012d8fe01e896158d5b6bc590b2"
  },
  "benchmark_adapters_and_scenarios": {
    "file": "benchmarks/project_scenarios.py",
    "nonblank_noncomment_lines_including_docstrings": 232,
    "function_definitions": 16,
    "branch_and_loop_nodes": 41,
    "sha256": "2cce53a652055ee1a9f88f22880d68f42be14b5becd10960fdf807bdb00b76c2"
  }
}
```

The SDK host wiring registers 3 tool schemas, 4 disclosure rules and 6 output fields.
The handwritten implementation has 3 explicit dispatch branches plus its own reference,
issuance and output-validation code. Domain authorization is shared and excluded from
both wiring counts. The larger benchmark adapter file is test infrastructure, not an
application dependency. Counts include docstrings and are not measured developer hours.
Branch/loop AST counts are descriptive, not calibrated complexity or risk scores.

## Developer experience observations

The same SDK configures new kinds, multiple private input fields and stricter notes
authorization without a travel-specific code path. That is evidence of mechanical reuse.
It centralizes otherwise duplicated schema, issuance and output protection checks.
Host policy still needs to bind project/issue relationships using trusted context; the
SDK does not infer relational authorization. Flat output schemas are straightforward
for the fixture but do not support real issue lists or arbitrary research prose.
The single-resource identity constraint blocks a realistic valid multi-issue flow.
These are implementation observations by the integration author, not an independent
developer usability study. No onboarding time or developer satisfaction was measured.

## Descriptive timing

Only the common successful maintainer workflow is timed, including scenario checks,
local stubs and teardown. No timing optimization or speed marketing claim was made.
```json
{
  "python": "3.11.14",
  "platform": "Windows-10-10.0.26300-SP0",
  "samples": 1000,
  "warmup": 50,
  "timings": {
    "handwritten": {
      "samples": 1000,
      "p50_us": 95.8,
      "p95_us": 147.9
    },
    "maskroute": {
      "samples": 1000,
      "p50_us": 270.35,
      "p95_us": 426.9
    }
  }
}
```

## Decision

Prefer an engineering case study with experimental source over positioning this as a
maintained reusable security SDK. Configuration reuse is real, but the frozen SDK
does not complete all valid second-application tasks and has not demonstrated enough
benefit to justify its general maintenance/security burden. No publication is authorized
by this recommendation. Independent review and hosted CI status are recorded separately
in `docs/VALIDATION_REPORT.md`; neither is implied by passing local tests.

SDK files changed during validation (audit separately): ['maskroute/policy.py', 'maskroute/session.py', 'maskroute/tools.py']
