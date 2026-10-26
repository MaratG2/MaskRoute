# MaskRoute

**Keep the context. Control the disclosure.** An experimental Python SDK for scoped reversible
references and exact-field disclosure in **mediated** model/tool workflows. Python 3.11+, no runtime
dependencies. The host supplies identity, labels, policies and business authorization.

Explicit values/spans and optional best-effort detection have different contracts. The detector
misses entities. This SDK does not intercept other HTTP clients/loggers or provider-hosted tools,
prevent inference from context, or provide compliance certification. Never assert unknown private
text is `PublicText`. See [architecture and limits](docs/ARCHITECTURE.md).

## Install and run

From this checkout, create/activate a Python 3.11+ virtual environment, then:

```shell
python -m pip install -e ".[dev]"
python -m examples.travel_support.demo
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
```

The demo uses only fictional fixtures and local recording stubs. It shows an allowed booking
lookup, allowed fixed public search and denied disclosure. Private display text is deliberately
omitted from the recorded console transcript. No credentials, network, GPU or database are needed.

```python
from maskroute import Classification, PublicText
from examples.travel_support.application import create_session
from examples.travel_support.fixtures import Sinks

sinks = Sinks()  # Records actual boundary payloads; do not log real private sink data.
with create_session(sinks) as session:  # Trusted host registers two tools and its authorizer.
    booking = session.protect_value(
        "BK-FAKE-101", kind="BOOKING", classification=Classification.CONFIDENTIAL
    )
    session.send_model(sinks.model_send, [PublicText("Lookup "), booking])
    proposal = {"name": "lookup_booking", "arguments": {"booking_ref": booking.token}}
    result = session.execute_tool_call(proposal)  # A real model's proposal is untrusted.
    session.send_tool_result(sinks.model_send, result)
    assert sinks.disclosures() == 0
```

`examples/` is checkout-only trusted application wiring. The installed package exposes
`ProtectionSession`, `ToolSpec`, `DisclosurePolicy`, typed inputs and classified output rules;
see [the host integration](examples/travel_support/application.py) for the complete setup.

## Evidence and positioning

Run `python -m benchmarks.run` for the four local controls. For the optional OSS comparison:

```shell
python -m pip install -e ".[dev,comparison]"
python -m benchmarks.run --iterations 2000 --warmup 100 --oss
```

[Measured report](benchmarks/report.md) · [JSON results](benchmarks/results.json) ·
[milestones](docs/IMPLEMENTATION_LOG.md) · [S01–S16 coverage](docs/TEST_MATRIX.md) ·
[OSS comparison](docs/OSS_COMPARISON.md).

The handwritten baseline and PIIGhost with the same host checks match the shared security/utility
gate. The handwritten implementation is smaller and faster in this experiment. v0.1 is an
engineering evaluation; expanding the product is a **no-go** until reuse has demonstrated value.
Existing MIT license retained. Public validation-branch upload and hosted CI were explicitly
approved; no main-branch merge or package release is authorized.

The second validation milestone adds a project-management integration, an independent handwritten
version and independently designed adversarial tests. Run `python -m examples.project_management.demo`
and `python -m benchmarks.reuse`. See the [reuse comparison](benchmarks/project_management/report.md)
and [validation status](docs/VALIDATION_REPORT.md). A valid multi-issue workflow is currently a strict
expected failure because one shared private value cannot bind to two authorization resources.
