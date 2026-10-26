import importlib.util

import pytest

from benchmarks.adapters import FACTORIES
from benchmarks.scenarios import evaluate
from examples.travel_support.demo import run_demo
from examples.travel_support.fixtures import PRIVATE_VALUES


def test_demo() -> None:
    result = run_demo()
    assert result["lookup"] == result["search"] == "allowed"
    assert result["denied_disclosure"] == "WRONG_KIND"
    assert result["forbidden_sink_disclosures"] == 0
    assert not any(value in str(result) for value in PRIVATE_VALUES)


@pytest.mark.parametrize("name", ["handwritten", "maskroute"])
def test_shared_comparison_release_gate(name: str) -> None:
    result = evaluate(FACTORIES[name])
    assert result["legitimate_task_success"] == 4
    assert result["forbidden_paths_rejected"] == result["forbidden_paths"]
    assert result["forbidden_sink_disclosures"] == 0
    assert result["false_denials"] == 0
    assert result["cross_scope_rejections"] == 1
    assert result["reference_roundtrip_correctness"] == 2


def test_controls_have_expected_utility_privacy_tradeoff() -> None:
    raw = evaluate(FACTORIES["unprotected"])
    redacted = evaluate(FACTORIES["blanket_redaction"])
    assert raw["legitimate_task_success"] == 4
    assert raw["forbidden_sink_disclosures"] != 0
    assert redacted["legitimate_task_success"] == 2  # Public-only work still succeeds.
    assert redacted["false_denials"] == 2
    assert redacted["forbidden_sink_disclosures"] == 0


@pytest.mark.skipif(
    importlib.util.find_spec("piighost") is None, reason="optional comparison extra"
)
def test_optional_oss_with_same_host_checks() -> None:
    from benchmarks.oss import PiighostTravel

    result = evaluate(PiighostTravel)
    assert result["legitimate_task_success"] == 4
    assert result["forbidden_paths_rejected"] == result["forbidden_paths"]
    assert result["forbidden_sink_disclosures"] == 0
