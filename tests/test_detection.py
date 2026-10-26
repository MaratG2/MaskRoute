import pytest

from benchmarks.detection_data import CASES, DICTIONARY, expected_spans
from examples.travel_support.fixtures import Sinks
from maskroute import (
    Classification as C,
)
from maskroute import (
    DictionaryEntry,
    MaskRouteError,
    ProtectionSession,
    detect_best_effort,
)


def test_s16_measured_misses_and_false_positives_at_actual_sink() -> None:
    tp = fp = fn = 0
    for case in CASES:
        predicted = {(s.start, s.end, s.kind) for s in detect_best_effort(case.text, DICTIONARY)}
        expected = expected_spans(case)
        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        sinks = Sinks()
        with ProtectionSession(principal="traveler_a", authorizer=lambda request: True) as app:
            protected = app.protect_text_best_effort(case.text, dictionary=DICTIONARY)
            assert protected.best_effort
            app.send_model(sinks.model_send, [protected])
        for start, end, _ in expected - predicted:
            assert (
                case.text[start:end] in sinks.model[0]
            )  # Known miss actually crosses the boundary.
        for start, end, _ in expected & predicted:
            assert case.text[start:end] not in sinks.model[0]
    assert (tp, fp, fn) == (6, 2, 4)


def test_dictionary_precedence_and_exact_repeats() -> None:
    text = "luma@example.invalid and luma@example.invalid"
    spans = detect_best_effort(
        text, [DictionaryEntry("luma@example.invalid", "ACCOUNT", C.RESTRICTED)]
    )
    assert len(spans) == 2
    assert all(s.kind == "ACCOUNT" and s.classification == C.RESTRICTED for s in spans)


def test_empty_dictionary_entry_denied() -> None:
    with pytest.raises(MaskRouteError):
        detect_best_effort("hello", [DictionaryEntry("", "PERSON")])
