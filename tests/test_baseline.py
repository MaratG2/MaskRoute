import pytest

from baseline.travel_support import Denied, HandwrittenTravel
from examples.travel_support.fixtures import AIRLINE, BOOKING_A, BOOKING_B, Sinks


def call(name: str, **arguments: str) -> dict[str, object]:
    return {"name": name, "arguments": arguments}


def test_handwritten_legitimate_roundtrip() -> None:
    sinks = Sinks()
    app = HandwrittenTravel("traveler_a", sinks)
    booking = app.issue(app.protect(BOOKING_A))
    result = app.call(call("lookup_booking", booking_ref=booking))
    app.send_result(result)
    search = app.call(call("search_baggage_policy", airline=result["airline"], topic="carry_on"))
    app.send_result(search)
    assert sinks.internal == [{"booking_ref": BOOKING_A}]
    assert sinks.search == [f"{AIRLINE} carry_on baggage policy"]
    assert sinks.disclosures() == 0
    assert search["policy"]


@pytest.mark.parametrize(
    "attack", ["unissued", "fabricated", "wrong_user", "cross_scope", "closed"]
)
def test_handwritten_reference_denials(attack: str) -> None:
    sinks = Sinks()
    app = HandwrittenTravel("traveler_a", sinks)
    token = app.protect(BOOKING_B if attack == "wrong_user" else BOOKING_A)
    if attack != "unissued":
        app.issue(token)
    if attack == "fabricated":
        token += "x"
    elif attack == "cross_scope":
        other = HandwrittenTravel("traveler_a", Sinks())
        token = other.issue(other.protect(BOOKING_A))
    elif attack == "closed":
        app.close()
    with pytest.raises(Denied):
        app.call(call("lookup_booking", booking_ref=token))
    assert sinks.internal == []
    assert sinks.search == []
    assert sinks.disclosures() == 0


@pytest.mark.parametrize(
    "proposal",
    [
        {"name": "web_search", "arguments": {"query": BOOKING_A}},
        {"name": "lookup_booking", "arguments": {"wrong": BOOKING_A}},
        {"name": "lookup_booking", "arguments": {"booking_ref": {"value": BOOKING_A}}},
        {"name": "lookup_booking", "arguments": {"booking_ref": BOOKING_A, "extra": "x"}},
    ],
)
def test_handwritten_schema_denials(proposal: object) -> None:
    sinks = Sinks()
    app = HandwrittenTravel("traveler_a", sinks)
    with pytest.raises(Denied):
        app.call(proposal)
    assert sinks.internal == []
    assert sinks.search == []
    assert sinks.disclosures() == 0


def test_handwritten_unknown_output_withheld() -> None:
    sinks = Sinks(hostile_output=True)
    app = HandwrittenTravel("traveler_a", sinks)
    token = app.issue(app.protect(BOOKING_A))
    with pytest.raises(Denied):
        app.call(call("lookup_booking", booking_ref=token))
    assert sinks.model == [token]
    assert sinks.disclosures() == 0


def test_handwritten_wrong_kind_search_denied() -> None:
    sinks = Sinks()
    app = HandwrittenTravel("traveler_a", sinks)
    token = app.issue(app.protect(BOOKING_A))
    with pytest.raises(Denied):
        app.call(call("search_baggage_policy", airline=token, topic="carry_on"))
    assert sinks.search == []
    assert sinks.disclosures() == 0
