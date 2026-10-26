from typing import cast

import pytest

from examples.travel_support.application import create_session as setup
from examples.travel_support.fixtures import AIRLINE, BOOKING_A, BOOKING_B, Sinks
from maskroute import (
    AuthorizationRequest,
    Code,
    MaskRouteError,
    ProtectionSession,
    ReferenceField,
    ToolSpec,
)
from maskroute import (
    Classification as C,
)
from maskroute import (
    Destination as D,
)
from tests.test_baseline import call


def issue(
    app: ProtectionSession,
    sinks: Sinks,
    value: str = BOOKING_A,
    kind: str = "BOOKING",
    classification: C = C.CONFIDENTIAL,
) -> str:
    ref = app.protect_value(value, kind=kind, classification=classification)
    app.send_model(sinks.model_send, [ref])
    return ref.token


def test_s03_s10_approved_fields_and_public_search() -> None:
    sinks = Sinks()
    app = setup(sinks)
    ref = issue(app, sinks)
    app.execute_tool_call(call("lookup_booking", booking_ref=ref))
    airline = issue(app, sinks, AIRLINE, "AIRLINE", C.PUBLIC)
    app.execute_tool_call(call("search_baggage_policy", airline=airline, topic="carry_on"))
    assert sinks.internal == [{"booking_ref": BOOKING_A}]
    assert sinks.search == [f"{AIRLINE} carry_on baggage policy"]
    assert sinks.disclosures() == 0


@pytest.mark.parametrize(
    "attack",
    ["wrong_user", "unissued", "wrong_kind", "cross_scope", "modified", "revoked", "closed"],
)
def test_s04_s07_tool_denials(attack: str) -> None:
    sinks = Sinks()
    app = setup(sinks)
    value = BOOKING_B if attack == "wrong_user" else BOOKING_A
    kind = "PERSON" if attack == "wrong_kind" else "BOOKING"
    ref = app.protect_value(value, kind=kind, classification=C.CONFIDENTIAL)
    if attack != "unissued":
        app.send_model(sinks.model_send, [ref])
    token = ref.token
    if attack == "modified":
        token += "x"
    elif attack == "cross_scope":
        token = issue(setup(Sinks()), Sinks())
    elif attack == "revoked":
        app.revoke(ref)
    elif attack == "closed":
        app.close()
    with pytest.raises(MaskRouteError):
        app.execute_tool_call(call("lookup_booking", booking_ref=token))
    assert sinks.internal == []
    assert sinks.search == []
    assert sinks.disclosures() == 0


@pytest.mark.parametrize(
    "proposal",
    [
        {"name": "web_search", "arguments": {"query": BOOKING_A}},
        {"name": "lookup_booking", "arguments": {"wrong_field": BOOKING_A}},
        {"name": "lookup_booking", "arguments": {"booking_ref": BOOKING_A, "extra": "x"}},
        {"name": "lookup_booking", "arguments": {"booking_ref": {"ref": BOOKING_A}}},
        {"name": "lookup_booking", "arguments": {"booking_ref": [BOOKING_A]}},
        {"name": ["lookup_booking"], "arguments": {}},
        {"name": "lookup_booking", "arguments": {}, "principal": "traveler_b"},
        '{"name": "lookup_booking"}',
    ],
)
def test_s08_closed_schemas(proposal: object) -> None:
    sinks = Sinks()
    app = setup(sinks)
    with pytest.raises(MaskRouteError):
        app.execute_tool_call(proposal)
    assert sinks.internal == []
    assert sinks.search == []
    assert sinks.disclosures() == 0


@pytest.mark.parametrize(
    "attack",
    [
        "private_booking",
        "private_airline",
        "unapproved_airline",
        "url",
        "free_query",
        "topic_injection",
    ],
)
def test_s09_search_smuggling(attack: str) -> None:
    sinks = Sinks()
    app = setup(sinks)
    if attack == "private_booking":
        ref = issue(app, sinks)
    else:
        ref = issue(
            app,
            sinks,
            "Unapproved Fake Air" if attack == "unapproved_airline" else AIRLINE,
            "AIRLINE",
            C.CONFIDENTIAL if attack == "private_airline" else C.PUBLIC,
        )
    args = {"airline": ref, "topic": "carry_on"}
    if attack == "url":
        args["airline"] = "https://example.invalid/?q=" + ref
    elif attack == "free_query":
        args["query"] = BOOKING_A
    elif attack == "topic_injection":
        args["topic"] = BOOKING_A
    with pytest.raises(MaskRouteError):
        app.execute_tool_call({"name": "search_baggage_policy", "arguments": args})
    assert sinks.search == []
    assert sinks.disclosures() == 0


def test_s07_authorization_rechecked_context_is_trusted() -> None:
    requests: list[AuthorizationRequest] = []
    allowed = True

    def auth(request: AuthorizationRequest) -> bool:
        requests.append(request)
        return allowed

    sinks = Sinks()
    app = setup(sinks, auth)
    ref = issue(app, sinks)
    app.execute_tool_call(call("lookup_booking", booking_ref=ref))
    allowed = False
    with pytest.raises(MaskRouteError, match=Code.UNAUTHORIZED):
        app.execute_tool_call(call("lookup_booking", booking_ref=ref))
    assert len(sinks.internal) == 1
    assert requests[-1].resource == BOOKING_A
    assert requests[-1].principal == "traveler_a"
    assert requests[-1].field == "booking_ref"
    assert requests[-1].action == "lookup_booking"
    assert sinks.disclosures() == 0


@pytest.mark.parametrize("mode", ["throw", "timeout", "truthy"])
def test_s13_authorizer_fails_closed(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def auth(request: AuthorizationRequest) -> bool:
        if mode == "throw":
            raise RuntimeError(BOOKING_A)
        return cast(bool, "yes") if mode == "truthy" else True

    sinks = Sinks()
    app = setup(sinks, auth)
    ref = issue(app, sinks)
    if mode == "timeout":
        ticks = iter([0.0, 2.0])
        monkeypatch.setattr("maskroute.session.monotonic", lambda: next(ticks))
    with pytest.raises(MaskRouteError) as caught:
        app.execute_tool_call(call("lookup_booking", booking_ref=ref))
    assert caught.value.__context__ is None
    assert BOOKING_A not in str(caught.value)
    assert sinks.internal == []
    assert sinks.disclosures() == 0


def test_default_policy_denies_even_host_approval() -> None:
    sinks = Sinks()
    app = ProtectionSession(principal="traveler_a", authorizer=lambda req: True)
    app.register_tool(
        ToolSpec(
            "lookup_booking",
            D.INTERNAL_TOOL,
            {"booking_ref": ReferenceField("BOOKING")},
            lambda args: sinks.lookup(args["booking_ref"]),
        )
    )
    ref = issue(app, sinks)
    with pytest.raises(MaskRouteError, match=Code.POLICY_DENIED):
        app.execute_tool_call(call("lookup_booking", booking_ref=ref))
    assert sinks.internal == []
