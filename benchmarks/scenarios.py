"""Shared deterministic task/threat inputs and inspection of actual recorded sinks."""

from dataclasses import asdict, dataclass

from baseline.travel_support import Denied
from examples.travel_support.fixtures import AIRLINE, BAGGAGE, BOOKING_A, BOOKING_B, Sinks
from maskroute import MaskRouteError

from .adapters import Factory, Workflow

ATTACKS = (
    "unissued",
    "modified",
    "wrong_kind",
    "cross_scope",
    "wrong_owner",
    "closed",
    "unknown_tool",
    "wrong_field",
    "extra",
    "nested",
    "url",
    "query",
    "topic",
    "unknown_output",
    "unapproved_airline",
)


def proposal(name: str, **arguments: str) -> dict[str, object]:
    return {"name": name, "arguments": arguments}


def booking_flow(app: Workflow, sinks: Sinks, topic: str = "carry_on") -> bool:
    token = app.issue(app.protect(BOOKING_A))
    result = app.call(proposal("lookup_booking", booking_ref=token))
    app.send_result(result)
    search = app.call(proposal("search_baggage_policy", airline=result["airline"], topic=topic))
    app.send_result(search)
    return (
        sinks.internal == [{"booking_ref": BOOKING_A}]
        and sinks.search == [f"{AIRLINE} {topic} baggage policy"]
        and search["policy"] == BAGGAGE
    )


def public_flow(app: Workflow, sinks: Sinks, topic: str) -> bool:
    airline = app.issue(app.protect(AIRLINE, "AIRLINE"))
    result = app.call(proposal("search_baggage_policy", airline=airline, topic=topic))
    app.send_result(result)
    return sinks.search == [f"{AIRLINE} {topic} baggage policy"] and result["policy"] == BAGGAGE


@dataclass(frozen=True)
class Trial:
    scenario: str
    expected_valid: bool
    succeeded: bool
    denied: bool
    disclosures: int
    internal_calls: int
    search_calls: int
    roundtrip_correct: bool


def valid_trial(factory: Factory, scenario: str) -> Trial:
    sinks = Sinks()
    app = factory(sinks)
    success = denied = False
    try:
        topic = "checked_baggage" if scenario.endswith("checked") else "carry_on"
        success = (
            booking_flow(app, sinks, topic)
            if scenario.startswith("booking")
            else public_flow(app, sinks, topic)
        )
    except (Denied, MaskRouteError):
        denied = True
    finally:
        app.close()
    return Trial(
        scenario,
        True,
        success,
        denied,
        sinks.disclosures(),
        len(sinks.internal),
        len(sinks.search),
        sinks.internal == [{"booking_ref": BOOKING_A}],
    )


def attack_trial(factory: Factory, attack: str) -> Trial:
    sinks = Sinks(hostile_output=attack == "unknown_output")
    app = factory(sinks)
    denied = False
    try:
        token = app.protect(
            BOOKING_B if attack == "wrong_owner" else BOOKING_A,
            "PERSON" if attack == "wrong_kind" else "BOOKING",
        )
        if attack != "unissued":
            app.issue(token)
        if attack == "modified":
            token += "x"
        elif attack == "cross_scope":
            other = factory(Sinks())
            try:
                token = other.issue(other.protect(BOOKING_A))
            finally:
                other.close()
        elif attack == "closed":
            app.close()
        request: object = proposal("lookup_booking", booking_ref=token)
        if attack == "unknown_tool":
            request = proposal("web_search", query=token)
        elif attack == "wrong_field":
            request = proposal("lookup_booking", query=token)
        elif attack == "extra":
            request = proposal("lookup_booking", booking_ref=token, principal="traveler_b")
        elif attack == "nested":
            request = {"name": "lookup_booking", "arguments": {"booking_ref": {"value": token}}}
        elif attack in {"url", "query", "topic", "unapproved_airline"}:
            airline = app.issue(
                app.protect(
                    "Unapproved Fake Air" if attack == "unapproved_airline" else AIRLINE, "AIRLINE"
                )
            )
            if attack == "url":
                request = proposal(
                    "search_baggage_policy",
                    airline="https://example.invalid/" + token,
                    topic="carry_on",
                )
            elif attack == "query":
                request = proposal(
                    "search_baggage_policy", airline=airline, topic="carry_on", query=token
                )
            elif attack == "topic":
                request = proposal("search_baggage_policy", airline=airline, topic=token)
            else:
                request = proposal("search_baggage_policy", airline=airline, topic="carry_on")
        result = app.call(request)
        app.send_result(result)
    except (Denied, MaskRouteError):
        denied = True
    finally:
        app.close()
    return Trial(
        attack,
        False,
        False,
        denied,
        sinks.disclosures(),
        len(sinks.internal),
        len(sinks.search),
        sinks.internal == [{"booking_ref": BOOKING_A}],
    )


def evaluate(factory: Factory) -> dict[str, object]:
    valid = [
        valid_trial(factory, scenario)
        for scenario in ("booking_carry", "booking_checked", "public_carry", "public_checked")
    ]
    hostile = [attack_trial(factory, attack) for attack in ATTACKS]
    return {
        "legitimate_task_success": sum(t.succeeded for t in valid),
        "legitimate_tasks": len(valid),
        "false_denials": sum(t.denied for t in valid),
        "forbidden_sink_disclosures": sum(t.disclosures for t in valid + hostile),
        "reference_roundtrip_correctness": sum(t.roundtrip_correct for t in valid[:2]),
        "reference_roundtrip_attempts": 2,
        "cross_scope_rejections": sum(t.denied for t in hostile if t.scenario == "cross_scope"),
        "forbidden_paths_rejected": sum(
            t.denied
            and t.search_calls == 0
            and t.internal_calls <= (1 if t.scenario == "unknown_output" else 0)
            for t in hostile
        ),
        "forbidden_paths": len(hostile),
        "trials": [asdict(t) for t in valid + hostile],
    }
