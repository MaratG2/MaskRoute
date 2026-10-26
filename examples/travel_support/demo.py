"""Run from repository root: python -m examples.travel_support.demo."""

import json
from dataclasses import dataclass

from maskroute import Classification as C
from maskroute import MaskRouteError, ProtectedRef, PublicText
from maskroute.references import TOKEN

from .application import create_session
from .fixtures import BAGGAGE, BOOKING_A, Sinks


@dataclass
class ModelStub:
    sinks: Sinks

    def __call__(self, payload: str) -> dict[str, object]:
        self.sinks.model_send(payload)
        if payload.startswith("Lookup "):
            found = TOKEN.search(payload)
            assert found is not None
            return {"name": "lookup_booking", "arguments": {"booking_ref": found.group()}}
        decoded = json.loads(payload)
        return {
            "name": "search_baggage_policy",
            "arguments": {"airline": decoded["airline"], "topic": "carry_on"},
        }


def run_demo() -> dict[str, object]:
    sinks = Sinks()
    model = ModelStub(sinks)
    with create_session(sinks) as app:
        booking = app.protect_value(BOOKING_A, kind="BOOKING", classification=C.CONFIDENTIAL)
        lookup = app.send_model(model, [PublicText("Lookup "), booking])
        result = app.execute_tool_call(lookup)
        search = app.send_tool_result(model, result)
        policy = app.execute_tool_call(search)
        app.send_tool_result(sinks.model_send, policy)
        denied = ""
        try:
            app.execute_tool_call(
                {
                    "name": "search_baggage_policy",
                    "arguments": {"airline": booking.token, "topic": "carry_on"},
                }
            )
        except MaskRouteError as error:
            denied = error.code.value
        passenger = result.fields["passenger"]
        assert isinstance(passenger, ProtectedRef)
        display = app.render_plain_text(
            "Booking confirmed for " + passenger.token + ".", allowed_kinds=frozenset({"PERSON"})
        )
        # The authorized display is consumed locally; never put its raw value into telemetry.
        assert display.text.startswith("Booking confirmed for ")
        assert sinks.disclosures() == 0
        return {
            "lookup": "allowed",
            "search": "allowed",
            "denied_disclosure": denied,
            "authorized_plain_text_display": "produced (private text omitted from log)",
            "public_policy": BAGGAGE,
            "model_requests": len(sinks.model),
            "search_requests": len(sinks.search),
            "forbidden_sink_disclosures": sinks.disclosures(),
        }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
