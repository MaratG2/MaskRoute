"""No masking / irreversible blanket redaction, with the same host business checks.

Neither control is intentionally given generic shell/search privileges. The only
experimental variable is what reaches the model and whether a booking can roundtrip.
"""

import json
from dataclasses import dataclass

from examples.travel_support.fixtures import (
    AIRLINE,
    BAGGAGE,
    PRIVATE_VALUES,
    TOPICS,
    Sinks,
    authorize,
)

from .travel_support import Denied


@dataclass(repr=False)
class UnprotectedTravel:
    principal: str
    sinks: Sinks
    redact: bool = False
    _closed: bool = False

    def protect(self, value: str, kind: str = "BOOKING", resource: str | None = None) -> str:
        return "[REDACTED]" if self.redact and kind != "AIRLINE" else value

    def issue(self, token: str) -> str:
        if self._closed:
            raise Denied()
        self.sinks.model_send(token)
        return token

    def call(self, proposal: object) -> dict[str, str]:
        if self._closed or type(proposal) is not dict or set(proposal) != {"name", "arguments"}:
            raise Denied()
        name, args = proposal["name"], proposal["arguments"]
        if type(name) is not str or type(args) is not dict:
            raise Denied()
        if any(type(k) is not str or type(v) is not str for k, v in args.items()):
            raise Denied()
        if name == "lookup_booking" and set(args) == {"booking_ref"}:
            booking = args["booking_ref"]
            if not authorize(self.principal, name, booking):
                raise Denied()
            result = self.sinks.lookup(booking)
            # The same output whitelist is retained; masking is the variable.
            if set(result) != {"airline", "passenger", "contact", "status"}:
                raise Denied()
            if any(type(v) is not str for v in result.values()):
                raise Denied()
            return {key: str(value) for key, value in result.items()}
        if name == "search_baggage_policy" and set(args) == {"airline", "topic"}:
            if args["airline"] != AIRLINE or args["topic"] not in TOPICS:
                raise Denied()
            if not authorize(self.principal, name, args["airline"]):
                raise Denied()
            response = self.sinks.search_send(f"{args['airline']} {args['topic']} baggage policy")
            if response != BAGGAGE:
                raise Denied()
            return {"policy": response}
        raise Denied()

    def send_result(self, result: dict[str, str]) -> None:
        payload = json.dumps(result, sort_keys=True)
        if self.redact:
            for value in PRIVATE_VALUES:
                payload = payload.replace(value, "[REDACTED]")
        self.sinks.model_send(payload)

    def close(self) -> None:
        self._closed = True
