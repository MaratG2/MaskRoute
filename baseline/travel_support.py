"""Handwritten, application-specific boundary built before the SDK.

It deliberately has the same security checks as the travel slice, without a generic
schema/registry framework. Its trusted host API is deliberately small and fixed.
"""

import contextlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field

from examples.travel_support.fixtures import AIRLINE, BAGGAGE, TOPICS, Sinks, authorize

Authorizer = Callable[[str, str, str], bool]


class Denied(Exception):
    """A constant error, with no model arguments or tool exception details."""

    def __init__(self) -> None:
        super().__init__("DENIED")


@dataclass(repr=False)
class HandwrittenTravel:
    principal: str
    sinks: Sinks
    authorizer: Authorizer = authorize
    _values: dict[str, tuple[str, str, str]] = field(default_factory=dict, init=False)
    _issued: set[str] = field(default_factory=set, init=False)
    _closed: bool = field(default=False, init=False)

    def _open(self) -> None:
        if self._closed or not callable(self.authorizer):
            raise Denied()

    def protect(self, value: str, kind: str = "BOOKING", resource: str | None = None) -> str:
        self._open()
        metadata = (value, kind, resource or value)
        for token, existing in self._values.items():
            if metadata == existing:
                return token
        token = f"[[{kind}_{secrets.token_hex(16)}]]"
        self._values[token] = metadata
        return token

    def issue(self, token: str) -> str:
        self._open()
        if token not in self._values:
            raise Denied()
        self._issued.add(token)
        self.sinks.model_send(token)
        return token

    def _check(self, token: str, kind: str, action: str) -> str:
        if token not in self._issued or token not in self._values:
            raise Denied()
        value, actual_kind, resource = self._values[token]
        if actual_kind != kind:
            raise Denied()
        allowed = False
        with contextlib.suppress(Exception):
            allowed = self.authorizer(self.principal, action, resource) is True
        if not allowed:
            raise Denied()
        return value

    def call(self, proposal: object) -> dict[str, str]:
        self._open()
        if type(proposal) is not dict or set(proposal) != {"name", "arguments"}:
            raise Denied()
        name, args = proposal["name"], proposal["arguments"]
        if type(name) is not str or type(args) is not dict:
            raise Denied()
        if any(type(k) is not str or type(v) is not str for k, v in args.items()):
            raise Denied()
        if name == "lookup_booking" and set(args) == {"booking_ref"}:
            value = self._check(args["booking_ref"], "BOOKING", name)
            output: object = None
            with contextlib.suppress(Exception):
                output = self.sinks.lookup(value)
            expected = {"airline", "passenger", "contact", "status"}
            if type(output) is not dict or set(output) != expected:
                raise Denied()
            if any(type(v) is not str for v in output.values()):
                raise Denied()
            if output["airline"] != AIRLINE or output["status"] != "confirmed":
                raise Denied()
            result = {"status": "confirmed"}
            for key, kind in (
                ("airline", "AIRLINE"),
                ("passenger", "PERSON"),
                ("contact", "EMAIL"),
            ):
                resource = AIRLINE if key == "airline" else value
                result[key] = self.protect(output[key], kind, resource)
            return result
        if name == "search_baggage_policy" and set(args) == {"airline", "topic"}:
            if args["topic"] not in TOPICS:
                raise Denied()
            airline = self._check(args["airline"], "AIRLINE", name)
            if airline != AIRLINE:
                raise Denied()
            response: str | None = None
            with contextlib.suppress(Exception):
                response = self.sinks.search_send(f"{airline} {args['topic']} baggage policy")
            if response is None or response != BAGGAGE:
                raise Denied()
            return {"policy": response}
        raise Denied()

    def send_result(self, result: dict[str, str]) -> None:
        self._open()
        # Trusted application calls this only on the validated call() result.
        self._issued.update(value for value in result.values() if value in self._values)
        self.sinks.model_send(json.dumps(result, sort_keys=True))

    def close(self) -> None:
        self._values.clear()
        self._issued.clear()
        self._closed = True
