"""Only interface adaptation; the independent handwritten baseline owns its checks."""

from collections.abc import Callable
from typing import Protocol

from baseline.controls import UnprotectedTravel
from baseline.travel_support import HandwrittenTravel
from examples.travel_support.application import create_session
from examples.travel_support.fixtures import Sinks
from maskroute import Classification as C
from maskroute import ProtectedRef, ProtectedResult


class Workflow(Protocol):
    def protect(self, value: str, kind: str = "BOOKING", resource: str | None = None) -> str: ...
    def issue(self, token: str) -> str: ...
    def call(self, proposal: object) -> dict[str, str]: ...
    def send_result(self, result: dict[str, str]) -> None: ...
    def close(self) -> None: ...


Factory = Callable[[Sinks], Workflow]


class MaskRouteTravel:
    def __init__(self, sinks: Sinks) -> None:
        self.session = create_session(sinks)
        self.sinks = sinks
        self.refs: dict[str, ProtectedRef] = {}
        self.results: dict[int, ProtectedResult] = {}

    def protect(self, value: str, kind: str = "BOOKING", resource: str | None = None) -> str:
        ref = self.session.protect_value(
            value,
            kind=kind,
            classification=C.PUBLIC if kind == "AIRLINE" else C.CONFIDENTIAL,
            resource=resource,
        )
        self.refs[ref.token] = ref
        return ref.token

    def issue(self, token: str) -> str:
        self.session.send_model(self.sinks.model_send, [self.refs[token]])
        return token

    def call(self, proposal: object) -> dict[str, str]:
        result = self.session.execute_tool_call(proposal)
        visible = {
            key: value.token if isinstance(value, ProtectedRef) else value.text
            for key, value in result.fields.items()
        }
        self.results[id(visible)] = result
        return visible

    def send_result(self, result: dict[str, str]) -> None:
        self.session.send_tool_result(self.sinks.model_send, self.results.pop(id(result)))

    def close(self) -> None:
        self.session.close()
        self.refs.clear()
        self.results.clear()


FACTORIES: dict[str, Factory] = {
    "unprotected": lambda sinks: UnprotectedTravel("traveler_a", sinks),
    "blanket_redaction": lambda sinks: UnprotectedTravel("traveler_a", sinks, redact=True),
    "handwritten": lambda sinks: HandwrittenTravel("traveler_a", sinks),
    "maskroute": MaskRouteTravel,
}
