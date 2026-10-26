"""Trusted host identity and authorization contracts."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from .protection import Classification


class Destination(StrEnum):
    INTERNAL_TOOL = "INTERNAL_TOOL"
    EXTERNAL_SEARCH = "EXTERNAL_SEARCH"
    USER_DISPLAY = "USER_DISPLAY"


@dataclass(frozen=True)
class DisclosureRule:
    tool: str
    field: str
    kind: str
    destination: Destination
    classifications: frozenset[Classification]

    def __post_init__(self) -> None:
        object.__setattr__(self, "classifications", frozenset(self.classifications))


@dataclass(frozen=True)
class DisclosurePolicy:
    rules: tuple[DisclosureRule, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))

    def permits(
        self,
        *,
        tool: str,
        field: str,
        kind: str,
        destination: Destination,
        classification: Classification,
    ) -> bool:
        return any(
            r.tool == tool
            and r.field == field
            and r.kind == kind
            and r.destination == destination
            and classification in r.classifications
            for r in self.rules
        )


@dataclass(frozen=True)
class AuthorizationRequest:
    principal: str = field(repr=False)
    action: str
    resource: str = field(repr=False)
    context: Mapping[str, str] = field(repr=False)
    destination: Destination
    tool: str | None
    field: str
    kind: str


Authorizer = Callable[[AuthorizationRequest], bool]
