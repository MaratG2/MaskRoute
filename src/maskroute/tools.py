"""Small closed string schemas: reference fields or finite enums; no recursive substitution."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .errors import Code, MaskRouteError
from .policy import Destination
from .protection import Classification
from .references import KIND

IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class ReferenceField:
    kind: str
    public_values: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_values", frozenset(self.public_values))


@dataclass(frozen=True)
class EnumField:
    choices: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "choices", frozenset(self.choices))


@dataclass(frozen=True)
class PublicOutput:
    """Trusted host attests a finite vocabulary for this field."""

    allowed_values: frozenset[str] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_values", frozenset(self.allowed_values))


@dataclass(frozen=True)
class ProtectedOutput:
    kind: str
    classification: Classification
    resource_from: str | None = None


@dataclass(frozen=True)
class ForbiddenOutput:
    pass


OutputField = PublicOutput | ProtectedOutput | ForbiddenOutput


@dataclass(frozen=True)
class ToolSpec:
    name: str
    destination: Destination
    fields: Mapping[str, ReferenceField | EnumField]
    handler: Callable[[Mapping[str, str]], object] = field(repr=False)
    outputs: Mapping[str, OutputField] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or IDENTIFIER.fullmatch(self.name) is None
            or not isinstance(self.destination, Destination)
            or self.destination == Destination.USER_DISPLAY
            or not callable(self.handler)
        ):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        for key, rule in self.fields.items():
            if type(key) is not str or IDENTIFIER.fullmatch(key) is None:
                raise MaskRouteError(Code.INVALID_SCHEMA)
            if type(rule) is ReferenceField:
                if KIND.fullmatch(rule.kind) is None:
                    raise MaskRouteError(Code.INVALID_SCHEMA)
            elif type(rule) is EnumField:
                if not rule.choices or any(type(v) is not str for v in rule.choices):
                    raise MaskRouteError(Code.INVALID_SCHEMA)
            else:
                raise MaskRouteError(Code.INVALID_SCHEMA)
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))
        for key, output in self.outputs.items():
            if type(key) is not str or IDENTIFIER.fullmatch(key) is None:
                raise MaskRouteError(Code.INVALID_SCHEMA)
            if type(output) is ProtectedOutput:
                if (
                    KIND.fullmatch(output.kind) is None
                    or not isinstance(output.classification, Classification)
                    or (
                        output.resource_from is not None
                        and not isinstance(self.fields.get(output.resource_from), ReferenceField)
                    )
                ):
                    raise MaskRouteError(Code.INVALID_SCHEMA)
            elif type(output) is PublicOutput:
                if not output.allowed_values or any(
                    type(v) is not str for v in output.allowed_values
                ):
                    raise MaskRouteError(Code.INVALID_SCHEMA)
            elif type(output) is not ForbiddenOutput:
                raise MaskRouteError(Code.INVALID_SCHEMA)
        object.__setattr__(self, "outputs", MappingProxyType(dict(self.outputs)))


def parse_call(proposal: object) -> tuple[str, dict[str, str]]:
    if type(proposal) is not dict or set(proposal) != {"name", "arguments"}:
        raise MaskRouteError(Code.INVALID_SCHEMA)
    name, args = proposal["name"], proposal["arguments"]
    if type(name) is not str or type(args) is not dict:
        raise MaskRouteError(Code.INVALID_SCHEMA)
    if any(type(k) is not str or type(v) is not str for k, v in args.items()):
        raise MaskRouteError(Code.INVALID_SCHEMA)
    return name, dict(args)
