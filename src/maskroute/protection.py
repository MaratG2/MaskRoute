"""Explicit typed inputs. PublicText is a trusted host assertion, not a detector."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass(frozen=True)
class SensitiveValue:
    value: str = field(repr=False)
    kind: str
    classification: Classification
    resource: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SensitiveSpan:
    start: int
    end: int
    kind: str
    classification: Classification
    resource: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class PublicText:
    text: str = field(repr=False)


@dataclass(frozen=True)
class ProtectedRef:
    """The handle is public; construction alone does not establish registry membership."""

    token: str = field(repr=False)
    kind: str


@dataclass(frozen=True, repr=False)
class ProtectedText:
    parts: tuple[PublicText | ProtectedRef, ...]
    best_effort: bool = False


@dataclass(frozen=True, repr=False)
class ProtectedResult:
    fields: Mapping[str, PublicText | ProtectedRef]
    _owner: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


@dataclass(frozen=True, repr=False)
class PlainTextResponse:
    """Display using a literal text surface; never feed into a rich-text/URL renderer."""

    text: str
