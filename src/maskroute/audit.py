"""Decision records contain only fixed codes and trusted schema identifiers."""

from dataclasses import dataclass
from enum import StrEnum

from .errors import Code
from .policy import Destination


class Action(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    RESTORE = "RESTORE"
    PROTECT = "PROTECT"


@dataclass(frozen=True)
class Event:
    action: Action
    reason: Code
    destination: Destination | None = None
    tool: str | None = None
    kind: str | None = None
