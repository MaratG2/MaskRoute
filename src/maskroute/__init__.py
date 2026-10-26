"""MaskRoute: explicit protection for mediated model/tool workflows."""

from .detection import DictionaryEntry, detect_best_effort
from .errors import Code, MaskRouteError
from .policy import AuthorizationRequest, Destination, DisclosurePolicy, DisclosureRule
from .protection import (
    Classification,
    PlainTextResponse,
    ProtectedRef,
    ProtectedResult,
    ProtectedText,
    PublicText,
    SensitiveSpan,
    SensitiveValue,
)
from .session import ProtectionSession
from .tools import (
    EnumField,
    ForbiddenOutput,
    ProtectedOutput,
    PublicOutput,
    ReferenceField,
    ToolSpec,
)

__all__ = [
    "DictionaryEntry",
    "detect_best_effort",
    "ForbiddenOutput",
    "PlainTextResponse",
    "ProtectedOutput",
    "ProtectedResult",
    "PublicOutput",
    "Destination",
    "DisclosurePolicy",
    "DisclosureRule",
    "EnumField",
    "ReferenceField",
    "ToolSpec",
    "AuthorizationRequest",
    "Classification",
    "Code",
    "MaskRouteError",
    "ProtectedRef",
    "ProtectedText",
    "ProtectionSession",
    "PublicText",
    "SensitiveSpan",
    "SensitiveValue",
]
