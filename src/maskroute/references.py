"""Private, conversation-scoped registry. No persistence or Python RAM-zeroization claim."""

import re
import secrets
from dataclasses import dataclass

from .errors import Code, MaskRouteError
from .protection import Classification, ProtectedRef, SensitiveValue

KIND = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
TOKEN = re.compile(r"\[\[[A-Z][A-Z0-9_]{0,31}_[0-9a-f]{32}\]\]")


@dataclass(repr=False)
class Entry:
    ref: ProtectedRef
    value: str
    classification: Classification
    resource: str
    provenance: str
    issued: bool = False
    revoked: bool = False


class Registry:
    def __init__(self) -> None:
        self._entries: dict[str, Entry] = {}
        self._identities: dict[tuple[str, str, Classification], str] = {}

    def protect(self, value: SensitiveValue, provenance: str) -> ProtectedRef:
        if (
            type(value.value) is not str
            or not value.value
            or type(value.kind) is not str
            or KIND.fullmatch(value.kind) is None
            or not isinstance(value.classification, Classification)
            or (value.resource is not None and type(value.resource) is not str)
        ):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        key = (value.value, value.kind, value.classification)
        resource = value.resource if value.resource is not None else value.value
        if key in self._identities:
            entry = self._entries[self._identities[key]]
            if entry.resource != resource:
                raise MaskRouteError(Code.METADATA_CONFLICT)
            if entry.revoked:
                raise MaskRouteError(Code.REVOKED_REFERENCE)
            return entry.ref
        ref = ProtectedRef(f"[[{value.kind}_{secrets.token_hex(16)}]]", value.kind)
        self._entries[ref.token] = Entry(
            ref, value.value, value.classification, resource, provenance
        )
        self._identities[key] = ref.token
        return ref

    def get(self, token: str, *, issued: bool = True) -> Entry:
        entry = self._entries.get(token)
        if entry is None:
            raise MaskRouteError(Code.UNKNOWN_REFERENCE)
        if entry.revoked:
            raise MaskRouteError(Code.REVOKED_REFERENCE)
        if issued and not entry.issued:
            raise MaskRouteError(Code.UNISSUED_REFERENCE)
        return entry

    def typed(self, ref: ProtectedRef) -> Entry:
        entry = self.get(ref.token, issued=False)
        if entry.ref is not ref:
            raise MaskRouteError(Code.UNKNOWN_REFERENCE)
        return entry

    def clear(self) -> None:
        self._entries.clear()
        self._identities.clear()
