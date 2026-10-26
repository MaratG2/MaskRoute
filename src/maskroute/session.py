"""Serial, in-memory protection sessions and mediated model calls."""

import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from time import monotonic
from types import MappingProxyType, TracebackType
from typing import TypeVar

from .audit import Action, Event
from .detection import DictionaryEntry, detect_best_effort, detected_value
from .errors import Code, MaskRouteError
from .policy import AuthorizationRequest, Authorizer, Destination, DisclosurePolicy
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
from .references import TOKEN, Registry
from .tools import (
    EnumField,
    ForbiddenOutput,
    ProtectedOutput,
    PublicOutput,
    ReferenceField,
    ToolSpec,
    parse_call,
)

T = TypeVar("T")
MessagePart = PublicText | ProtectedRef | ProtectedText


class ProtectionSession:
    def __init__(
        self,
        *,
        principal: str,
        authorizer: Authorizer,
        policy: DisclosurePolicy | None = None,
        context: Mapping[str, str] | None = None,
        authorization_timeout_seconds: float = 1.0,
    ) -> None:
        if not callable(authorizer):
            raise MaskRouteError(Code.AUTHORIZER_REQUIRED)
        if type(principal) is not str or not principal:
            raise MaskRouteError(Code.INVALID_SCHEMA)
        self._principal = principal
        self._authorizer = authorizer
        self._registry = Registry()
        self._closed = False
        self._policy = policy if policy is not None else DisclosurePolicy()
        self._context = MappingProxyType(dict(context or {}))
        if not math.isfinite(authorization_timeout_seconds) or authorization_timeout_seconds <= 0:
            raise MaskRouteError(Code.INVALID_SCHEMA)
        self._authorization_timeout = authorization_timeout_seconds
        self._tools: dict[str, ToolSpec] = {}
        self._events: list[Event] = []
        self._owner = object()

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def _record(
        self,
        action: Action,
        reason: Code = Code.OK,
        *,
        destination: Destination | None = None,
        tool: str | None = None,
        kind: str | None = None,
    ) -> None:
        self._events.append(Event(action, reason, destination, tool, kind))

    def _open(self) -> None:
        if self._closed:
            raise MaskRouteError(Code.SESSION_CLOSED)

    def protect_value(
        self,
        value: str,
        *,
        kind: str,
        classification: Classification,
        resource: str | None = None,
    ) -> ProtectedRef:
        self._open()
        ref = self._registry.protect(
            SensitiveValue(value, kind, classification, resource), "explicit"
        )
        self._record(Action.PROTECT, kind=ref.kind)
        return ref

    def protect_spans(self, text: str, spans: Sequence[SensitiveSpan]) -> ProtectedText:
        self._open()
        if type(text) is not str or any(type(s) is not SensitiveSpan for s in spans):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        if any(type(s.start) is not int or type(s.end) is not int for s in spans):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        ordered = sorted(spans, key=lambda span: span.start)
        end = 0
        for span in ordered:
            if not 0 <= end <= span.start < span.end <= len(text):
                raise MaskRouteError(Code.INVALID_SCHEMA)
            end = span.end
        parts: list[PublicText | ProtectedRef] = []
        end = 0
        for span in ordered:
            parts.append(PublicText(text[end : span.start]))
            parts.append(
                self._registry.protect(
                    SensitiveValue(
                        text[span.start : span.end], span.kind, span.classification, span.resource
                    ),
                    "span",
                )
            )
            end = span.end
        parts.append(PublicText(text[end:]))
        return ProtectedText(tuple(parts))

    def protect_text_best_effort(
        self,
        text: str,
        *,
        dictionary: Sequence[DictionaryEntry] = (),
    ) -> ProtectedText:
        self._open()
        spans = detect_best_effort(text, dictionary)
        parts: list[PublicText | ProtectedRef] = []
        end = 0
        for span in spans:
            parts.append(PublicText(text[end : span.start]))
            ref = self._registry.protect(detected_value(text, span), "detected_best_effort")
            parts.append(ref)
            self._record(Action.PROTECT, kind=ref.kind)
            end = span.end
        parts.append(PublicText(text[end:]))
        return ProtectedText(tuple(parts), best_effort=True)

    def _assemble(self, parts: Sequence[MessagePart]) -> tuple[str, list[ProtectedRef]]:
        self._open()
        content: list[str] = []
        refs: list[ProtectedRef] = []
        for part in parts:
            if type(part) is PublicText:
                if type(part.text) is not str:
                    raise MaskRouteError(Code.INVALID_SCHEMA)
                if "[[" in part.text or "]]" in part.text:
                    raise MaskRouteError(Code.TOKEN_LIKE_TEXT)
                content.append(part.text)
            elif type(part) is ProtectedRef:
                self._registry.typed(part)
                content.append(part.token)
                refs.append(part)
            elif type(part) is ProtectedText:
                # Only a flat sequence is allowed, even when Python callers ignore type hints.
                if any(type(p) not in {PublicText, ProtectedRef} for p in part.parts):
                    raise MaskRouteError(Code.INVALID_SCHEMA)
                nested, nested_refs = self._assemble(part.parts)
                content.append(nested)
                refs.extend(nested_refs)
            else:
                raise MaskRouteError(Code.INVALID_SCHEMA)
        return "".join(content), refs

    def send_model(self, provider: Callable[[str], T], parts: Sequence[MessagePart]) -> T:
        """Issue typed references only on a successful mediated outbound call.

        A provider failure may have received the protected payload. It does not grant
        new issuance locally, and there is no automatic retry.
        """
        payload, refs = self._assemble(parts)
        return self._transmit(provider, payload, refs)

    def _transmit(self, provider: Callable[[str], T], payload: str, refs: list[ProtectedRef]) -> T:
        succeeded = False
        result: T
        with suppress(Exception):
            result = provider(payload)
            succeeded = True
        if not succeeded:
            self._record(Action.DENY, Code.PROVIDER_FAILED)
            raise MaskRouteError(Code.PROVIDER_FAILED)
        for ref in refs:
            self._registry.typed(ref).issued = True
        self._record(Action.ALLOW)
        return result

    def send_tool_result(self, provider: Callable[[str], T], result: ProtectedResult) -> T:
        self._open()
        if type(result) is not ProtectedResult or result._owner is not self._owner:
            raise MaskRouteError(Code.INVALID_SCHEMA)
        payload: dict[str, str] = {}
        refs: list[ProtectedRef] = []
        for key, value in result.fields.items():
            text, typed = self._assemble([value])
            payload[key] = text
            refs.extend(typed)
        return self._transmit(provider, json.dumps(payload, sort_keys=True), refs)

    def revoke(self, ref: ProtectedRef) -> None:
        self._open()
        self._registry.typed(ref).revoked = True

    def register_tool(self, tool: ToolSpec) -> None:
        self._open()
        if type(tool) is not ToolSpec or tool.name in self._tools:
            raise MaskRouteError(Code.INVALID_SCHEMA)
        self._tools[tool.name] = tool

    def _authorize(self, request: AuthorizationRequest) -> None:
        allowed = False
        start = monotonic()
        with suppress(Exception):
            allowed = self._authorizer(request) is True
        if monotonic() - start > self._authorization_timeout:
            raise MaskRouteError(Code.AUTHORIZATION_TIMEOUT)
        if not allowed:
            raise MaskRouteError(Code.UNAUTHORIZED)

    def execute_tool_call(self, proposal: object) -> ProtectedResult:
        try:
            return self._execute_tool_call(proposal)
        except MaskRouteError as error:
            # Never include the untrusted proposed name, arguments, or handles.
            self._record(Action.DENY, error.code)
            raise

    def _require_live_references(self, tokens: Sequence[str]) -> None:
        # A trusted callback can close/revoke while authorizing a later field.
        # Revalidate the complete set at the final disclosure boundary.
        self._open()
        for token in tokens:
            self._registry.get(token)

    def _execute_tool_call(self, proposal: object) -> ProtectedResult:
        self._open()
        name, args = parse_call(proposal)
        tool = self._tools.get(name)
        if tool is None:
            raise MaskRouteError(Code.UNKNOWN_TOOL)
        if set(args) != set(tool.fields):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        restored: dict[str, str] = {}
        references: list[str] = []
        for field, rule in tool.fields.items():
            value = args[field]
            if isinstance(rule, EnumField):
                if value not in rule.choices:
                    raise MaskRouteError(Code.INVALID_SCHEMA)
                restored[field] = value
                continue
            assert isinstance(rule, ReferenceField)
            entry = self._registry.get(value)
            if entry.ref.kind != rule.kind:
                raise MaskRouteError(Code.WRONG_KIND)
            if not self._policy.permits(
                tool=name,
                field=field,
                kind=rule.kind,
                destination=tool.destination,
                classification=entry.classification,
            ):
                raise MaskRouteError(Code.POLICY_DENIED)
            if tool.destination == Destination.EXTERNAL_SEARCH and (
                entry.classification != Classification.PUBLIC
                or entry.value not in rule.public_values
            ):
                raise MaskRouteError(Code.POLICY_DENIED)
            self._authorize(
                AuthorizationRequest(
                    self._principal,
                    name,
                    entry.resource,
                    self._context,
                    tool.destination,
                    name,
                    field,
                    rule.kind,
                )
            )
            restored[field] = entry.value
            references.append(value)
        # Authorization is required even for a tool having no reference arguments.
        if not any(isinstance(rule, ReferenceField) for rule in tool.fields.values()):
            self._authorize(
                AuthorizationRequest(
                    self._principal,
                    name,
                    name,
                    self._context,
                    tool.destination,
                    name,
                    "",
                    "",
                )
            )
        self._require_live_references(references)
        succeeded = False
        output: object = None
        for rule in tool.fields.values():
            if isinstance(rule, ReferenceField):
                self._record(
                    Action.RESTORE, destination=tool.destination, tool=name, kind=rule.kind
                )
        with suppress(Exception):
            output = tool.handler(MappingProxyType(restored))
            succeeded = True
        if not succeeded:
            raise MaskRouteError(Code.TOOL_FAILED)
        result = self._protect_output(tool, output, args)
        self._record(Action.ALLOW, destination=tool.destination, tool=name)
        return result

    def _protect_output(
        self,
        tool: ToolSpec,
        output: object,
        args: Mapping[str, str],
    ) -> ProtectedResult:
        if type(output) is not dict or any(type(k) is not str for k in output):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        if set(output) - set(tool.outputs):
            raise MaskRouteError(Code.UNCLASSIFIED_OUTPUT)
        required = {k for k, rule in tool.outputs.items() if not isinstance(rule, ForbiddenOutput)}
        if required - set(output):
            raise MaskRouteError(Code.INVALID_SCHEMA)
        # Validate the entire result before allocating any references or issuing any content.
        for key, value in output.items():
            rule = tool.outputs[key]
            if isinstance(rule, ForbiddenOutput):
                raise MaskRouteError(Code.FORBIDDEN_OUTPUT)
            if type(value) is not str or not value:
                raise MaskRouteError(Code.INVALID_SCHEMA)
            if isinstance(rule, PublicOutput) and value not in rule.allowed_values:
                raise MaskRouteError(Code.FORBIDDEN_OUTPUT)
        protected: dict[str, PublicText | ProtectedRef] = {}
        for key, value in output.items():
            rule = tool.outputs[key]
            if isinstance(rule, PublicOutput):
                protected[key] = PublicText(value)
            elif isinstance(rule, ProtectedOutput):
                resource = (
                    self._registry.get(args[rule.resource_from]).resource
                    if rule.resource_from is not None
                    else value
                )
                ref = self._registry.protect(
                    SensitiveValue(value, rule.kind, rule.classification, resource),
                    "tool_output",
                )
                protected[key] = ref
                self._record(
                    Action.PROTECT, destination=tool.destination, tool=tool.name, kind=rule.kind
                )
        return ProtectedResult(protected, self._owner)

    def render_plain_text(self, text: str, *, allowed_kinds: frozenset[str]) -> PlainTextResponse:
        """Restore exact issued tokens only to an authenticated literal text display.

        Deliberately conservative: rich syntax, URLs, partial tokens and JSON are rejected.
        The host supplies allowed kinds and must render the result as inert plain text.
        """
        try:
            return self._render_plain_text(text, allowed_kinds)
        except MaskRouteError as error:
            self._record(Action.DENY, error.code, destination=Destination.USER_DISPLAY)
            raise

    def _render_plain_text(self, text: str, allowed_kinds: frozenset[str]) -> PlainTextResponse:
        self._open()
        if type(text) is not str:
            raise MaskRouteError(Code.UNSAFE_SURFACE)
        remainder = TOKEN.sub("", text)
        if re.fullmatch(r"[\w\s.,!?;()'’\"\-]*", remainder) is None or re.search(
            r"\bwww\.", remainder, re.IGNORECASE
        ):
            raise MaskRouteError(Code.UNSAFE_SURFACE)
        pieces: list[str] = []
        end = 0
        for match in TOKEN.finditer(text):
            entry = self._registry.get(match.group())
            if entry.ref.kind not in allowed_kinds:
                raise MaskRouteError(Code.POLICY_DENIED)
            self._authorize(
                AuthorizationRequest(
                    self._principal,
                    "display",
                    entry.resource,
                    self._context,
                    Destination.USER_DISPLAY,
                    None,
                    "text",
                    entry.ref.kind,
                )
            )
            pieces.extend((text[end : match.start()], entry.value))
            end = match.end()
        pieces.append(text[end:])
        self._require_live_references([match.group() for match in TOKEN.finditer(text)])
        self._record(Action.RESTORE, destination=Destination.USER_DISPLAY)
        return PlainTextResponse("".join(pieces))

    def close(self) -> None:
        self._registry.clear()
        self._tools.clear()
        self._closed = True

    def __enter__(self) -> "ProtectionSession":
        self._open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
