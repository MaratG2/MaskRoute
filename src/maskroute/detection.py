"""Tiny optional detector. Exact dictionaries and regexes demonstrably miss entities."""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from .errors import Code, MaskRouteError
from .protection import Classification, SensitiveSpan, SensitiveValue

EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])")
PHONE = re.compile(r"(?<!\w)\+\d[\d ()-]{7,}\d(?!\w)")


@dataclass(frozen=True)
class DictionaryEntry:
    text: str = field(repr=False)
    kind: str
    classification: Classification = Classification.CONFIDENTIAL


def detect_best_effort(
    text: str,
    dictionary: Sequence[DictionaryEntry] = (),
) -> tuple[SensitiveSpan, ...]:
    """Dictionary matches win overlaps; regex matches then win by start/longest.

    Matches are case sensitive and literal. No aliases, coreference, obfuscated email,
    ordinary names, or contextual sensitivity inference is attempted.
    """
    if type(text) is not str:
        raise MaskRouteError(Code.INVALID_SCHEMA)
    candidates: list[tuple[int, SensitiveSpan]] = []
    for entry in dictionary:
        if type(entry) is not DictionaryEntry or not entry.text:
            raise MaskRouteError(Code.INVALID_SCHEMA)
        for match in re.finditer(re.escape(entry.text), text):
            candidates.append(
                (0, SensitiveSpan(match.start(), match.end(), entry.kind, entry.classification))
            )
    for pattern, kind in ((EMAIL, "EMAIL"), (PHONE, "PHONE")):
        for match in pattern.finditer(text):
            candidates.append(
                (1, SensitiveSpan(match.start(), match.end(), kind, Classification.CONFIDENTIAL))
            )
    selected: list[SensitiveSpan] = []
    for _, span in sorted(
        candidates, key=lambda item: (item[0], item[1].start, -(item[1].end - item[1].start))
    ):
        if all(span.end <= other.start or span.start >= other.end for other in selected):
            selected.append(span)
    return tuple(sorted(selected, key=lambda span: span.start))


def detected_value(text: str, span: SensitiveSpan) -> SensitiveValue:
    return SensitiveValue(
        text[span.start : span.end], span.kind, span.classification, span.resource
    )
