"""Optional PIIGhost 2.1.1 + exactly the handwritten host authorization/output checks.

Uses public APIs only; the random per-session delimiter is a supported factory option.
This evaluates an integrated alternative, not PIIGhost alone as a security gateway.
"""

import asyncio
import secrets

from piighost.components.anonymizer import Anonymizer
from piighost.components.detector import ExactMatchDetector
from piighost.components.placeholder import LabelCounterPlaceholderFactory
from piighost.pipeline import ThreadAnonymizationPipeline

from baseline.travel_support import Denied, HandwrittenTravel
from examples.travel_support.fixtures import (
    AIRLINE,
    BOOKING_A,
    BOOKING_B,
    CONTACT,
    PASSENGER,
    Sinks,
)


class PiighostTravel(HandwrittenTravel):
    def __init__(self, sinks: Sinks) -> None:
        super().__init__("traveler_a", sinks)
        self._runner = asyncio.Runner()
        self._thread = secrets.token_hex(16)
        factory = LabelCounterPlaceholderFactory(prefix=f"<<{self._thread}|")
        self._pipeline = ThreadAnonymizationPipeline(
            ExactMatchDetector(
                {
                    BOOKING_A: "BOOKING",
                    BOOKING_B: "BOOKING",
                    AIRLINE: "AIRLINE",
                    "Unapproved Fake Air": "AIRLINE",
                    PASSENGER: "PERSON",
                    CONTACT: "EMAIL",
                }
            ),
            anonymizer=Anonymizer(factory),
            observation_redactor=factory,
        )

    def protect(self, value: str, kind: str = "BOOKING", resource: str | None = None) -> str:
        self._open()
        result = self._runner.run(self._pipeline.anonymize(value, thread_id=self._thread))
        token = str(result.text)
        if token == value:
            raise Denied()
        self._values[token] = (value, kind, resource or value)
        return token

    def _check(self, token: str, kind: str, action: str) -> str:
        expected = super()._check(token, kind, action)
        restored = self._runner.run(self._pipeline.deanonymize(token, thread_id=self._thread))
        if not isinstance(restored, str) or restored != expected:
            raise Denied()
        return restored

    def close(self) -> None:
        if not self._closed:
            self._runner.run(self._pipeline.forget_thread(thread_id=self._thread))
            self._runner.close()
        super().close()
