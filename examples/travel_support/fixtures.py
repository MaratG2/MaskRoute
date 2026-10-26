"""Entirely invented fixtures and recording sinks shared by every comparison."""

from dataclasses import dataclass, field

BOOKING_A = "BK-FAKE-101"
BOOKING_B = "BK-FAKE-202"
AIRLINE = "Cloud Kestrel Air"
PASSENGER = "Luma Exampleton"
CONTACT = "luma@example.invalid"
PAYMENT = "PAYMENT-FAKE-NEVER-DISCLOSE"
PRIVATE_VALUES = (BOOKING_A, BOOKING_B, PASSENGER, CONTACT, PAYMENT)
OWNERS = {BOOKING_A: "traveler_a", BOOKING_B: "traveler_b"}
TOPICS = frozenset({"carry_on", "checked_baggage"})
BAGGAGE = "Synthetic allowance: one cabin bag."


@dataclass(repr=False)
class Sinks:
    """Capture actual boundary payloads; never print these raw test fixtures as logs."""

    model: list[str] = field(default_factory=list)
    search: list[str] = field(default_factory=list)
    internal: list[dict[str, str]] = field(default_factory=list)
    hostile_output: bool = False

    def model_send(self, payload: str) -> str:
        self.model.append(payload)
        return payload

    def lookup(self, booking_ref: str) -> dict[str, object]:
        self.internal.append({"booking_ref": booking_ref})
        result: dict[str, object] = {
            "airline": AIRLINE,
            "passenger": PASSENGER,
            "contact": CONTACT,
            "status": "confirmed",
        }
        if self.hostile_output:
            result["payment_token"] = PAYMENT
        return result

    def search_send(self, query: str) -> str:
        self.search.append(query)
        return BAGGAGE

    def disclosures(self) -> int:
        """Count (payload, protected value) pairs at forbidden model/search sinks."""
        return sum(
            value in payload for payload in self.model + self.search for value in PRIVATE_VALUES
        )


def authorize(principal: str, action: str, resource: str) -> bool:
    if action in {"lookup_booking", "display"}:
        return OWNERS.get(resource) == principal
    return action == "search_baggage_policy" and resource == AIRLINE
