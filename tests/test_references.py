from typing import cast

import pytest

from examples.travel_support.fixtures import BOOKING_A, Sinks
from maskroute import (
    Classification as C,
)
from maskroute import (
    Code,
    MaskRouteError,
    ProtectedRef,
    ProtectionSession,
    PublicText,
    SensitiveSpan,
    SensitiveValue,
)
from maskroute.policy import Authorizer


def session() -> ProtectionSession:
    return ProtectionSession(principal="traveler_a", authorizer=lambda request: True)


def booking(app: ProtectionSession) -> ProtectedRef:
    return app.protect_value(BOOKING_A, kind="BOOKING", classification=C.CONFIDENTIAL)


def test_s01_s02_explicit_payload_stability_isolation() -> None:
    sinks = Sinks()
    app, other = session(), session()
    ref = booking(app)
    assert booking(app) is ref
    assert booking(other).token != ref.token
    app.send_model(sinks.model_send, [PublicText("Lookup "), ref])
    assert sinks.model == ["Lookup " + ref.token]
    assert sinks.disclosures() == 0
    assert len(ref.token.rsplit("_", 1)[1][:-2]) == 32
    assert BOOKING_A not in repr(ref) + repr(app)


def test_s04_creation_not_issuance() -> None:
    app = session()
    ref = booking(app)
    with pytest.raises(MaskRouteError, match=Code.UNISSUED_REFERENCE):
        app._registry.get(ref.token)
    app.send_model(lambda payload: payload, [ref])
    assert app._registry.get(ref.token).issued


@pytest.mark.parametrize("attack", ["foreign", "forged", "altered", "revoked", "closed"])
def test_s05_s06_reference_rejection(attack: str) -> None:
    app = session()
    sinks = Sinks()
    ref = booking(app)
    if attack == "foreign":
        ref = booking(session())
    elif attack == "forged":
        ref = ProtectedRef(ref.token, "BOOKING")
    elif attack == "altered":
        ref = ProtectedRef(ref.token + "x", "BOOKING")
    elif attack == "revoked":
        app.revoke(ref)
    elif attack == "closed":
        app.close()
    with pytest.raises(MaskRouteError):
        app.send_model(sinks.model_send, [ref])
    assert sinks.model == []


def test_token_text_never_issues_and_failed_provider_does_not_issue() -> None:
    app = session()
    sinks = Sinks()
    ref = booking(app)
    with pytest.raises(MaskRouteError, match=Code.TOKEN_LIKE_TEXT):
        app.send_model(sinks.model_send, [PublicText(ref.token)])
    assert sinks.model == []

    def fail(payload: str) -> str:
        sinks.model_send(payload)
        raise RuntimeError(BOOKING_A)

    with pytest.raises(MaskRouteError, match=Code.PROVIDER_FAILED) as caught:
        app.send_model(fail, [ref])
    assert caught.value.__context__ is None
    assert not app._registry.get(ref.token, issued=False).issued
    assert sinks.disclosures() == 0


def test_span_boundaries_and_unlabeled_occurrence() -> None:
    app = session()
    sinks = Sinks()
    text = "Luma and Luma"
    protected = app.protect_spans(text, [SensitiveSpan(0, 4, "PERSON", C.CONFIDENTIAL)])
    app.send_model(sinks.model_send, [protected])
    assert sinks.model[0].endswith(" and Luma")  # Only the explicitly marked occurrence.
    assert not sinks.model[0].startswith("Luma")


@pytest.mark.parametrize("ranges", [[(-1, 2)], [(0, 99)], [(2, 2)], [(0, 3), (2, 4)]])
def test_invalid_spans(ranges: list[tuple[int, int]]) -> None:
    app = session()
    with pytest.raises(MaskRouteError, match=Code.INVALID_SCHEMA):
        app.protect_spans(
            "Luma", [SensitiveSpan(a, b, "PERSON", C.CONFIDENTIAL) for a, b in ranges]
        )


def test_metadata_conflict_missing_authorizer_and_teardown() -> None:
    with pytest.raises(MaskRouteError, match=Code.AUTHORIZER_REQUIRED):
        ProtectionSession(principal="traveler_a", authorizer=cast(Authorizer, None))
    with session() as app:
        booking(app)
        with pytest.raises(MaskRouteError, match=Code.METADATA_CONFLICT):
            app.protect_value(
                BOOKING_A, kind="BOOKING", classification=C.CONFIDENTIAL, resource="x"
            )
    with pytest.raises(MaskRouteError, match=Code.SESSION_CLOSED):
        booking(app)
    assert BOOKING_A not in repr(SensitiveValue(BOOKING_A, "BOOKING", C.CONFIDENTIAL))
