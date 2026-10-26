"""Trusted host policy for the two synthetic operations; no arbitrary query tool."""

from collections.abc import Mapping

from maskroute import (
    AuthorizationRequest,
    DisclosurePolicy,
    DisclosureRule,
    EnumField,
    ProtectedOutput,
    ProtectionSession,
    PublicOutput,
    ReferenceField,
    ToolSpec,
)
from maskroute import (
    Classification as C,
)
from maskroute import (
    Destination as D,
)
from maskroute.policy import Authorizer

from .fixtures import AIRLINE, BAGGAGE, TOPICS, Sinks, authorize


def host_authorize(request: AuthorizationRequest) -> bool:
    return authorize(request.principal, request.action, request.resource)


def create_session(
    sinks: Sinks,
    authorizer: Authorizer = host_authorize,
    *,
    principal: str = "traveler_a",
) -> ProtectionSession:
    app = ProtectionSession(
        principal=principal,
        authorizer=authorizer,
        policy=DisclosurePolicy(
            (
                DisclosureRule(
                    "lookup_booking",
                    "booking_ref",
                    "BOOKING",
                    D.INTERNAL_TOOL,
                    frozenset({C.CONFIDENTIAL}),
                ),
                DisclosureRule(
                    "search_baggage_policy",
                    "airline",
                    "AIRLINE",
                    D.EXTERNAL_SEARCH,
                    frozenset({C.PUBLIC}),
                ),
            )
        ),
    )
    app.register_tool(
        ToolSpec(
            "lookup_booking",
            D.INTERNAL_TOOL,
            {"booking_ref": ReferenceField("BOOKING")},
            lambda args: sinks.lookup(args["booking_ref"]),
            outputs={
                "airline": ProtectedOutput("AIRLINE", C.PUBLIC),
                "passenger": ProtectedOutput("PERSON", C.CONFIDENTIAL, "booking_ref"),
                "contact": ProtectedOutput("EMAIL", C.CONFIDENTIAL, "booking_ref"),
                "status": PublicOutput(frozenset({"confirmed"})),
            },
        )
    )

    def search(args: Mapping[str, str]) -> object:
        return {"policy": sinks.search_send(f"{args['airline']} {args['topic']} baggage policy")}

    app.register_tool(
        ToolSpec(
            "search_baggage_policy",
            D.EXTERNAL_SEARCH,
            {
                "airline": ReferenceField("AIRLINE", frozenset({AIRLINE})),
                "topic": EnumField(TOPICS),
            },
            search,
            outputs={"policy": PublicOutput(frozenset({BAGGAGE}))},
        )
    )
    return app
