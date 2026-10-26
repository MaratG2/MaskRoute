"""Project host wiring through existing public SDK APIs; no SDK customization."""

from collections.abc import Mapping

from maskroute import (
    AuthorizationRequest,
    Classification,
    Destination,
    DisclosurePolicy,
    DisclosureRule,
    EnumField,
    ProtectedOutput,
    ProtectionSession,
    PublicOutput,
    ReferenceField,
    ToolSpec,
)

from .fixtures import (
    OTHER_TECH,
    PROJECT_A,
    RESEARCH,
    SECTIONS,
    TECH,
    TOPICS,
    VERSIONS,
    VIEWS,
    ProjectSinks,
    host_authorize,
)


def authorize(request: AuthorizationRequest) -> bool:
    return host_authorize(
        request.principal, request.action, request.resource, request.kind, request.context
    )


def create_session(
    sinks: ProjectSinks, *, principal: str = "member_amber", project: str = PROJECT_A
) -> ProtectionSession:
    internal = Destination.INTERNAL_TOOL
    external = Destination.EXTERNAL_SEARCH
    private = frozenset({Classification.CONFIDENTIAL})
    app = ProtectionSession(
        principal=principal,
        context={"active_project": project},
        authorizer=authorize,
        policy=DisclosurePolicy(
            (
                DisclosureRule("read_issue", "project", "PROJECT", internal, private),
                DisclosureRule("read_issue", "issue", "ISSUE", internal, private),
                DisclosureRule("read_notes", "issue", "ISSUE", internal, private),
                DisclosureRule(
                    "research_dependency",
                    "technology",
                    "TECHNOLOGY",
                    external,
                    frozenset({Classification.PUBLIC}),
                ),
            )
        ),
    )
    app.register_tool(
        ToolSpec(
            "read_issue",
            internal,
            {
                "project": ReferenceField("PROJECT"),
                "issue": ReferenceField("ISSUE"),
                "view": EnumField(VIEWS),
            },
            sinks.read_issue,
            {
                "title": ProtectedOutput("ISSUE_TITLE", Classification.CONFIDENTIAL, "issue"),
                "owner": ProtectedOutput("EMAIL", Classification.CONFIDENTIAL, "issue"),
                "technology": ProtectedOutput("TECHNOLOGY", Classification.PUBLIC),
                "state": PublicOutput(frozenset({"open"})),
            },
        )
    )
    app.register_tool(
        ToolSpec(
            "read_notes",
            internal,
            {"issue": ReferenceField("ISSUE"), "section": EnumField(SECTIONS)},
            sinks.read_notes,
            {"note": ProtectedOutput("ISSUE_NOTE", Classification.RESTRICTED, "issue")},
        )
    )

    def research(args: Mapping[str, str]) -> object:
        return sinks.research_send(
            f"{args['technology']} version {args['version']} {args['topic']} public documentation"
        )

    app.register_tool(
        ToolSpec(
            "research_dependency",
            external,
            {
                "technology": ReferenceField("TECHNOLOGY", frozenset({TECH, OTHER_TECH})),
                "topic": EnumField(TOPICS),
                "version": EnumField(VERSIONS),
            },
            research,
            {"guidance": PublicOutput(frozenset({RESEARCH}))},
        )
    )
    return app
