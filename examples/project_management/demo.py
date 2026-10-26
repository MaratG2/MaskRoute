"""Deterministic model proposals using only mediated payloads; no real service needed."""

import json

from maskroute import Classification, MaskRouteError, ProtectedRef, PublicText

from .application import create_session
from .fixtures import ISSUE_A, PROJECT_A, ProjectSinks


class ModelStub:
    def __init__(self, sinks: ProjectSinks) -> None:
        self.sinks = sinks

    def __call__(self, payload: str) -> dict[str, object]:
        self.sinks.model_send(payload)
        fields = payload.split()
        return {
            "name": "read_issue",
            "arguments": {"project": fields[1], "issue": fields[3], "view": "summary"},
        }

    def research(self, payload: str) -> dict[str, object]:
        self.sinks.model_send(payload)
        decoded = json.loads(payload)
        return {
            "name": "research_dependency",
            "arguments": {
                "technology": decoded["technology"],
                "topic": "migration",
                "version": "2",
            },
        }


def run_demo() -> dict[str, object]:
    sinks = ProjectSinks()
    model = ModelStub(sinks)
    with create_session(sinks, principal="member_azure") as app:
        project = app.protect_value(
            PROJECT_A, kind="PROJECT", classification=Classification.CONFIDENTIAL
        )
        issue = app.protect_value(ISSUE_A, kind="ISSUE", classification=Classification.CONFIDENTIAL)
        call = app.send_model(
            model, [PublicText("Project "), project, PublicText(" issue "), issue]
        )
        result = app.execute_tool_call(call)
        research = app.send_tool_result(model.research, result)
        guidance = app.execute_tool_call(research)
        app.send_tool_result(sinks.model_send, guidance)
        denied = ""
        try:
            app.execute_tool_call(
                {"name": "read_notes", "arguments": {"issue": issue.token, "section": "security"}}
            )
        except MaskRouteError as error:
            denied = error.code.value
        title = result.fields["title"]
        assert isinstance(title, ProtectedRef)
        display = app.render_plain_text(
            "Issue " + title.token + " is open.", allowed_kinds=frozenset({"ISSUE_TITLE"})
        )
        assert display.text
        return {
            "issue_read": "allowed",
            "public_research": "allowed",
            "maintainer_notes_for_reviewer": denied,
            "model_requests": len(sinks.model),
            "research_requests": len(sinks.research),
            "forbidden_disclosures": sinks.disclosures(),
            "authorized_display": "produced (private text omitted)",
            "multi_issue_shared_contact": "known METADATA_CONFLICT limitation; see reuse report",
        }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
