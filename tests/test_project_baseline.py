import pytest

from baseline.project_management import HandwrittenProjects, ProjectDenied
from examples.project_management.fixtures import (
    ISSUE_A,
    ISSUE_A2,
    ISSUE_B,
    PROJECT_A,
    TECH,
    ProjectSinks,
)


def request(name: str, **arguments: str) -> dict[str, object]:
    return {"name": name, "arguments": arguments}


def test_handwritten_project_workflow_and_multi_issue_identity() -> None:
    sinks = ProjectSinks()
    app = HandwrittenProjects(sinks, principal="member_amber", project=PROJECT_A)
    project = app.protect(PROJECT_A, "PROJECT")
    issue = app.protect(ISSUE_A, "ISSUE")
    issue2 = app.protect(ISSUE_A2, "ISSUE")
    app.send([project, issue, issue2])
    first = app.call(request("read_issue", project=project, issue=issue, view="summary"))
    app.send_result(first)
    second = app.call(request("read_issue", project=project, issue=issue2, view="triage"))
    app.send_result(second)
    assert first["owner"] != second["owner"]  # Same value, different issue authorization.
    notes = app.call(request("read_notes", issue=issue, section="engineering"))
    app.send_result(notes)
    research = app.call(
        request(
            "research_dependency", technology=first["technology"], topic="migration", version="2"
        )
    )
    app.send_result(research)
    assert sinks.internal[0][1] == {"project": PROJECT_A, "issue": ISSUE_A, "view": "summary"}
    assert sinks.research == [f"{TECH} version 2 migration public documentation"]
    assert sinks.disclosures() == 0
    app.close()


@pytest.mark.parametrize(
    "attack",
    [
        "cross_project",
        "notes_role",
        "unissued",
        "nested",
        "extra",
        "private_research",
        "unknown_output",
        "nested_output",
        "closed",
    ],
)
def test_handwritten_project_denials(attack: str) -> None:
    sinks = ProjectSinks(hostile=attack)
    app = HandwrittenProjects(
        sinks,
        principal="member_azure" if attack == "notes_role" else "member_amber",
        project=PROJECT_A,
    )
    project = app.protect(PROJECT_A, "PROJECT")
    issue = app.protect(ISSUE_B if attack == "cross_project" else ISSUE_A, "ISSUE")
    app.send([project] if attack == "unissued" else [project, issue])
    proposal: object = request("read_issue", project=project, issue=issue, view="summary")
    if attack == "notes_role":
        proposal = request("read_notes", issue=issue, section="engineering")
    elif attack == "nested":
        proposal = {
            "name": "read_issue",
            "arguments": {"project": project, "issue": {"x": issue}, "view": "summary"},
        }
    elif attack == "extra":
        proposal = request(
            "read_issue", project=project, issue=issue, view="summary", role="maintainer"
        )
    elif attack == "private_research":
        proposal = request("research_dependency", technology=issue, topic="migration", version="1")
    elif attack == "closed":
        app.close()
    with pytest.raises(ProjectDenied):
        result = app.call(proposal)
        app.send_result(result)
    assert sinks.research == []
    assert len(sinks.internal) == (1 if attack in {"unknown_output", "nested_output"} else 0)
    assert sinks.disclosures() == 0
    app.close()
