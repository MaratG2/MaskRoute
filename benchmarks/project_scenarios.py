"""One frozen project task/attack harness for the SDK and independent manual boundary."""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Protocol

from baseline.project_management import HandwrittenProjects, ProjectDenied
from examples.project_management.application import create_session
from examples.project_management.fixtures import (
    ISSUE_A,
    ISSUE_A2,
    ISSUE_B,
    PROJECT_A,
    PROJECT_B,
    RESEARCH,
    TECH,
    ProjectSinks,
)
from maskroute import Classification, MaskRouteError, ProtectedRef, ProtectedResult


def request(name: str, **arguments: str) -> dict[str, object]:
    return {"name": name, "arguments": arguments}


class Workflow(Protocol):
    def protect(self, value: str, kind: str, resource: str | None = None) -> str: ...
    def send(self, handles: list[str]) -> str: ...
    def call(self, proposal: object) -> dict[str, str]: ...
    def send_result(self, result: dict[str, str]) -> None: ...
    def close(self) -> None: ...


class MaskRouteProjects:
    def __init__(self, sinks: ProjectSinks, principal: str, project: str) -> None:
        self.sinks = sinks
        self.session = create_session(sinks, principal=principal, project=project)
        self.refs: dict[str, ProtectedRef] = {}
        self.results: dict[int, ProtectedResult] = {}

    def protect(self, value: str, kind: str, resource: str | None = None) -> str:
        ref = self.session.protect_value(
            value,
            kind=kind,
            resource=resource,
            classification=Classification.PUBLIC
            if kind == "TECHNOLOGY"
            else Classification.CONFIDENTIAL,
        )
        self.refs[ref.token] = ref
        return ref.token

    def send(self, handles: list[str]) -> str:
        return self.session.send_model(
            self.sinks.model_send, [self.refs[handle] for handle in handles]
        )

    def call(self, proposal: object) -> dict[str, str]:
        result = self.session.execute_tool_call(proposal)
        visible = {
            key: value.token if isinstance(value, ProtectedRef) else value.text
            for key, value in result.fields.items()
        }
        self.results[id(visible)] = result
        return visible

    def send_result(self, result: dict[str, str]) -> None:
        self.session.send_tool_result(self.sinks.model_send, self.results.pop(id(result)))

    def close(self) -> None:
        self.session.close()
        self.refs.clear()
        self.results.clear()


Factory = Callable[[ProjectSinks, str, str], Workflow]
FACTORIES: dict[str, Factory] = {
    "handwritten": lambda sinks, principal, project: HandwrittenProjects(
        sinks, principal=principal, project=project
    ),
    "maskroute": MaskRouteProjects,
}
VALID = ("reviewer_research", "maintainer_notes", "second_project", "multi_issue_shared_contact")
ATTACKS = (
    "unissued",
    "cross_scope",
    "cross_project_pair",
    "issue_acl",
    "notes_role",
    "wrong_kind",
    "modified",
    "closed",
    "unknown_tool",
    "extra_identity",
    "nested",
    "private_research",
    "free_query",
    "url",
    "topic",
    "version",
    "unknown_output",
    "nested_output",
    "injected_output",
)


@dataclass(frozen=True)
class Trial:
    scenario: str
    valid: bool
    succeeded: bool
    denied: bool
    error_code: str
    disclosures: int
    model_requests: int
    internal_calls: int
    research_calls: int
    rejected_before_forbidden_effect: bool


def legitimate(app: Workflow, sinks: ProjectSinks, scenario: str, project: str, issue: str) -> bool:
    project_ref, issue_ref = app.protect(project, "PROJECT"), app.protect(issue, "ISSUE")
    app.send([project_ref, issue_ref])
    first = app.call(request("read_issue", project=project_ref, issue=issue_ref, view="summary"))
    app.send_result(first)
    if scenario == "multi_issue_shared_contact":
        other = app.protect(ISSUE_A2, "ISSUE")
        app.send([other])
        result = app.call(request("read_issue", project=project_ref, issue=other, view="triage"))
        app.send_result(result)
    elif scenario == "maintainer_notes":
        notes = app.call(request("read_notes", issue=issue_ref, section="security"))
        app.send_result(notes)
    result = app.call(
        request(
            "research_dependency", technology=first["technology"], topic="migration", version="2"
        )
    )
    app.send_result(result)
    expected = [("read_issue", {"project": project, "issue": issue, "view": "summary"})]
    if scenario == "multi_issue_shared_contact":
        expected.append(("read_issue", {"project": project, "issue": ISSUE_A2, "view": "triage"}))
    elif scenario == "maintainer_notes":
        expected.append(("read_notes", {"issue": issue, "section": "security"}))
    return (
        sinks.internal == expected
        and result["guidance"] == RESEARCH
        and sinks.research == [f"{TECH} version 2 migration public documentation"]
    )


def hostile(app: Workflow, scenario: str, factory: Factory) -> None:
    project = app.protect(PROJECT_A, "PROJECT")
    raw_issue = (
        ISSUE_B
        if scenario == "cross_project_pair"
        else ISSUE_A2
        if scenario == "issue_acl"
        else ISSUE_A
    )
    issue = app.protect(raw_issue, "EMAIL" if scenario == "wrong_kind" else "ISSUE")
    app.send([project] if scenario == "unissued" else [project, issue])
    if scenario == "cross_scope":
        other = factory(ProjectSinks(), "member_amber", PROJECT_A)
        try:
            issue = other.protect(ISSUE_A, "ISSUE")
            other.send([issue])
        finally:
            other.close()
    elif scenario == "modified":
        issue += "x"
    elif scenario == "closed":
        app.close()
    proposal: object = request("read_issue", project=project, issue=issue, view="summary")
    if scenario == "notes_role":
        proposal = request("read_notes", issue=issue, section="engineering")
    elif scenario == "unknown_tool":
        proposal = request("dump_registry")
    elif scenario == "extra_identity":
        proposal = request(
            "read_issue", project=project, issue=issue, view="summary", role="maintainer"
        )
    elif scenario == "nested":
        proposal = {
            "name": "read_issue",
            "arguments": {"project": project, "issue": [issue], "view": "summary"},
        }
    elif scenario in {"private_research", "free_query", "url", "topic", "version"}:
        technology = app.protect(TECH, "TECHNOLOGY")
        app.send([technology])
        args = {"technology": technology, "topic": "migration", "version": "2"}
        if scenario == "private_research":
            args["technology"] = issue
        elif scenario == "free_query":
            args["query"] = issue
        elif scenario == "url":
            args["technology"] = "https://example.invalid/" + issue
        elif scenario == "topic":
            args["topic"] = issue
        else:
            args["version"] = issue
        proposal = {"name": "research_dependency", "arguments": args}
    result = app.call(proposal)
    app.send_result(result)
    if scenario == "injected_output":
        app.call(request("dump_registry"))


def trial(factory: Factory, scenario: str, *, valid: bool) -> Trial:
    sinks = ProjectSinks(hostile="" if valid else scenario)
    principal = (
        "member_azure"
        if scenario in {"reviewer_research", "notes_role", "issue_acl"}
        else "member_amber"
    )
    project, issue = (PROJECT_B, ISSUE_B) if scenario == "second_project" else (PROJECT_A, ISSUE_A)
    app = factory(sinks, principal, project)
    succeeded = denied = False
    error = ""
    try:
        if valid:
            succeeded = legitimate(app, sinks, scenario, project, issue)
        else:
            hostile(app, scenario, factory)
    except (ProjectDenied, MaskRouteError) as exc:
        denied = True
        error = exc.code.value if isinstance(exc, MaskRouteError) else "DENIED"
    finally:
        app.close()
    permitted_reads = 1 if scenario in {"unknown_output", "nested_output", "injected_output"} else 0
    rejected = denied and not sinks.research and len(sinks.internal) <= permitted_reads
    return Trial(
        scenario,
        valid,
        succeeded,
        denied,
        error,
        sinks.disclosures(),
        len(sinks.model),
        len(sinks.internal),
        len(sinks.research),
        rejected if not valid else False,
    )


def evaluate(factory: Factory) -> dict[str, object]:
    allowed = [trial(factory, case, valid=True) for case in VALID]
    attacks = [trial(factory, case, valid=False) for case in ATTACKS]
    return {
        "legitimate_task_success": sum(t.succeeded for t in allowed),
        "legitimate_tasks": len(allowed),
        "false_denials": sum(t.denied for t in allowed),
        "forbidden_sink_disclosures": sum(t.disclosures for t in allowed + attacks),
        "forbidden_paths_rejected": sum(t.rejected_before_forbidden_effect for t in attacks),
        "forbidden_paths": len(attacks),
        "trials": [asdict(t) for t in allowed + attacks],
    }
