import pytest

from benchmarks.project_scenarios import ATTACKS, FACTORIES, VALID, trial
from maskroute import MaskRouteError


@pytest.mark.parametrize(
    ("implementation", "scenario"),
    [
        pytest.param(
            implementation,
            scenario,
            marks=pytest.mark.xfail(
                strict=True,
                reason="Frozen SDK cannot bind one private value/kind to two issue resources",
            ),
        )
        if implementation == "maskroute" and scenario == "multi_issue_shared_contact"
        else pytest.param(implementation, scenario)
        for implementation in FACTORIES
        for scenario in VALID
    ],
)
def test_project_allowed_tasks(implementation: str, scenario: str) -> None:
    result = trial(FACTORIES[implementation], scenario, valid=True)
    assert result.succeeded
    assert not result.denied
    assert result.disclosures == 0


def test_known_reuse_denial_is_private_and_has_expected_cause() -> None:
    result = trial(FACTORIES["maskroute"], "multi_issue_shared_contact", valid=True)
    assert result.error_code == "METADATA_CONFLICT"
    assert result.denied
    assert result.disclosures == 0
    assert result.research_calls == 0


def test_project_demo() -> None:
    from examples.project_management.demo import run_demo

    report = run_demo()
    assert report["issue_read"] == report["public_research"] == "allowed"
    assert report["maintainer_notes_for_reviewer"] == "UNAUTHORIZED"
    assert report["forbidden_disclosures"] == 0


@pytest.mark.parametrize("implementation", list(FACTORIES))
@pytest.mark.parametrize("scenario", ATTACKS)
def test_project_forbidden_paths(implementation: str, scenario: str) -> None:
    result = trial(FACTORIES[implementation], scenario, valid=False)
    assert result.denied
    assert result.rejected_before_forbidden_effect
    assert result.disclosures == 0


def test_project_source_is_issue_authorization_not_raw_display_permission() -> None:
    from examples.project_management.application import create_session
    from examples.project_management.fixtures import ISSUE_A, PROJECT_A, ProjectSinks
    from maskroute import Classification, ProtectedRef

    sinks = ProjectSinks()
    with create_session(sinks, principal="member_azure") as app:
        project = app.protect_value(
            PROJECT_A, kind="PROJECT", classification=Classification.CONFIDENTIAL
        )
        issue = app.protect_value(ISSUE_A, kind="ISSUE", classification=Classification.CONFIDENTIAL)
        app.send_model(sinks.model_send, [project, issue])
        result = app.execute_tool_call(
            {
                "name": "read_issue",
                "arguments": {"project": project.token, "issue": issue.token, "view": "summary"},
            }
        )
        app.send_tool_result(sinks.model_send, result)
        title = result.fields["title"]
        assert isinstance(title, ProtectedRef)
        displayed = app.render_plain_text(title.token, allowed_kinds=frozenset({"ISSUE_TITLE"}))
        assert displayed.text
        with pytest.raises(MaskRouteError):
            app.execute_tool_call(
                {"name": "read_notes", "arguments": {"issue": issue.token, "section": "security"}}
            )
        assert len(sinks.internal) == 1
        assert sinks.disclosures() == 0
