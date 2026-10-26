"""Regression reproductions for independently reviewed host-integration defects."""

from collections.abc import Mapping
from typing import cast

import pytest

from maskroute import (
    AuthorizationRequest,
    Code,
    DisclosurePolicy,
    DisclosureRule,
    EnumField,
    MaskRouteError,
    ProtectedRef,
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


@pytest.mark.parametrize(
    "mutation", ["enum", "output", "external_allowlist", "policy_rules", "policy_classifications"]
)
def test_registered_configuration_snapshots_collections(mutation: str) -> None:
    terms = {"approved"}
    public_values = {"approved"}
    classes = {C.PUBLIC}
    rule = DisclosureRule(
        "send", "reference", "TERM", D.EXTERNAL_SEARCH, cast(frozenset[C], classes)
    )
    rules = [rule]
    policy = DisclosurePolicy(cast(tuple[DisclosureRule, ...], rules))
    sink: list[Mapping[str, str]] = []
    model: list[str] = []
    app = ProtectionSession(
        principal="fixture_member", authorizer=lambda request: True, policy=policy
    )
    value = (
        "newly_added"
        if mutation in {"external_allowlist", "policy_classifications"}
        else "approved"
    )
    ref = app.protect_value(
        value,
        kind="TERM",
        classification=C.CONFIDENTIAL if mutation == "policy_classifications" else C.PUBLIC,
    )
    app.send_model(model.append, [ref])

    def handler(args: Mapping[str, str]) -> object:
        sink.append(dict(args))
        return {"status": "newly_added" if mutation == "output" else "approved"}

    enum = EnumField(cast(frozenset[str], terms))
    output = PublicOutput(cast(frozenset[str], terms))
    reference = ReferenceField("TERM", cast(frozenset[str], public_values))
    app.register_tool(
        ToolSpec(
            "send",
            D.EXTERNAL_SEARCH,
            {"reference": reference, "choice": enum},
            handler,
            {"status": output},
        )
    )
    terms.add("newly_added")
    public_values.add("newly_added")
    classes.add(C.CONFIDENTIAL)
    rules.clear()
    assert enum.choices == frozenset({"approved"})
    assert output.allowed_values == frozenset({"approved"})
    assert reference.public_values == frozenset({"approved"})
    assert rule.classifications == frozenset({C.PUBLIC})
    assert policy.rules == (rule,)
    if mutation == "policy_rules":
        result = app.execute_tool_call(
            {"name": "send", "arguments": {"reference": ref.token, "choice": "approved"}}
        )
        app.send_tool_result(model.append, result)
        assert len(sink) == 1
    else:
        with pytest.raises(MaskRouteError):
            result = app.execute_tool_call(
                {
                    "name": "send",
                    "arguments": {
                        "reference": ref.token,
                        "choice": "newly_added" if mutation == "enum" else "approved",
                    },
                }
            )
            app.send_tool_result(model.append, result)
        assert len(sink) == (1 if mutation == "output" else 0)
        assert len(model) == 1


@pytest.mark.parametrize("operation", ["tool", "display"])
@pytest.mark.parametrize("change", ["close", "revoke_first", "revoke_last"])
def test_lifecycle_change_during_later_authorization_denies_before_effect(
    operation: str, change: str
) -> None:
    captured: list[dict[str, str]] = []
    first: ProtectedRef
    last: ProtectedRef

    def authorize(request: AuthorizationRequest) -> bool:
        if request.resource == "fixture_second_resource":
            if change == "close":
                app.close()
            else:
                app.revoke(first if change == "revoke_first" else last)
        return True

    policy = DisclosurePolicy(
        tuple(
            DisclosureRule("use_pair", field, "ITEM", D.INTERNAL_TOOL, frozenset({C.CONFIDENTIAL}))
            for field in ("first", "last")
        )
    )
    app = ProtectionSession(principal="fixture_member", authorizer=authorize, policy=policy)
    first = app.protect_value(
        "fixture_first_private",
        kind="ITEM",
        classification=C.CONFIDENTIAL,
        resource="fixture_first_resource",
    )
    last = app.protect_value(
        "fixture_second_private",
        kind="ITEM",
        classification=C.CONFIDENTIAL,
        resource="fixture_second_resource",
    )

    def handler(args: Mapping[str, str]) -> object:
        captured.append(dict(args))
        return {}

    app.register_tool(
        ToolSpec(
            "use_pair",
            D.INTERNAL_TOOL,
            {"first": ReferenceField("ITEM"), "last": ReferenceField("ITEM")},
            handler,
        )
    )
    app.send_model(lambda payload: None, [first, last])
    with pytest.raises(MaskRouteError) as error:
        if operation == "tool":
            app.execute_tool_call(
                {"name": "use_pair", "arguments": {"first": first.token, "last": last.token}}
            )
        else:
            app.render_plain_text(
                first.token + " and " + last.token, allowed_kinds=frozenset({"ITEM"})
            )
    assert error.value.code in {Code.SESSION_CLOSED, Code.REVOKED_REFERENCE}
    assert captured == []
