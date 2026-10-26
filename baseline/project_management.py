"""Independent handwritten second application. No MaskRoute or travel-baseline imports."""

import json
import secrets
from collections.abc import Callable, Mapping
from contextlib import suppress

from examples.project_management.fixtures import (
    OTHER_TECH,
    RESEARCH,
    SECTIONS,
    TECH,
    TOPICS,
    VERSIONS,
    VIEWS,
    ProjectSinks,
    host_authorize,
)

Authorizer = Callable[[str, str, str, str, Mapping[str, str]], bool]


class ProjectDenied(Exception):
    def __init__(self) -> None:
        super().__init__("DENIED")


class HandwrittenProjects:
    def __init__(
        self,
        sinks: ProjectSinks,
        *,
        principal: str,
        project: str,
        authorizer: Authorizer = host_authorize,
    ) -> None:
        if not callable(authorizer):
            raise ProjectDenied()
        self.sinks = sinks
        self.principal = principal
        self.context = {"active_project": project}
        self.authorizer = authorizer
        self.values: dict[str, tuple[str, str, str]] = {}
        self.issued: set[str] = set()
        self.closed = False
        self.results: dict[int, dict[str, str]] = {}

    def protect(self, value: str, kind: str, resource: str | None = None) -> str:
        if self.closed:
            raise ProjectDenied()
        metadata = (value, kind, value if resource is None else resource)
        for handle, existing in self.values.items():
            if existing == metadata:
                return handle
        handle = f"[[{kind}_{secrets.token_hex(16)}]]"
        self.values[handle] = metadata
        return handle

    def send(self, handles: list[str]) -> str:
        if self.closed or any(handle not in self.values for handle in handles):
            raise ProjectDenied()
        payload = json.dumps(handles)
        succeeded = False
        with suppress(Exception):
            self.sinks.model_send(payload)
            succeeded = True
        if not succeeded:
            raise ProjectDenied()
        self.issued.update(handles)
        return payload

    def resolve(self, handle: str, kind: str, action: str) -> str:
        if self.closed or handle not in self.issued or handle not in self.values:
            raise ProjectDenied()
        value, actual_kind, resource = self.values[handle]
        if actual_kind != kind:
            raise ProjectDenied()
        allowed = False
        with suppress(Exception):
            allowed = self.authorizer(self.principal, action, resource, kind, self.context) is True
        if not allowed:
            raise ProjectDenied()
        return value

    def call(self, proposal: object) -> dict[str, str]:
        if self.closed or type(proposal) is not dict or set(proposal) != {"name", "arguments"}:
            raise ProjectDenied()
        name, args = proposal["name"], proposal["arguments"]
        if type(name) is not str or type(args) is not dict:
            raise ProjectDenied()
        if any(type(k) is not str or type(v) is not str for k, v in args.items()):
            raise ProjectDenied()
        raw: dict[str, str]
        output: object = None
        resources: dict[str, tuple[str, str]] = {}
        if name == "read_issue" and set(args) == {"project", "issue", "view"}:
            if args["view"] not in VIEWS:
                raise ProjectDenied()
            raw = {
                "project": self.resolve(args["project"], "PROJECT", name),
                "issue": self.resolve(args["issue"], "ISSUE", name),
                "view": args["view"],
            }
            with suppress(Exception):
                output = self.sinks.read_issue(raw)
            expected = {"title", "owner", "technology", "state"}
            resources = {
                "title": ("ISSUE_TITLE", raw["issue"]),
                "owner": ("EMAIL", raw["issue"]),
                "technology": ("TECHNOLOGY", TECH),
            }
        elif name == "read_notes" and set(args) == {"issue", "section"}:
            if args["section"] not in SECTIONS:
                raise ProjectDenied()
            raw = {"issue": self.resolve(args["issue"], "ISSUE", name), "section": args["section"]}
            with suppress(Exception):
                output = self.sinks.read_notes(raw)
            expected = {"note"}
            resources = {"note": ("ISSUE_NOTE", raw["issue"])}
        elif name == "research_dependency" and set(args) == {"technology", "topic", "version"}:
            if args["topic"] not in TOPICS or args["version"] not in VERSIONS:
                raise ProjectDenied()
            technology = self.resolve(args["technology"], "TECHNOLOGY", name)
            if technology not in {TECH, OTHER_TECH}:
                raise ProjectDenied()
            with suppress(Exception):
                output = self.sinks.research_send(
                    f"{technology} version {args['version']} {args['topic']} public documentation"
                )
            expected = {"guidance"}
        else:
            raise ProjectDenied()
        if type(output) is not dict or set(output) != expected:
            raise ProjectDenied()
        if any(type(v) is not str or not v for v in output.values()):
            raise ProjectDenied()
        if "state" in output and output["state"] != "open":
            raise ProjectDenied()
        if "guidance" in output and output["guidance"] != RESEARCH:
            raise ProjectDenied()
        result: dict[str, str] = {}
        for key, value in output.items():
            if key in resources:
                kind, resource = resources[key]
                result[key] = self.protect(value, kind, value if key == "technology" else resource)
            else:
                result[key] = value
        self.results[id(result)] = dict(result)
        return result

    def send_result(self, result: dict[str, str]) -> None:
        if self.closed or self.results.pop(id(result), None) != result:
            raise ProjectDenied()
        succeeded = False
        with suppress(Exception):
            self.sinks.model_send(json.dumps(result, sort_keys=True))
            succeeded = True
        if not succeeded:
            raise ProjectDenied()
        self.issued.update(value for value in result.values() if value in self.values)

    def close(self) -> None:
        self.closed = True
        self.values.clear()
        self.issued.clear()
        self.results.clear()
