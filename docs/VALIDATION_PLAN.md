# Second validation milestone

Requested 26 October 2026: freeze new SDK features, validate hosted CI, obtain independent review,
and test reuse through a synthetic project-management assistant and handwritten comparison.
The new user request extends the original one-integration experiment; it does not authorize a
SaaS, new detectors, generic tools, production claims or publication.

## Frozen experiment

Use three operations: `read_issue(project, issue, view)`, `read_notes(issue, section)`, and
`research_dependency(technology, topic, version)`. Trusted host membership/issue ACLs bind resources
to an active project. Maintainers can read private notes; reviewers cannot. The model gets no
identity/context override. Research accepts only approved fictional public technologies and
fixed topics/versions. Outputs contain private issue titles, contact fields and restricted notes.

Both implementations share domain fixtures and host authorization, but not reference/gateway code.
Build and test the handwritten implementation first. Wire the same SDK using only public APIs;
record every SDK source change separately and permit only fixes to demonstrated contract defects.
Compare actual sink payloads, successful tasks, false denials, roundtrip behavior, app-side line
counts and observable policy complexity. Timing is descriptive; do not optimize it.

Include a legitimate multi-issue workflow where the same private contact occurs on two authorized
issues in one session. Keep issue-specific authorization: do not broaden it to project-wide display
merely to make reference reuse easier. If the frozen SDK cannot express this, report the limitation
and count the false denial instead of removing the scenario.

Independent AI reviewers own a contract-first attack suite and an implementation review. They are
separate from this integration's author, but are not external human auditors or certification.

## Hosted CI and publication boundary

The existing GitHub repository is public and currently contains no CI workflow. Local SSH access
failed, but the connected GitHub app can access the repository. Running new hosted jobs requires
uploading the implementation/workflow. AGENTS.md says: "Do not publish or push to a remote without
explicit approval." Prepare a concrete, tested branch/file manifest first and request that approval
before remote writes. A CI run request is not treated as approval to publish all currently local code.

Recommend an experimental SDK or an engineering case study based on evidence; do not publish either
without the user's explicit approval. Report six milestone statuses separately, including blockers.
