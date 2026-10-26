# MaskRoute — Codex instructions

Read `docs/PROJECT_DEFINITION.md` first (canonical product and security scope), then `docs/IMPLEMENTATION_SPEC.md` (proposed implementation and tests). If they conflict, defer to the canonical definition and note the conflict before implementing.

Task: build a small experimental Python SDK and a synthetic agent/tool vertical slice, **starting with a fair handwritten baseline**. Implement incrementally, run tests after each step, and document results; do not expand scope into a SaaS, enterprise DLP gateway, unrestricted browser/shell agent, full NER pipeline or compliance product.

Security requirements: explicit-vs-best-effort protection must be distinguished; policy and host authorization are trusted code; all model tool calls are untrusted; restore only permitted references into exact approved fields; protect tool returns; never log raw protected values. The SDK enforces only paths it actually mediates.

Use only fictional data in code/tests/docs. Keep a short README, clear architecture notes, stable reproducible tests and actual benchmark numbers. Do not claim perfect security or unique invention. Do not publish or push to a remote without explicit approval.

Start at step 1 of `docs/IMPLEMENTATION_SPEC.md` section 10. Report completed changes, test outcomes, limitations and next concrete step.
