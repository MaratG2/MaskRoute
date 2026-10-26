# Existing work and fair comparison

Reviewed on 26 October 2026. Upstream documentation is source evidence, not a security audit or an
instruction to change this project's scope. No competitor is claimed to be defeated by these tests.

## PIIGhost: measured integrated alternative

Installed **PIIGhost 2.1.1** as an optional comparison extra. Its public
[`ThreadAnonymizationPipeline` API](https://docs.piighost.dev/en/guide/getting-started/conversation/)
supports in-memory conversational masking, restoration, and explicit thread cleanup. The public
[`ExactMatchDetector` example](https://github.com/Athroniaeth/piighost/blob/master/README.md)
works without downloading a detector model. These APIs fit the local synthetic comparison.

`benchmarks/oss.py` uses those operations and `Anonymizer(LabelCounterPlaceholderFactory(...))`,
with a random per-session prefix through the factory's supported `prefix` parameter. This avoids
cross-session ordinal token collisions without misrepresenting them as an upstream vulnerability.
The same independent handwritten host checks provide schemas, issuance, kind/resource authorization,
fixed search and output handling. This is explicitly labeled **PIIGhost with host checks**, not a
claim that a masking primitive alone supplies application authorization. The adapter retains the
baseline's host metadata and therefore duplicates some mapping storage; the code count includes it.

The [upstream tool strategy documentation](https://docs.piighost.dev/en/guide/tool-call-strategies/)
describes broader middleware restoration behavior. We do not benchmark a deliberately permissive
default as if it were the only supported integration. Framework integrations, NER, persistent
storage and advanced guard rails are outside this small test. The local synchronous adapter uses
one asyncio Runner per session; its workflow latency includes runner creation and cleanup and is
not an intrinsic async performance comparison. It passes the same shared gate as MaskRoute.

## Documented exclusions

- [Privacy Guard](https://github.com/mehrantsi/privacy-guard) exposes reversible per-conversation
  operations through a Cloudflare Workers/Durable Objects/container service. Excluded from the
  local Python, no-running-service benchmark because comparable deployment/storage/network costs
  would need a separate experiment. This is not a finding of weaker security.
- [Hermes Privacy Gateway](https://github.com/saiteja-madha/hermes-privacy-gateway) is a Hermes Agent
  integration with model-input/tool-result protection and selected tool restoration. Excluded from
  numeric ranking because the specified vertical slice has no Hermes runtime or profile vault.
- Presidio, FIDES and Pipelock remain prior art named in the canonical definition. Their full APIs
  were not evaluated or ranked in this task. No feature-parity or superiority claim is made.

The current evidence favors a small handwritten boundary for this one application. Reuse across
distinct integrations would be required to justify MaskRoute as more than an engineering artifact.
