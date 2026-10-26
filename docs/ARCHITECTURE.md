# v0.1 architecture and decisions

The ZIP's `PROJECT_DEFINITION.md` is authoritative; `IMPLEMENTATION_SPEC.md` supplies the sequence
and acceptance cases. Earlier numbered documents are preserved as historical drafts. Scope conflicts
and milestone outcomes are recorded in `IMPLEMENTATION_LOG.md`.

## Boundary and ownership

Trusted host code authenticates a principal, provides immutable execution context, labels values,
registers tools/output fields, configures disclosure rules, and implements the authorizer. A model
only proposes a plain dictionary containing `name` and `arguments`. That dictionary cannot choose
the principal, destination, authorizer, policy, classifications, or resources.

`ProtectionSession` owns one in-memory `Registry` and one model conversation/execution. All operations
on that session must be serial. Independent sessions share no registry or issuance state. The host
must not reuse one session for different model conversations or users. The SDK is not a sandbox for
malicious Python code: its private attributes and callbacks live in the trusted host process.

The flow is: typed content → mediated model send → untrusted proposal → strict input schema →
reference scope/issuance/kind → exact tool/field/destination/classification permission → fresh host
authorization → exact argument restoration → handler → classified output filter → mediated result
send. Public search additionally requires a public classification, independently approved value,
host approval and finite topic; the trusted application constructs the query.

## Recorded implementation decisions

1. **Token syntax:** `[[KIND_<32 lowercase random hex digits>]]`. Each new entry uses
   `secrets.token_hex(16)` (128 bits). Hints carry no authority. Exact token strings only; no repairing
   changed formatting. Stable identity is exact `(value, kind, classification)` in one registry.
   Reusing that identity with conflicting resource metadata fails closed. Multiple aliases are not
   coreference-resolved. A revoked identity cannot be silently recreated during the same session.
2. **Issuance:** `send_model` / `send_tool_result` combine assembly and sending, replacing the
   specification's illustrative prepare-then-send method. Only the original registered typed object
   grants issuance, after a successful provider callback. Literal reserved syntax in `PublicText`
   is rejected; token-shaped strings do not issue references. A failed send may have reached the
   provider, but grants no new local issuance and is never retried automatically. Previously issued
   handles remain issued. The host adapter must represent one complete outbound send, not enqueue
   undelivered content and claim success. Streaming is not implemented.
3. **Schema engine:** small manual validators, no Pydantic or runtime dependencies. Inputs are flat
   strings, either exact reference fields or finite enums. Additional keys, arbitrary strings in
   reference slots, nested JSON, arrays, binary and unknown tools fail closed. Raw JSON strings are
   rejected; adapters must parse JSON strictly (including duplicate-key rejection) before submission.
4. **Disclosure policy:** a tuple of field rules, separate from the host authorizer. No policy DSL.
   The callback receives `(principal, action, resource, immutable context, destination, tool, field,
   kind)`. Only literal boolean `True` authorizes. Exceptions and elapsed-deadline violations deny.
   The synchronous deadline is checked after return and **cannot interrupt a hung callback**. The
   host must enforce I/O timeouts. Business tools still enforce consequential-action authorization.
5. **Public attestation:** demo airline output is classified public by host configuration, but search
   still checks its own exact airline allowlist. Public output text is a finite host-approved
   vocabulary (`confirmed` and the synthetic policy); arbitrary search-provider prose is unsupported
   in this vertical slice. `PUBLIC` alone never permits external reference restoration.
6. **Output handling:** an unknown/forbidden field rejects the entire result, including known fields.
   Missing required fields and non-string/nested/binary values also reject. The internal handler may
   already have executed; output rejection does not roll back business effects. Protected fields
   become unissued handles. Resource ownership for passenger/contact fields is inherited from the
   approved booking argument; an external tool cannot declare labels or authorization metadata.
7. **Display:** `render_plain_text` makes a separate `display` authorization call for each exact
   issued handle and requires a host-supplied kind allowlist. It returns `PlainTextResponse`, whose
   representation omits content. This is deliberately more conservative than general prose: URL,
   JSON, markup/code punctuation and `www.` syntax are rejected. The host must use a literal text
   surface (e.g. textContent), never HTML, Markdown, URL interpolation, auto-linking or a tool input.
   The method is not a general rich-text sanitizer. Undetected/inferred raw text is not made safe
   by this renderer; the explicit guarantee concerns restoration of registered references.
8. **Events and errors:** immutable snapshots of `ALLOW`, `DENY`, `RESTORE`, `PROTECT` with fixed reason
   codes, trusted schema identifiers and kinds. No values, mappings, principals or handles. There
   is no global logging hook. Error payloads from providers/tools/authorizers are discarded before
   raising constant SDK codes, without retaining an exception chain. Debuggers collecting locals,
   host tracebacks/logging outside this API, and malicious callback code are outside coverage.
9. **Detection:** optional case-sensitive exact dictionary plus email and phone-like regexes;
   deterministic dictionary-first, then earliest/longest overlap selection. Explicit spans reject
   overlap rather than guessing. Best-effort text remains tagged as such; unlabeled gaps and repeated
   occurrences can leave the process. No NER, alias detection, semantic minimization or certification.
10. **Packaging:** stdlib-only `src/` package with `py.typed`; examples/baselines/benchmarks stay in the
    checkout. Optional PIIGhost comparison is isolated from the core. No real provider adapter was
    needed to meet deterministic gates, so none was added. Existing repository MIT license retained;
    owner review precedes any publication. No changes were pushed.

## Limits and decision gate

Closing clears registry/tool references; Python memory is not securely zeroized, and callers can
retain raw input or authorized display strings. Reference names/number/relationships and public
search intent still reveal information. Encryption at rest, persistent vaults, concurrency within
a session, resource quotas, network confinement, unrestricted tools and hosted providers are out of
scope. These finite tests demonstrate tested behavior, not a formal information-flow proof.

The original travel baseline achieves the same shared enforcement with less total code. The second
project-management integration demonstrates configuration reuse, but a shared private contact on
two issue resources causes a legitimate `METADATA_CONFLICT` denial. The handwritten comparison
completes that task. The original identity contract remains unchanged; permissions were not widened
to hide this result. See `VALIDATION_REPORT.md` for the measured reuse gate and recommendation.

## Validation corrections (26 October 2026)

Independent review reproduced two host-integration defects. Frozen rule objects now defensively
snapshot nested enum/output/search vocabularies and policy collections. Mutating a collection that
was supplied during construction cannot silently change the registered rules. Strictly typed
immutable inputs already had this behavior; the fix also handles mutable runtime inputs.

All reference/lifecycle checks now run again after authorization callbacks and immediately before
handler effects or final display return. A later callback that closes the session or revokes an
earlier reference prevents the whole pending disclosure. Callbacks should not reenter session
operations; these defensive checks do not provide concurrency safety or undo effects performed
inside trusted callbacks. No new API, detector, policy language, or registry identity was introduced.

`INDEPENDENT_REVIEW.md` preserves the original reproductions and independently verified fixes.
The original travel benchmark is a historical pre-fix measurement; its fingerprint is not the
current validation source. Current reuse results and their source metrics are recorded separately.
