# R04 Evidence-constrained capability chains

Route goal: combine already-validated local behaviors into routes that have prerequisites and evidence and can really advance, and validate missing connecting conditions first. This route is a late combination trial and uses the [shared experiment protocol](shared-experiment-protocol-and-evaluation.md).

## Derived from penetration-testing logic

Whether a local finding has value depends on what capability it gives which subject over which resource, and whether it can satisfy the next step's prerequisites. A single phenomenon may have limited impact; combined, it comes closer to the task goal.

But a path on the graph does not mean it can actually be walked. A successful upload does not prove the file is accessible, let alone executable; two services using the same technology does not prove they share an authentication domain; reading one controlled object does not prove all objects can be read.

So the unit of combination should be a proven behavior with explicit conditions. Before connecting, check subject, object, state, authorization and time conditions, and generate validation tasks only for necessary conditions not yet met, so the model cannot fill gaps with natural language and call them facts.

## What the original design already has, and what is added

The existing exploration graph already supports deriving intents from several facts, and the Planner already dispatches exploit chains serially. These mechanisms are in [`internal/agent/tools.go`](../../internal/agent/tools.go) and [`internal/agent/planner.go`](../../internal/agent/planner.go).

This route's increment is a scope-constrained capability representation for key facts, a small set of checkable combination prerequisites, and compatibility validation before plans are generated. Drawing one more attack graph or adding chain prompts does not count as done.

After review it is an M4 late capability: common observations, verifiable predicates and the plan-reference foundation come first, then version-by-version validation. The original Planner still dispatches gap experiments; researching capability chains is no reason to develop a standalone search controller early.

## Capability representation and combination constraints

| Content | Constraint |
| --- | --- |
| Subject | The actual executing subject and authentication domain; the same role name is not automatically the same subject |
| Action and effect | Distinguish different facts such as a request being accepted, an object being readable and a state being modifiable |
| Resource scope | Bound to specific objects or an evidence-backed set; never extrapolated from one instance to everything |
| Holding conditions | Identity, object, business state, dependencies and known environment conditions |
| Source evidence | Points to valid experiments and checkable assertions; a model's candidate description is never promoted to a proven capability directly |
| Applicable version | When it was validated, and which changes require re-checking |

Combination rules are first limited to a few observable object operations. Several prerequisites must hold together and connect in actual execution order; an earlier step may change state and invalidate an old capability, so label matching on a static graph is not enough.

Object identifiers across services must have a reliable mapping; a credential's audience, permissions and tenant conditions must also be checked. Company ownership, the same IP, similar path names or using the same framework can never replace this evidence.

## Route generation and advancement

1. Register assertion-checked facts as scope-constrained capabilities, keeping the raw evidence and uncertainty.
2. Work backwards from a concrete goal to a few explicit prerequisites, match them against proven capabilities and list the gaps.
3. Known incompatible combinations are not dispatched; when a key condition is unknown, generate a task to validate that condition without claiming the chain holds.
4. Advance compatible candidates step by step through the existing intent scheduling, re-checking later conditions after every step's output.
5. New counter-evidence or context changes enter review; historical routes are kept and invalidated prerequisites are not reused.

For example, if controlled service A issues a read-only sharing credential for a test document and service B accepts that credential to modify the same document, you must prove the credential can be obtained, the resource mapping is consistent, the credential really is read-only, and B produced a real write. Knowing only that A and B both have a document with the same name or both use some token cannot form this chain.

Goal priority can help choose gaps, but there is no need to introduce fictional success probabilities first. V1/V2 rank by goal relevance, number of missing prerequisites, known validation cost and constraints, and keep the Planner's ability to propose other open directions.

## Minimal implementation and integration

V1 has a human review a small number of capability records, limited to semantics such as subject, object reads and state modification, without automatically turning every vulnerability name into an execution capability. The combiner only outputs compatible, incompatible, or which prerequisites are missing.

V2 plugs into the existing intent tools to validate one gap; source records can come from routes such as R02/R03 or be confirmed manually from an independent valid experiment. Compatibility checks follow the shared protocol and need not wait for every route to be integrated.

Hooks into the existing graph storage in [`internal/db/exploration.go`](../../internal/db/exploration.go) and the dispatch path in [`internal/agent/tools.go`](../../internal/agent/tools.go), storing capabilities and source references without building another authoritative fact store. Cross-target actions must still be checked one by one against the user's authorized scope; a knowledge link is not execution permission.

R05's common checks and baselines are reused, and combination rules are also registered and validated one by one as machine predicates. After referenced context changes, the dispatch and claim gates re-check; write-back and goal completion use the common rules. Logs and reports distinguish validated edges, unknown connections and rejected combinations, and never write the existence of a path up as realized impact.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R04-V1 | Manually proven capabilities, a few combination rules, subject/object and state compatibility checks | Offline counterexamples of executable and fictional combinations; suggestions only |
| R04-V2 | Dispatch a validation task for a single missing prerequisite and replan after execution | One real executable chain, blocking behavior when prerequisites are insufficient, full validation cost |
| R04-V3 | Multi-fact combination, incremental revision after evidence changes, bounded-depth route comparison | Control evaluation against free planning and with the combiner off, chain-failure review and rollback |

Extracting capabilities automatically from natural language can generate candidates, but a proven label must pass the corresponding assertion. Capabilities not covered by rules stay ordinary facts for the Planner to explore freely, and are not forced into types.

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R04-A | Two authorized test services, the same controlled object, a legitimate read-only credential wrongly gaining write effect on the second service | Object and permission connections are validated one by one and the chain is confirmed after the effect is actually observed |
| R04-B | Two records with the same name belonging to different authentication domains or object namespaces | The fictional join is rejected; identical text or numbers are not a basis for connection |
| R04-C | An earlier step changes the object's state, invalidating a capability the later step relied on | Prerequisites are re-checked; an old capability cannot declare the chain successful |
| R04-D | One route lacks a key mapping while another executable route has complete evidence | The unknown mapping only generates a follow-up test; the complete route can still advance and is not held back by the unknown branch |

## Validity basis and failure conditions

Multi-stage problems require considering interactions between several elements; this motivation is supported by [MulVAL's original research](https://www.usenix.org/conference/14th-usenix-security-symposium/mulval-logic-based-network-security-analyzer). That research does not prove this design's dynamic capability extraction or LLM combination is effective; this route must first validate that type and prerequisite checks are reliable.

The main metrics are evidence-backed chains that were actually walked, the fictional-join rate, the cost of validating key prerequisites and final goal output. Graph path counts, chain length and model-generated explanations cannot replace these metrics.

If normalizing natural-language capabilities fails often, rule maintenance costs more than effective combinations gain, or many goals can only hold through unvalidated connections, keep human suggestions and do not widen automatic execution. It should advance only once prerequisite expression and evidence quality have a foundation.
