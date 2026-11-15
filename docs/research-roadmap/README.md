# ARTEX innovation roadmap and version plan

Created: 2026-10-15. Review update: 2026-10-16. Source baseline: a9d11cb. Status: R&D design; every version and fixture is a future development plan.

The implementation mainline is audit first, then harden the existing loop by building four gates: dispatch, claim, write-back and completion. The capability routes plug into the existing dual graph and Planner/Worker. R05 pushes common predicates, baselines and diagnostics down into shared infrastructure; R02 is validated first; R03 delivers reachability first; R01 and R06 are built alongside evidence references and retesting; R04 comes last.

"Innovation" here means incremental design relative to ARTEX's current implementation. Authorization differentials, stateful testing, hypothesis maintenance and input reduction all have mature research or tooling behind them. The added value is wiring them into the autonomous exploration loop while preserving identity, object, state, evidence and applicability conditions; no claim of an industry first is made, and results reported by source projects are not treated as ARTEX's measured results.

The R01-R06 numbering is kept for research and evaluation, but they are no longer understood as six independent infrastructures. The revised [question-driven experiment search architecture](../QUESTION_DRIVEN_EXPERIMENT_SEARCH.md) makes the gated Planner the main deliverable; a standalone controller is developed only after residual scheduling problems meet the admission criteria.

## The six routes

| Route | Concrete innovation | Why it is worth doing | Explicit prerequisite |
| --- | --- | --- | --- |
| [R01 Conditional hypotheses and plan revision](R01-conditional-hypotheses-and-plan-revision.md) | Explicitly link a conclusion's applicability conditions to the plans that rely on it, and locate affected directions on counter-evidence | Prevents one local failure from closing a whole route, and stops stale hypotheses from consuming budget | Key context differences can be identified, and real evidence references exist |
| [R02 Identity and object relationship differentials](R02-identity-and-object-relationship-differentials.md) | Pick a small number of high-value authorization controls from ownership, role and tenant relationships | Validates boundaries with controlled objects and explicit permission expectations, reducing blind object guessing and status-code misreads | Authorized test identities, object relationships and independent permission expectations |
| [R03 Business state machines and invariants](R03-business-state-machines-and-invariants.md) | Build state preparation and dependency extraction first, then generate counterexamples from sourced rules | Improves reachability of valid states, and judges business violations only once rules are explicit | V1 needs a repeatable flow and observable state; violation judgments additionally need independent rules |
| [R04 Evidence-constrained capability chains](R04-evidence-constrained-capability-chains.md) | Chain routes from proven capabilities with subject, object and conditions, testing only missing prerequisites | Lowers the risk of stringing findings into a fictional exploit chain, and raises the combined value of existing findings | Capabilities have checkable evidence, and identity and resource conditions in a combination are compatible |
| [R05 Test validity and discriminating experiments](R05-test-validity-and-discriminating-experiments.md) | Provide common validity predicates and baselines to every route, and evaluate active diagnosis strategies separately | Keeps expired logins, missing objects and environment anomalies from being written up as security conclusions | Applicable controls or trustworthy observations exist; predicates earn decision authority only after item-by-item validation |
| [R06 Minimal reproduction preserving controls](R06-minimal-reproduction-preserving-controls.md) | Reduce requests and sequences while preserving permission relationships and the vulnerability effect, producing repeatable checks | Lessens interference from incidental responses and redundant steps in reproduction and fix confirmation | A clear oracle, a repeatable environment and the necessary reset means |

Capability boundaries: R05 decides whether an experiment is valid at all, R01 manages the conditions under which conclusions are reused across rounds; R02 validates subject-object permission relationships, R03 prepares business state and validates flows when rules exist; R04 combines existing capabilities and R06 reduces existing proofs. They share basic records while each keeps its own decision responsibility.

## Validity judgment and priority

Routes that directly correct concrete testing errors and can be validated on small fixtures come first. R05 targets invalid tests, R02 permission relationships, R03 business state, R01 erroneous extrapolation across conditions, and R06 lost reproduction conditions. Their benefit mechanisms can all be observed item by item and do not depend on training a new large model.

R04 places higher demands on fact quality and rule completeness, so it is a later combination route. Its goal is to raise the proportion of executable chains; merely generating more paths on the graph cannot count as success.

| Positioning | Route | Main benefit metric | Main risk |
| --- | --- | --- | --- |
| M0 observation, M2 common foundation | R05 | Times invalid tests were recorded as security conclusions; diagnosis recovery cost | Over-strict checks leave much undecidable and crowd out the real testing budget |
| M2 first end-to-end capability | R02 | Detection of authorization boundaries under known policies, false positives and total preparation cost | Wrongly inferred permission expectations, mixed identities, or shared objects treated as private |
| M3 reachability, M4 rule counterexamples | R03 | Reachability of valid states; violation detection under sourced rules | Mistaking an observed flow for an enforced rule; incomplete resets |
| Early observation, M3 full revision | R01 | Wrong continued dispatch after evidence changes, legitimate reopening, and duplicate overhead | Similar-condition mismatches causing repeated reopening or wrong pruning |
| Advances with M3 retesting | R06 | Successful reproduction in new environments, faithful reduction, handover cost | A weak oracle, so the reduced case proves a different problem |
| M4 late combination validation | R04 | Proportion of verified executable chains, cost of filling key prerequisites | Wrongly joining capabilities of different subjects, objects or moments |

This is a priority judgment based on mechanism and fit with the project. A route enters automatic execution only after meeting its validation threshold; no percentage improvement in success rate is assumed in advance.

## Differences from the existing design

The existing Planner already asks for re-checking weak negative conclusions and advances serial chains step by step with TodoWrite; workers can already search other execution processes; standalone finding retests already require valid prerequisites and normal controls; facts already carry observed/inferred confidence. None of these is counted as innovation again.

What the capability routes add is executable experiment expression and checking: binding context, assertions and evidence into stable records, and generating controls, checking applicability, revising plans and combining capabilities from those records. The model proposes strategies and interprets semantics; only registered and validated machine predicates get the corresponding admission and promotion authority. An `observed` label, a node being `confirmed`, or asset-touch coverage can never replace evidence acceptance.

## Shared protocol and R&D boundaries

Every route uses the [shared experiment protocol and evaluation](shared-experiment-protocol-and-evaluation.md). The meaning of minimal context, experiments and assertions is unified first, so the six routes do not each build their own conclusion system. Raw output is still stored by execution records, traffic and evidence facilities; the graph stores references and conclusions without six copies of the content.

Graph transactions, completion authority and the planning-reference schema are described in [architecture review and evolution design](../ARCHITECTURE_REVIEW_AND_EVOLUTION.md). Offline observation can start early; before automatic execution the corresponding reliability and predicate acceptance must pass. Common baselines share storage, versioning and review mechanisms, while health, owner controls and normal flows are still judged separately.

Routes keep four modes: off, observe, suggest and execute; predicates additionally have per-type authority stages of observation, suggestion and enforced checking. A route switch does not turn off the basic reference, transaction and completion-authority rules. Observe mode sends no requests to the target; unsupported scenarios stay unknown and open exploration remains available.

## Versions within a route

V1, V2 and V3 are R&D milestones within each route, not released ARTEX version numbers.

| Route | V1 minimal validation | V2 executable capability | V3 integrated into continuous exploration |
| --- | --- | --- | --- |
| R01 | Manually label key evidence; observe condition changes and affected plans | Persist evidence versions; review via reused triggers and recovery scans | Conditional negative results and controlled reopening |
| R02 | Read-only differential between two identities on a controlled object | Roles, tenants and dynamic object relationships | Link flows and output next-step validation suggestions |
| R03 | One real successful flow, dependency extraction and state preparation | Bounded step-skipping, reordering and repetition experiments under sourced invariants | Flow combinations across identities and objects |
| R04 | Manually curate proven capabilities and check combination compatibility | Generate a validation task for a single missing prerequisite | Incremental revision and multi-fact combination |
| R05 common capability | Label validity on historical traces and form predicate contracts | Shared baselines, prerequisite checks and budgeted diagnosis | Share versioned, time-limited diagnosis state across workers |
| R06 | Lock proof conditions that must not be removed and produce reduction candidates | Faithful reduction in a resettable environment | Hook into standalone retests and regression records |

## Implementation order and stage acceptance

M0-M4 is the mainline order, not release versions or a schedule commitment. Read-only fixture validation can happen within a stage; deliverables involving real execution and conclusion promotion advance according to their dependencies.

| Milestone | Implementation | Required deliverables and acceptance |
| --- | --- | --- |
| M0 audit first | Classify goal proofs, negative re-checks, duplicate work, graph and recovery errors; offline observation for R05-V1 and R01-V1 | Sample list, availability and statistical definitions, cost baseline and fixtures; insufficient data is marked explicitly and incidence is never inflated |
| M1 reliability hardening | Finish bypass protection; key graph transactions, error propagation, invariants and startup reconciliation; schema, versioning and recovery for plan evidence and expected-output references | Rolling back tool config cannot restore reason-only completion authority; edge failures leave no partial success; plans are recoverable after rebuild and late writes are rejected |
| M2 main deliverable | Common observations, machine predicates, baselines and a structured HTTP channel; R05-V2 and R02-V1 through all four gates; decision logs and tiered presentation delivered together | Identifies session expiry, legitimate denial, legitimate sharing and real violations; prerequisite changes after dispatch are detected before claim and before key actions; unknown rules never prove a goal automatically |
| M3 capability expansion | R02-V2; R03-V1 state reachability; R01-V2 persistent review; R06-V1/V2 hooked into standalone retests | Dynamic dependencies and resets are repeatable; evidence changes cause no wrong continued dispatch; reduction preserves the original control and proof relationship, with preparation and diagnosis costs accounted for |
| M4 separate promotion | R03-V2 when rule sources exist; validate each route's V3 separately; once the foundation is ready, R04-V1 last, then V2/V3 based on results | Rules are never guessed by the model; cross-round gains have independent controls; capability chains are walked through step by step and never accepted by graph path counts |

M2's evidence version check is first limited to explicit references and does not require R01's full semantic conflict detection. R03-V1 needs no business invariants beforehand; only the violation-judgment stage requires independent rules. R06 does not wait for R01 to finish. R04 can validate independently with manually reviewed capability records, without first building a general chain-search platform.

Common foundations and route capabilities keep a single source of state, and the graph references the original records. New gates should cover shared business paths and state explicitly which checks general tools do not yet include. Arbitrary Bash cannot by default count as execution covered by the structured HTTP adapter.

## Conditional branch for a new controller

A standalone controller is not a required M0-M4 deliverable. Its earliest admission prerequisite is that the task types under study have passed M1 and M2 and still show repeatable global scheduling failures: viable alternative candidates existed at the time, records suffice for attribution, and small changes such as stage quotas, priorities and dependency wake-ups have already been compared.

Once the prerequisites are met, register the samples, repetitions, main metric, allowed regressions and total cost cap first, then enter the A2 controlled standalone controller prototype. Adoption must prove an increment over the fully gated Planner and be re-checked on held-out tasks; otherwise the mainline continues. Concrete cases, exclusion conditions and A2/A3 acceptance are in [controller admission](../QUESTION_DRIVEN_EXPERIMENT_SEARCH.md#when-is-a-new-controller-needed).

The four evaluation groups are E0 original implementation, E1 M1 hardening, E2 gated Planner and E3 a standalone controller with the same capabilities. The first two separate foundational gains; E2 is the main deliverable; E3 differs from E2 only in decision authority and budget allocation, with no extra accounts, hidden rules or total budget. Threshold values are set from the audit and costs and fixed before evaluation; unregistered or under-sampled runs count only as observations.

## What each version should deliver

Each iteration delivers field contracts, input/output examples, support boundaries, fixed fixtures, gate decisions and sample reports, paired evaluation records, switches and the rollback method. Evaluations report false positives, false negatives, wrong completions, undecidable cases, preparation requests and model cost separately; intent, request or graph-node counts alone are forbidden as benefit measures.

Goal achieved, budget exhausted, blocked prerequisite, insufficient stage gain and manual stop are each delivered as distinct termination reasons. Simple budget and marginal-progress rules are validated in the existing loop first; stopping does not mean the goal is complete, and the existing rough coverage cannot prove testing was exhaustive.

Versions that miss their threshold remain observation or suggestion capabilities. Fix the oracle, context or prerequisite expression first, then decide whether to widen automatic execution.
