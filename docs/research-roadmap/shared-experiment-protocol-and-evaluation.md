# Shared experiment protocol and evaluation for the innovation roadmap

Review update: 2026-10-16. Status: a shared contract awaiting implementation, wired into the existing Planner and Worker.

The six capability directions share experiment semantics, predicates and baseline facilities, with R05 responsible for common validity checks and diagnosis. The protocol's goal is that every conclusion can answer: who did what to which object under which conditions, what was actually observed, and why that is enough to draw the conclusion. It does not depend on a standalone search controller.

## Minimal data contract

### Experiment context

| Field | Meaning and constraints |
| --- | --- |
| task_id and exploration_id | Explicitly distinguish task and exploration record IDs, with ownership checked |
| authorization_revision | Version of the user's authorized scope; dynamically discovered assets do not expand authorization automatically |
| target_ref | Exact target reference, keeping protocol, host, port and necessary path information |
| actor_ref and session_revision | Subject and its current login-state version; credentials are resolved by reference by the executor |
| object_refs and relation_refs | Test objects, ownership, tenant and sharing relationships and their basis |
| application_state_ref | Business pre-state and its observation record, not replaced by a verbal description |
| environment_revision | Known deployment, config or test environment version; noted as unknown when it cannot be confirmed |
| observation_channel | Actually available response, state read, log or other observation channel |

Tokens, cookies and passwords are not copied into global fact summaries. A first implementation can map in-task references to the existing credential config without rebuilding the whole credential-management system at the same time. A role name, the same IP or belonging to the same company alone can never establish that subjects, authentication domains or authorizations are the same.

### Experiment record

Records the experiment ID, source intent, hypothesis and evidence references, normal control, changed factors, operation sequence, expected assertion, observation references, request and model budget, and the reset method when needed.

Shared records store schema_version, route outputs store route_id and route_version, and the mode is recorded separately at runtime. Protocol versions are kept apart from R&D milestones, and new optional fields keep old records readable; context missing from historical records stays unknown and is never backfilled in bulk by model guesses.

Control requests and variant requests are bound to the same context version. After a login state, object or business state changes, applicability is re-checked. Random tokens and dynamic identifiers are extracted through explicit dependencies; the model never guesses what a previous request produced.

### Observation and plan references

Observation details are saved first by a supported executor, including at least the execution and attempt IDs, actual target, context references, time, observation channel and raw record references. The model generates a summary afterwards and can never be the only source of these fields. A fact can aggregate several observations, while assertions remain bound to their actual applicability conditions.

The existing `record_fact` summarization requirement is a model tool instruction, not a database merge. Migration keeps historical text and unknown conditions, and never uses the model to recover objects or sessions that were not recorded. Sensitive details are read through existing permissions, and credentials are never copied into global summaries.

Plan steps store `step_id`, `plan_revision`, evidence references and `expected_output_refs`. Future outputs use placeholder references formed from the step and an output key, bound to observations or assertions after execution; nonexistent fact IDs must never stand for future facts. Progress is derived from run state and valid bindings and supports review after a binding is revoked; persisting a single checked flag is not enough.

### Assertions and experiment results

An assertion includes at least the rule being checked, the rule source, the actually observable conditions and evidence references. Programs can only judge implemented assertions automatically; permission or business rules proposed by the model are hypotheses to be validated until confirmed. Several observations can support a conclusion through sourced derivation; proofs cannot be admitted or rejected based only on `observed/inferred` labels.

| Result | Meaning |
| --- | --- |
| violation_observed | A defined rule was observed being violated under valid conditions, and the evidence satisfies the assertion |
| not_reproduced | Not reproduced in this experiment under the current conditions; cannot be extrapolated to the whole target being safe |
| inconclusive | Prerequisites, controls, observations or evidence are insufficient to form a positive or negative conclusion |
| not_applicable | Existing evidence proves the test method does not apply under the current conditions |

These are results of the new experiment protocol and do not directly replace the existing intent state, confidence or finding-retest verdict. An adapter maps them explicitly: for example, inconclusive never maps to fixed, and not_reproduced does not automatically close a whole exploration route.

When referencing findings, the distinction between finding_id and finding_node_id is kept, following existing API conventions. When results are written to the graph or reports, source task, reference permissions and evidence version are checked.

## Predicate authority and the four gates

| Type | Required content | Authority |
| --- | --- | --- |
| Machine predicate | Registered name and version, input types, applicability conditions, observation requirements, program result and reason | Takes part in admission, invalidation and conclusion promotion only within its validated scope |
| Model annotation | Source, explanation, candidate conditions, relative score and what remains to be validated | A suggestion or review lead; can never grant itself decision authority |

Machine predicate results can be true, false or unknown; they are local condition values and do not equal the four-valued experiment result directly. For example, a successful status-code match is not a permission violation. The oracle must combine a valid identity, object relationship, independent permission expectation and actual effect to form the corresponding assertion.

Evaluation records are produced by programs and bound to input observations, context and rule versions; the model can only reference them and cannot pass off a JSON object with the same name as a validated result. When a known prerequisite has failed or necessary evidence is missing, validity cannot be restored by editing a text label.

The model can register review leads but cannot directly change evidence validity or create blocking states. Whether something enters blocking review is decided by a registered rule or an explicit human decision; when a necessary condition is unknown it is handled by program rules, so open-ended labels never gain actual admission authority.

The four gates call the common rules at dispatch, claim, write-back and completion respectively, and business state and required relationships are committed atomically. Versions are re-checked at claim time, but before key requests the target's actual state must still be re-checked as far as supported; database checks cannot guarantee the external environment is unchanged. See [main architecture responsibilities](../QUESTION_DRIVEN_EXPERIMENT_SEARCH.md#responsibilities-of-the-four-gates).

A closed predicate set constrains automatic decisions but does not close the set of exploration strategies. Unknown methods can enter suggestions, prerequisite preparation or bounded exploration; unimplemented assertions can never be promoted directly to a proven goal.

## Layers of validity checking

| Layer | What is checked | Conclusion that cannot be drawn from it |
| --- | --- | --- |
| Transport | Whether a complete response from the corresponding target was actually received | Receiving a response does not mean the target's business logic was reached |
| Identity | For experiments needing login, whether the subject and session are valid | A health check returning 200 does not prove the login is valid |
| Business baseline | Whether a legitimate control produces the expected business result | One legitimate success does not prove all parameters and later states are valid |
| Observation capability | Whether the effect this experiment verifies can be seen | No visible echo does not mean no effect |
| Method applicability | Whether the current method is compatible with known target conditions | A black-box response cannot generally prove a specific code branch was reached |

Each experiment declares the checks it actually needs. Anonymous public endpoints do not require login; when an observation is missing the output is unknown, and no fact that a prerequisite holds is fabricated. Normal controls prefer the smallest known-good read, re-checked at batch boundaries, on context changes or when anomalies appear, to control extra overhead.

## Shared baseline records

R02's owner controls, R03's normal business flows and R05's session health share baseline storage, references, re-checks and invalidation, while each keeps its own purpose and oracle. A reachable normal flow cannot prove a business order must be followed, and a valid session cannot prove ownership of a specific object.

A baseline is bound to the target, subject and session, object or business state, purpose, observation references and predicate version, and records its validity period and abnormal-invalidation conditions. It is re-checked after the target's authorization or environment changes; server-side state changes without a local notification are handled through expiry and anomaly re-checks. The same context number cannot extend validity indefinitely.

Requests to create and restore baselines all count toward the budget; they cannot be built separately for six routes with the preparation cost hidden. Before reuse, check whether the context is compatible; task-private sessions and objects do not propagate automatically just because the asset graph is shared.

## Integration with the existing architecture

| Location | Integration responsibility |
| --- | --- |
| internal/agent/planner.go and internal/agent/tools.go | Propose experiments and receive structured conclusions; dispatch and completion go through the common domain rules |
| internal/agent/worker.go | Execute experiments and return actual observations, still responsible for one intent |
| internal/db and the existing evidence storage | Persist context, versions and relationships, referencing raw records and snapshots |
| internal/agent/retester.go and internal/server/finding_retests.go | Reuse standalone retests and the existing reproduced/fixed/inconclusive handling |
| internal/agent/finding_workflow.go | Reuse the baseline/proof/verification evidence roles and report version checks |
| internal/server/engine.go | Claim and execute experiments along the existing scheduling path, checking prerequisites, budget and notifications |

An implementation can add a small experiment domain module, define the contracts above first, then adapt the existing agents, database and executors to them. A single source of business state is kept. The new routes' checks cover only actions executed through these experiment interfaces and cannot claim to cover arbitrary Bash or every third-party tool's behavior.

Module boundaries can be organized as in the table below; the directory names are development suggestions, and the repository does not contain these modules yet.

| Suggested module | Responsibility and dependencies |
| --- | --- |
| experiment | Shared references, context, experiment results and assertion interfaces; no dependency on agent, server or a specific database |
| experiment/predicate | Registration, applicability and evaluation records of common machine predicates |
| experiment/baseline | Reference, version, expiry and re-check contracts for baselines of each purpose |
| experiment/belief | R01's evidence maintenance and review location |
| experiment/authorization | R02's relationship selection and differential experiments |
| experiment/workflow | R03's states, dependencies and invariants |
| experiment/capability | R04's capability representation and combination checks |
| experiment/validity | R05's common validity checks and budgeted cause-discrimination strategies |
| experiment/reduction | R06's faithful reduction and reproduction recipes |
| Existing db, agent, server | Persistence adapters, tool adapters and in-task assembly respectively |

Route modules depend on the shared contract and consume other routes' capabilities through interfaces, avoiding reading each other's private tables or forming dependency cycles. The shared contract and necessary storage adapters are integrated first, then each route version is wired separately into tool registration and task assembly. Migrations for new fields are handled uniformly by the storage adapter, and turning a switch off never deletes historical experiments.

The first protocol-native execution channel is structured HTTP, responsible for identity injection, dynamic dependencies, control association and recording actual requests/responses, reusing the existing evidence facilities. When traffic capture is off, the channel is not HTTP, or the proxy does not cover it, the raw records the executor actually provides are used; without a record, evidence cannot be fabricated, and global capture is never turned on automatically just to start a route.

Bash remains the general-purpose channel. Evidence quality is judged by source, completeness, context and verifiability, not ranked by channel alone. When structured identity, an effect model or replayability is missing, state explicitly which capability is downgraded; its observations cannot be claimed to have passed the corresponding check.

Prefer new sessions or controlled objects to isolate independent experiments, while still comparing actual read/write conflicts on shared resources. Conflict records include authentication domain, subject, object set and state domain; writes by different subjects to the same object can also conflict. The model cannot narrow the side-effect scope the executor knows about; unknown writes are reconciled first, never retried directly.

Durable evidence and review todos are written first, then TriggerEvent and debounce are reused to wake the Planner. Recovery scans pending-review records instead of relying on in-memory events surviving intact.

## Gate logs and tiered presentation

Every new oracle ships together with its log and report adaptation. Gate logs record the gate type, the actual decision such as allow or deny, the related intent or goal, evidence and context versions, predicate version, reason and follow-up review references. Decisions allowing state transitions are saved with the business transaction, and success is not returned when a key record fails; logs never fabricate comparisons with unevaluated candidates.

Presentation distinguishes candidate explanations, sourced observations, rule-validated conclusions and independent reproductions, each with its own conditions and references. They express different guarantees, cannot be promoted by labels the model applies itself, and are not converted into uncalibrated confidence scores. `not_reproduced` shows the valid control, test method and applicable scope; insufficient conditions should be inconclusive and never displayed as fixed.

The existing evidence version and retest UI are reused. New four-valued experiment results, node workflow state, model confidence and retest verdicts are stored separately and linked through explicit adapters, so four sets of concepts never get mixed into one status field.

## Modes and rollback

| Mode | Behavior |
| --- | --- |
| off | Takes no part in planning or execution |
| observe | Analyzes existing traces or fixtures, sends no extra target requests and does not change original decisions |
| suggest | Outputs evidence-backed experiment suggestions, executed through the existing scheduling and permission paths |
| execute | Executes automatically only within supported prerequisites, operation types and budget |

Each route has its own switch and version number. Turning it off stops new route actions while keeping the evidence and versions already produced. External operations already in progress cannot be undone by flipping a switch; their ownership and results still need a normal wrap-up.

Predicates additionally register an authority stage of observation, suggestion or enforced checking, accepted item by item according to input type and decision capability. A route entering execute does not mean every predicate it proposes is authorized; new checks under observation do not change old decisions. Experiment route switches do not turn off basic rules such as reference ownership, transactions and completion authority.

## Control evaluation design

Architecture evaluation uses the [four groups defined in the architecture document](../QUESTION_DRIVEN_EXPERIMENT_SEARCH.md#prototype-versions-and-control-evaluation): E0 original implementation, E1 reliability hardening, E2 the gated-Planner main deliverable, and E3 a standalone controller built only after admission. E2 and E3 share the same route versions and checkers and differ only in candidate selection and budget allocation.

Decision-authority controls fix the candidate generation protocol, information and candidate cap; swapping the generator or widening the search is a separate ablation, so improved input quality is not mistaken for a controller increment.

A single route is compared with the same stage's implementation with that route off; combinations are ablated item by item. R05's common checks and active diagnosis are measured separately, and R03 reachability and violation judgment under sourced rules are measured separately, so gains from stronger rule input, more budget or foundational fixes are not credited to the algorithm.

Fix the model, prompt version, task input, accounts, objects, initial service snapshot and budget, and record every actual failover. Reset the service before paired runs so the first group cannot change the second group's test conditions; randomize the order of groups and repeat to observe the distribution of results.

Offline traces can only validate classification, references and plan-revision logic; they cannot prove extra requests find more problems. Discovery capability must be validated on resettable services with known real rules. The evaluator holds the hidden implementation and vulnerability labels; business rules, test accounts and object-creation observations explicitly provided by the task can be common input to both the old and new groups.

Samples with explicit rules and pure black-box samples without rules are counted separately. The latter cannot secretly feed extra strategy to the new approach, and keeping only the former to claim overall effect is not allowed. Without rules, the pending-confirmation state should be kept and its impact on task output counted. Grey-box conditions form a separate group.

## Fixture requirements

Each route document lists four kinds of minimal fixtures. Each kind should have corresponding versions for applicable and not applicable, normal and violating or interfering conditions, including counterexamples that would make the original oracle wrong. They are test requirements to be implemented, not completed run records.

Test objects use controlled accounts, unique markers and resettable business data. Fixtures needing write operations run in an isolated test environment, verifying that cleanup or recovery actually completed. These restrictions come from the need for experiment comparability and state reliability.

## Promotion and stop conditions

V1 validates decision logic and record semantics first; V2 then compares actual execution effect; V3 studies cross-round and cross-route combinations. Before each promotion, this version's metrics and extra budget are fixed; the definition of success is never adjusted after seeing the results.

Automatic execution requires at least: fixed correctness fixtures pass; normal scenarios add no false positives; interference is identified as undecidable; no goal the original implementation succeeded on is lost; the route's main metric is stable across paired repetitions; total cost stays within this version's budget. With insufficient samples only observations are reported, never statistical significance or general effectiveness.

| Route | Main metric | Must be reported alongside |
| --- | --- | --- |
| R01 | Continued dispatch after wrong evidence, legitimate reopening and revision correctness | Unnecessary reopening, missed valid directions, revision cost |
| R02 | Violation detection under known permission policies | False positives, false negatives, undecidable cases, identity and object preparation cost |
| R03 | V1 reachability of valid states; V2 violation detection under sourced rules | Reset failures, invalid sequences, missing rules, false negatives and execution cost |
| R04 | Capability chains that are actually executable and reach the goal | Fictional joins, paths missing prerequisites, validation requests and model cost |
| R05 common capability | Times invalid tests were misread as safe | Decidable proportion, diagnosis recovery benefit, extra requests and shared baseline cost |
| R06 | Successful reproduction in an independent environment and fidelity of the proof relationship | Reduction request cost, lost necessary conditions, proportion that cannot be reduced |

Every control, discrimination, review and reduction request is billed; tool, model and manual supplementary costs are recorded too. The discovery and reproduction stages are accounted separately, then a total is reported. Raising the undecidable proportion, shortening reports or producing more nodes is not, by itself, an improvement.

If the gain comes only from more requests, wrongly inferred rules, ignoring undecidable samples, changing the goal definition or incomplete environment resets, stay in the current mode, fix the experiment and compare again.

## Task goals and stopping with a reason

Effectiveness is evaluated by goal output with sufficient evidence within budget, while also reporting wrong completions, valid experiments, exploration and proof waits, and preparation cost. The existing rough asset coverage cannot replace testing adequacy; quantitative acceptance needs an explicit metric, denominator and rule version.

Budget, an unrecoverable prerequisite block or low marginal progress within a pre-registered window can end exploration, each saving its termination reason and what remains uncovered. No new facts only triggers a strategy review; limited alternative strategies and cost limits decide whether to continue and never constitute proof of "fully tested".

The start and adoption thresholds for a new controller follow the [architecture document](../QUESTION_DRIVEN_EXPERIMENT_SEARCH.md#when-is-a-new-controller-needed). The common protocol, the four gates and the six capability directions can all be delivered within the existing loop.
