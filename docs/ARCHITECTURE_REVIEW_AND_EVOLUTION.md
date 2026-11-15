# ARTEX architecture review and evolution design

Created: 2026-10-15. Review update: 2026-10-16. Code baseline: `a9d11cb`. Status: R&D design; the new mechanisms are not implemented yet.

ARTEX's mainline keeps the dual graph, the Planner/Worker division of labor, and the Go monolith and PostgreSQL core. Existing traces are audited first, then completion authority, graph writes and planning recovery are fixed, and only then are the four gates -- dispatch, claim, write-back and completion -- and the common experiment protocol built into the existing loop.

A standalone search controller is not a first-batch deliverable. Questions, observations, evidence and versions are first used by the existing Planner; only when repeatable global scheduling failures that cannot be fixed with smaller changes remain after gating does a standalone control prototype begin. The full admission conditions are in [question-driven experiment search architecture](QUESTION_DRIVEN_EXPERIMENT_SEARCH.md).

Capability building advances according to the [innovation roadmap and version plan](research-roadmap/README.md). R05 sinks into common checks and diagnosis, R02 comes first, R03 starts with state reachability, R01 reuses the existing wake-up mechanism, R06 advances with retesting, and R04 comes last. Every version must validate its benefit; no success-rate improvement is promised in advance.

## Existing architecture and design value

ARTEX already forms the basic loop of continuous exploration: the user gives a goal, the Planner picks directions based on existing facts, a Worker executes one explicit intent and writes assets, facts, findings and execution records back, and the Planner adjusts the next step accordingly.

| Existing mechanism | Responsibility and value |
| --- | --- |
| Asset graph | Stores shared assets and their links, answering what was discovered and how assets relate |
| Exploration graph | Records the source, process and results of exploration through goals, intents, facts, findings, hints and their relationships |
| Planner | Combines goals with the global situation, maintains cross-round todos and decides the next exploration directions |
| Worker | Executes one intent at a time, accumulates evidence, and hands new leads found during execution back to the Planner |
| Process search and session records | Reuses other workers' process observations, supporting continued execution and investigation |
| Hot/cold compaction and summaries | Manages context size while keeping the original nodes |
| Evidence and retest capability | Existing finding evidence snapshots, evidence versions and a standalone retest path |

The dual graph, fact-driven planning, process information exchange and multi-round todos are all capabilities of the original design. Later plans should evolve incrementally on top of these mechanisms, keeping open exploration and cross-asset association.

## Confirmed reliability gaps

### Completion decisions lack common evidence acceptance

`proveGoal` in [`internal/agent/tools.go`](../internal/agent/tools.go) checks ownership, readable source and type of the goal and evidence nodes, but does not check evidence sufficiency, condition validity or quantified acceptance; write errors for the proof relationship and the goal state are also ignored.

The `goal_met` handler can mark a task complete directly, but that does not mean the default Planner can necessarily call it. [`internal/agent/toolcatalog.go`](../internal/agent/toolcatalog.go) already unbinds the tool by default, and [`internal/server/orchestration.go`](../internal/server/orchestration.go) has a migration unbinding it on old databases. Residual risks include manual rebinding, and [`internal/server/assembly.go`](../internal/server/assembly.go) allowing the base tool set when reading the tool table fails. Completion authority should be protected by common acceptance rules, not only by tool visibility.

`confidence=observed` is currently filled in by the model and `confirmed` is a node workflow state; neither can serve as a program verification result on its own. The existing coverage is also only a rough asset metric: [`internal/db/task_assets_context.go`](../internal/db/task_assets_context.go) counts assets linked to a fact as tested, which does not mean those assets have completed systematic validation. Quantified goals must first define the metric and its version, and then be computed by the program.

### Planning state depends on the Planner instance

`todos` in [`internal/agent/planner.go`](../internal/agent/planner.go) is an in-memory map; `todoFor` lets multiple planning rounds in the same Planner instance share todos, while `NewPlanner` creates an empty map. Keeping state across rounds here is not the same as persisting it across instances.

`invalidateTaskAgents` in [`internal/server/task_llm.go`](../internal/server/task_llm.go) clears the agent cache, and the next `agentsForTask` recreates the Planner. So a process restart or a rebuild after agent cache invalidation both break the continuity of these in-memory todos.

Planning state should belong to the task, independent of the lifecycle of the model session and the Planner object. While an old instance is still running, its late writes must also be kept from overwriting a newer planning version.

### Some graph operations have step-by-step commit windows

[`internal/agent/tools.go`](../internal/agent/tools.go) has the following paths:

- After creating an intent, the source relationship is written separately and `Link` errors are ignored.
- After creating a fact, the `intent -> yields -> fact` relationship is written separately and edge errors are ignored.
- When proving a goal, the `proves` relationship and the `met` state are written separately and both write errors are ignored.

These paths can leave partially successful results when a database operation fails, for example an intent missing its source relationship, or a goal marked complete while its proof relationship was never saved.

The project does not lack transaction capability. `RecordFindingTx` in [`internal/db/finding_traffic.go`](../internal/db/finding_traffic.go) already puts the finding node, intent relationship and related records into one transaction. This business-transaction boundary should be extended to the other key graph operations.

### Observation conditions may be lost during summarization

The `record_fact` tool instruction asks the model to summarize several observations from one exploration where possible; it is not an automatic database merge. The current fields have no separate observation-level context reference, so identity, object and state differences can be lost in the summary, and adding a schema afterwards cannot recover information already omitted.

Supported executors should save raw observations and context first, then generate the fact summary. The summary can be coarse-grained, but an assertion's applicability conditions and individual observations cannot be squashed into one unconditional conclusion.

### Claiming and notifications do not yet express durable dependencies

`claimNext` in [`internal/server/engine.go`](../internal/server/engine.go) calls `ClaimIntent` in [`internal/db/exploration.go`](../internal/db/exploration.go), which currently only atomically checks that the intent is open and claims it, with no prerequisite version check.

[`internal/server/manager.go`](../internal/server/manager.go) already has the event hints needed for `TriggerEvent` and debounce wake-ups, but `pendingTriggers` lives in memory. They can be reused to notify changes but cannot replace durable evidence state, review todos and recovery scans.

## Trace audit, done first

M0 first determines which transcripts, activity, graph relationships and config versions are actually available. It checks whether call records are complete, whether tools were reachable at the time, and whether tasks and intents can be linked; samples with missing data are marked undecidable, and the existence of a tool definition is not taken as evidence of an actual call.

| Audit target | What is checked | Priority affected |
| --- | --- | --- |
| Goal completion | Actual `prove_goal` / `goal_met` calls, evidence chains, conditions and acceptance; cases where inferred facts took part in proofs | Completion gate, evidence adaptation and bypass protection |
| Negative observations | Whether the control was valid at the time, whether a re-check was planned and actually executed, and whether there was still wrong extrapolation after it | R05 common checks, R01 conditional reuse |
| Scheduling and budget | Repeated dead ends, preparation and diagnosis cost, exploration and proof waits, available alternative candidates | Simple quotas, stop rules and whether a controller is needed |
| Graph and recovery | Missing required relationships, partial writes, todo rebuilds, late results and unknown actions | Atomic operations, reference schema, startup reconciliation |

Proportions use decidable samples as the denominator, reporting complete, missing and unattributable data separately. The `inferred` share is only a lead; evidence-backed derivation must still be distinguished from insufficient evidence. Human or model review should keep the raw references; model opinions cannot automatically serve as ground-truth labels.

The audit delivers a sample list, error classification, redacted references, statistical definitions and priorities for the next stage. When historical records are insufficient, the necessary observations and controlled fixtures are added first; historical incidence is never fabricated, and it is not assumed the audit can be done in a day. Audit and preparatory fixes can overlap, but benefits cannot be claimed after skipping the baseline.

## M1 foundational hardening

This stage first fixes reliability and obvious completion bypasses. M2 then wires in predicates with explicit evidence semantics and the four gates; "the transaction committed successfully" is never taken to mean a goal has been proven.

### Converging completion authority

Remove the model's ability to end a task automatically on a reason alone; if the `goal_met` name is kept, its handler must also go through the common acceptance path. High-privilege tools must not regain completion authority through a fallback when reading the tool table fails.

`prove_goal` may promote a goal only after the necessary writes succeed, evidence references are valid and the currently supported acceptance rules are satisfied. Semantic goals not yet supported stay pending acceptance and are handled by an explicit human confirmation flow; the model provides evidence candidates and reasons but cannot fill them in as validated rules itself.

Goal completion is separate from stopping exploration. Timeout, budget exhaustion, prerequisite blocks or insufficient stage gain should deliver partial results and reasons, and are never marked as the goal being achieved.

### Atomic graph domain operations

Database transactions are organized around the following business actions:

| Business action | What is committed together |
| --- | --- |
| Create intent | Intent node, asset anchors and the necessary source relationships |
| Record fact | Fact node, asset anchors and the corresponding yield relationship |
| Prove goal | Validated evidence references, proof relationship and goal state change |
| Create goal | Goal node and the necessary source relationship to the task root |

Within the transaction, node ownership, linked-task reference permissions, state and required relationships are checked; success is returned and follow-up notifications are triggered only after the transaction commits. External commands should not be included in long database transactions.

`internal/agent/tools.go` currently ignores `Link` errors in five places: intent parent relationships, root relationships, goal proofs, fact yields and goal sources. Transactions and error propagation are extended around business actions, with invariant checks for required graph relationships and startup reconciliation. Allowed direct source-task references must be identified explicitly so legitimate cross-task evidence is not mistaken for orphans; records that cannot be repaired reliably go to manual review, and are never deleted automatically or patched with guessed edges.

What is added here are business-operation boundaries in the existing storage layer. The database remains the authoritative source of business state; no parallel state kernel or full event-sourcing platform is added for now. The semantic sufficiency of a goal proof still needs an acceptance method per goal definition; transactions can only guarantee record consistency.

### Task-level planning state

Todos, planning versions and the necessary evidence references are saved in durable records owned by the task. The Planner restores from the record every round, saves a new version when todos are updated successfully, checks the expected version on write and rejects stale overwrites.

This is not simply serializing the in-memory map. First design stable identifiers for plan steps, evidence references, expected-output references and how they are bound: facts not produced yet use in-plan output placeholder references, bound to observations or assertions once actually produced. Execution progress is derived from valid outputs and run state; the model's ticks are kept as notes and cannot independently prove a step is complete.

Todos remain revisable plan drafts. Only explicitly known prerequisites act as scheduling constraints; no complete flow has to be generated in advance. Evidence that historical todos lack stays unknown and is not filled in by model guesses.

Restoring a plan does not mean every external command can be replayed safely. A tool execution may already have had an effect whose result was not yet saved; on recovery the next step should be decided from execution records and external state.

### Unified evidence references and uncertainty

The existing `record_fact` already supports `evidence` and `confidence`, distinguishing `observed` from `inferred`; `graph_overview` also carries confidence, including fact overviews of linked tasks. This existing capability must not be repackaged as new design. See [`internal/agent/tools.go`](../internal/agent/tools.go) for the implementation.

The incremental work is giving important conclusions stable source references -- tool calls, execution records, raw output or evidence snapshots -- and carrying confidence through summaries, search and goal evaluation. A node's `confirmed` workflow state should not be interpreted as everything having been reproduced independently.

`confidence` keeps expressing direct observation versus inference; retests separately record method, conditions and result. HTTP snapshots can reuse the existing evidence facilities, and command output and non-HTTP evidence should have suitable reference forms too; not every conclusion has to be bound to HTTP traffic.

The verification method is chosen per goal: the program checks implemented conditions and calls the retest capability when reproduction is needed; for open semantics the model proposes candidates and a human accepts explicitly. Several real observations can support a conclusion through sourced derivation rules; `inferred` is not treated as entirely invalid, and the `observed` label is not treated as a sufficient condition.

### Execution identifiers and evaluation baseline

Executions get stable run identifiers and attempt numbers, recording the model, prompt and tool config versions actually used, the compaction strategy and the budget. Config digests are recorded without saving secrets; failover is allowed while the actual choice of every call is kept.

Evaluation runs alongside the first round of changes. A baseline is established first with controlled cases and saved execution traces, focusing on recovery correctness, repeated operations, evidence sufficiency, goal decisions and cost per unit of effective output. LLM output fluctuates, so comparisons should fix task conditions and repeat runs to observe the distribution.

## M2 builds the four gates into the original loop

Dispatch, claim, write-back and completion use shared domain operations, covering the same business constraints for agents, platform tools and manual submissions. The completion gate cannot be bypassed by rebinding tools, the claim gate cannot rely only on the version at dispatch time, and the write-back gate must keep observation conditions. Specific responsibilities are in [the four gates in the main architecture](QUESTION_DRIVEN_EXPERIMENT_SEARCH.md#responsibilities-of-the-four-gates).

The common foundation first provides observation details, machine predicate registration, baselines isolated by context and purpose, and a structured HTTP execution channel. R05's checks and diagnosis plug in here, and R02's first version serves as the minimal capability that goes through all four gates. The closed vocabulary only constrains automatic decisions; the model can still propose open exploration directions.

Gate decision logs, experiment results and tiered evidence presentation ship together with the checkers. The existing [`web/src/components/finding-retest-panel.tsx`](../web/src/components/finding-retest-panel.tsx) already shows "still reproducible, fixed, cannot confirm" and should be reused and extended; the new four-valued experiment results do not directly replace the existing retest verdict.

Route switches and predicate promotion are controlled separately, and basic rules such as reference ownership, transactions and completion authority always apply. Unsupported actions have explicit boundaries; it cannot be claimed that arbitrary Bash has received complete prerequisite and scope checks.

## Adjustments to the original eight recommendations

| Initial direction | Choice after review | Condition to advance |
| --- | --- | --- |
| Task kernel and structured plans | Narrowed to atomic domain operations, a plan-reference schema and persisted planning state | Handled in M1; a standalone controller must additionally meet admission conditions |
| Durable execution and leases | Record run identifiers, attempts and recovery evidence first | Introduce leases when there are multiple instances or remote execution |
| Three layers of observation, fact and verification | Extend the existing facts, confidence and evidence facilities | Avoid storing three sets of similar records |
| Unified context compilation | Optimize global summaries, local details and on-demand reads first | Validate the benefit with information-loss and cost data |
| Complete coverage matrix | Record actual test conditions, evidence, results and proof first | Generate targeted matrices only for systematic coverage tasks |
| Adaptive scheduling | Build the budget ledger, stage quotas and reasoned stopping first | A complex selector must prove global scheduling is still out of control after gating |
| Multiple runners | Keep a lightweight execution interface and add containers or remote environments as needed | Advance when there is an explicit isolation or deployment need |
| Config-recorded evaluation and dependency injection | Move evaluation earlier; implement dependency injection around concrete testing difficulties | No whole-system refactor without a goal |

A complete plan engine, a graph database, a resident judge agent, a RAG service and a distributed workflow framework are all not default dependencies of the first round.

## Design boundaries that preserve autonomous exploration

### Combining global summaries with local evidence

A worker's context consists of a small global overview, the relevant subgraph of the current intent and detailed records read on demand. The existing hot/cold compaction and process search keep their responsibilities.

`renderWorkerGraphOverview` in [`internal/agent/worker.go`](../internal/agent/worker.go) explicitly encourages workers to discover cross-asset leads while executing their intent and hand them to the Planner. Context trimming should preserve this associative ability; when a worker finds a new direction it hands over the lead, and actual execution is still assigned by the Planner.

### De-duplication and stop decisions keep condition information

Hard de-duplication mainly handles repeated execution of the same submission. Semantic similarity can remind the Planner, but the same asset or a similar description is not enough to judge a duplicate: after identity, parameters, environment, time or factual evidence change, testing again may be valuable.

No new facts can trigger a re-evaluation of direction but does not trigger termination on its own. Marginal progress is checked against pre-registered windows and cost limits, allowing exploration to stop after limited alternative strategies; infrastructure blocks, hypotheses not reproduced, budget exhaustion and insufficient stage gain are recorded separately, and stopping is never interpreted as fully tested or goal complete.

### Test records and coverage keep their precise meaning

An asset being touched, a test having been executed and systematic security validation being complete are metrics at different levels. The existing coarse coverage signal should be presented according to what it actually means.

Prefer storing tests that actually happened and their conditions, viewing gaps as needed. Avoid expanding every combination of asset, identity, operation, hypothesis and environment by default, which would flood scheduling with low-value entries.

### Authorization boundary independent of discovery scope

`AddAutoScope` in [`internal/db/task_scope.go`](../internal/db/task_scope.go) adds domain or IP scope based on registered assets, and [`internal/agent/tools_insert.go`](../internal/agent/tools_insert.go) calls that path. So the dynamically growing `task_scope` should not be used directly as a fixed execution authorization boundary.

If execution permission control is added, store a separate, user-managed, versioned authorized scope expressing conditions such as hosts, IPs and ports at the needed granularity. Discovering new assets can extend knowledge and task-scope records but must never expand execution authorization automatically. The existing asset interception mechanism still has to be combined with the actual action target to determine coverage boundaries.

### Leases and external side effects are handled separately

A single-process deployment first makes run ownership explicit. Multi-instance or remote-worker scenarios then design rules for claiming, renewing, reclaiming and rejecting writes from expired workers.

An expired lease cannot revoke commands already sent and cannot guarantee an external operation runs only once. For actions that started but whose result is unknown, use idempotency keys or query external state, depending on the action's nature, before deciding whether to retry. [LangGraph's idempotency notes](https://docs.langchain.com/oss/python/langgraph/functional-api#idempotency) likewise point out that unfinished tasks may run again on recovery and duplicate side effects must be handled.

## The falsifiable-plan innovation direction

### Increment over the original design

The original exploration graph already records the sources of facts and intents through relationships such as `derived_from`. The new direction expresses on top of those source relationships: which hypothesis a plan depends on, the conditions under which the hypothesis applies, which evidence supports or refutes it, and which version of the evidence the plan relies on.

That way, besides storing exploration history, the system can locate the plans that need re-evaluation after evidence changes. The key increment is maintaining evidence validity and explicitly reviewing affected plans.

### Minimal representation and revision flow

Record the following for key exploration directions first, without requiring every operation to fill in a complete structure:

| Information | Purpose |
| --- | --- |
| Hypothesis and applicability conditions | States the judgment and the assets, identities and environment it applies to |
| Supporting evidence | References actual observations, keeping source and uncertainty |
| Expected observations and refutation conditions | States what the test hopes to obtain and which results would weaken the current evidence |
| Plans depending on the hypothesis | Locates todos or intents needing review after evidence changes |
| Evidence version and review state | Distinguishes the original plan, plans pending review and revised plans |

This can first be expressed through existing facts, hints and plan links; new node or edge types are considered only after the benefit is confirmed, and no third graph is built by default.

When new evidence arrives, first check whether it applies to the same conditions. When the model raises a suspected conflict, a review candidate is registered; blocking review starts only when a machine rule confirms required evidence is invalid or unknown, or a human explicitly decides so. The Planner is given supporting and refuting evidence and revises the plan within the common constraints, saving reasons and historical versions.

State is persisted first, then notified through the existing triggers and debounce; recovery scans unfinished reviews. When the machine has confirmed a prerequisite failed, the Planner cannot just edit a text label to make it pass again; new valid evidence must go through the common write-back and admission paths.

A semantic conflict never revokes a whole chain automatically on the strength of one classification label. When the completion evidence of a goal is affected, review should be triggered too; re-evaluation is not the same as deleting historical evidence.

### Example and validation method

Suppose endpoints A and B share an authentication mechanism, and the plan is to re-check on B the trigger conditions of a problem already confirmed on A. Later, under the corresponding identity and environment, B is observed using a different mechanism, so the original trigger prerequisite does not hold.

The system keeps this counter-evidence, locates the plans depending on the shared-authentication hypothesis and hands them to the Planner for re-evaluation. It only shows that the evidence for reusing A's test needs revision; it cannot be used to claim B has no other problems.

Validation compares at least the original implementation, the implementation with reliability hardening, and the one that additionally adds falsifiable plans, to avoid crediting the gains of engineering fixes to the new mechanism. Focus on how often a refuted wrong hypothesis is still executed repeatedly, how wrong conclusions propagate forward, the replanning cost and the final effective output.

Persistence, transactions and evidence traceability are applications of mature engineering methods; falsifiable plans are an evolution idea relative to ARTEX, and no industry first is claimed on that basis.

## Suggested implementation order and acceptance

| Order | Scope | Key acceptance scenarios |
| --- | --- | --- |
| M0 first | Trace audit, definitions, fixed cases and config baseline | Errors can be located; insufficient data is clearly marked and proportions are never inflated |
| M1 foundational hardening | Completion-bypass protection, graph transactions and invariants, planning-reference schema and recovery | Write failures are never reported as success; plans and evidence can be recovered after rebuild, and late writes are rejected |
| M2 main architecture | Common observations, predicates, baselines, the HTTP channel, the four gates, logs and tiered presentation | Execution goes end to end with R05 common checks and the R02 read-only differential; prerequisite drift can be reviewed |
| M3 capability expansion | R02 expansion, R03 reachability, R01 review and R06 retest integration | Valid states are reached repeatably, invalidated evidence causes no wrong continued dispatch, reduction keeps the proof relationship |
| M4 separate promotion | Business counterexamples under sourced rules, cross-round capability of each route, then R04 validation | Every benefit has an independent control; capability chains never hold through unknown connections |
| Conditional branch | Evaluate a standalone controller for residual scheduling problems after the complete M2 mainline | Meets the architecture document's admission conditions, then proves an increment over the gated Planner |
| As deployment requires | Remote execution leases and targeted coverage matrices | A concrete scenario exists, and execution ownership, late results and condition differences can be handled |

Detailed version dependencies follow the [route plan](research-roadmap/README.md). Evaluation distinguishes four groups: the original implementation, M1 hardening, the gated Planner and the conditional standalone controller; a new controller cannot double-count gains the first three groups already obtained, and completing all six routes is not a prerequisite for starting it.

## External design references and adoption scope

| Reference | Mechanism worth borrowing | Choice in ARTEX |
| --- | --- | --- |
| [Cairn server protocol](https://github.com/oritera/Cairn/blob/main/docs/specs/server-protocol.md) | Facts and intents form a shared blackboard, decoupling planning from execution | The project already has a similar foundation; the focus is consistency of state and relationships |
| [PentestGPT architecture](https://github.com/GreyDGL/PentestGPT/blob/main/docs/architecture.md) | Deterministic code manages authoritative state, scope, execution and evidence, adding verification as goals require | Borrow the responsibility boundaries without porting its runtime framework wholesale |
| [LangGraph Functional API](https://docs.langchain.com/oss/python/langgraph/functional-api) | Checkpoint recovery, reuse of completed results, idempotency requirements in retries | Recovery semantics are designed separately from external side effects; this is no reason to change the Go stack |
| [OpenHands SDK design](https://github.com/OpenHands/docs/blob/main/sdk/arch/design.mdx) | Explicit state ownership and component interfaces, isolation capabilities used as needed | Keep the execution interface and choose local, container or remote environments based on actual needs |

These references support mechanism choices but cannot directly prove they raise success rates or lower costs in ARTEX. Concrete choices are based on control results from controlled tasks and long-term exploration.
