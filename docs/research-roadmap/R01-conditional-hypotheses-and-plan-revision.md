# R01 Conditional hypotheses and plan revision

Route goal: reuse exploration conclusions only under the conditions that support them, and let counter-evidence trigger precise plan revision. Versions and modes follow the [shared experiment protocol](shared-experiment-protocol-and-evaluation.md).

Review positioning: joins the M0 audit early in observe mode; full revision plugs into the existing Planner in M3. M1 first designs plan-evidence and expected-output references; M2 first checks explicit dependency versions without waiting for full semantic conflict detection, and introduces no new controller.

## Derived from penetration-testing logic

A test that did not succeed may mean at least that the method does not apply, a prerequisite does not hold, the effect is not observable, or the issue genuinely does not reproduce under these specific conditions. Writing all of these up as "the target is not exploitable" closes routes prematurely; recording no negative results at all repeats the same tests.

So what should be stored is a conditional conclusion: under a given identity, object, business state, test method and observation capability, what was observed. Later tasks reuse knowledge within those conditions, not a global negation.

Positive hypotheses work the same way. Two endpoints may share an authentication mechanism -- that is only an explanation to be validated. If a plan relies on it and new evidence refutes it, the system should find the plans that depend on it instead of carrying on with the old rationale.

## What the original design already has, and what is added

[`internal/agent/planner.go`](../../internal/agent/planner.go) already requires reviewing weak negative evidence, limits re-checks of the same direction, redispatches when there is a materially new mechanism, and advances chains step by step with todos. [`internal/agent/tools.go`](../../internal/agent/tools.go) already stores confidence and the source relationship from facts to intents.

This route adds conditional conclusions, explicit decision evidence and a revision flow after evidence changes. It is more than persisting todos, and swapping the summary prompt does not count as a complete implementation.

## Core representation

| Record | Content to store |
| --- | --- |
| Raw observation | Actual output, time, context and evidence references, with history kept |
| Conditional conclusion | Assertion, applicability conditions, method used, observation capability, supporting and refuting evidence |
| Plan evidence | Which conclusions a todo or intent relies on, and the evidence version |
| Revision event | What change triggered review, which directions are affected, and how the Planner handles it |

Observation, interpretation and applicability are kept separate. For example, "user B was denied access to object X at a given moment" is a historical observation; "no user can access X" is an extra inference that cannot be drawn from that observation directly.

Only implemented assertions or human-confirmed counter-evidence can formally mark a piece of evidence invalid. Suspected conflicts raised by the model are first registered as review candidates; they do not change truth values, block execution or revoke goal proofs directly, and enter blocking review only through a registered rule or an explicit human decision. When a programmatic check finds a necessary condition unknown, it defers according to its own rules.

Review status belongs to the new protocol; new status strings must not be written directly into the existing exploration-node state enum.

## Decision and revision rules

1. Key plans state locatable evidence; several independent, sufficient sets of evidence are allowed.
2. New evidence is first compared on identity, object, state, method and environment conditions. Conclusions under different conditions do not automatically contradict each other.
3. For counter-evidence within the applicability conditions, locate the affected plans; if another independent set of evidence still holds, keep the plan and flag the change.
4. When all valid evidence is lost, or whether evidence applies cannot be confirmed, enter review and let the Planner choose to continue, modify, pause or abandon.
5. When reopening an already-tested direction, record the material change and the new validation goal, and control repeated execution with a budget under the same conditions.

Refreshing a token once is not necessarily a new mechanism; when the same subject, permissions and validity are unchanged there is no reason to retest. A login recovering from expired to valid, a changed role or tenant relationship, or a newly discovered required parameter may change the applicability of an old test.

Likewise, one denial response does not mean the route should be sealed forever. Reusing a negative conclusion requires checking its method, prerequisites and observation conditions; when information is missing it stays unknown.

## Minimal implementation and integration

V1 manually confirms context and evidence for a few key hypotheses only, links todos or intents through existing fact IDs, and observes which changes should trigger review. Condition matching and impact location are validated first; no full natural-language truth inference is attempted.

Later, evidence versions and review todos are stored in task-owned records, and [`internal/server/manager.go`](../../internal/server/manager.go)'s TriggerEvent and debounce are reused to wake the Planner. They serve as notifications; the existing in-memory events are not a durable dependency mechanism. Changes and pending-review records are committed first, and unprocessed items are scanned at startup or recovery, so a lost notification never loses a revision.

The dispatch and claim gates check the versions of referenced evidence. Required evidence in pending review cannot be treated as established; when other independent, sufficient evidence exists, execution continues by explicit rules. The model can only propose semantic conflicts and handling suggestions; it cannot fabricate machine counter-evidence or override invalidation results. Gate logs store the affected references, the rule applied and the actual decision.

Raw facts and revision history are kept, and source records of linked tasks remain read-only; a source task's conditions cannot be treated directly as this task's conditions. Observation-level context comes from common records and is never guessed and rebuilt from already-summarized, lossy details.

Uses R05's common validity predicates and baselines; when developed independently it can use a fixed implementation of the same protocol without waiting for every diagnosis strategy. Route switches and predicate decision authority are accepted separately.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R01-V1 | Link key conclusions to plan evidence, observe condition differences, human confirmation of semantic conflicts | Input/output examples, impact-location results, same-condition and different-condition fixtures; observe only, no automatic redispatch |
| R01-V2 | Persist evidence versions, multiple evidence sets and review todos; reuse triggers and implement recovery scans | Stale-write rejection, review after lost notifications and restart, dispatch and claim decision logs |
| R01-V3 | Reuse of conditional negative results, controlled reopening on material change, goal evidence review | Cross-round control evaluation, duplicate budget, review path when goal conclusions are affected |

V3 never deletes historical findings automatically and never cascades one possibly-conflicting semantic judgment into failure of all downstream goals. When the supporting or refuting relationship cannot be determined, the original evidence is kept and handed to review.

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R01-A | An expired session produces a negative observation; then a valid session is restored and the test prerequisites are met | The old negative does not seal off the new condition; a distinct review direction is generated |
| R01-B | The same valid identity only refreshes its token; other applicability conditions are unchanged | No repeated reopening because of an irrelevant version change |
| R01-C | A plan has two independent, sufficient evidence sets and one is refuted; a notification is lost, then a restart | The evidence that still holds is kept; when both fail, review is required, and recovery misses no todo |
| R01-D | Different tenants or environments produce opposite observations, plus a record with unclear conditions | Not misjudged as a same-condition contradiction; unclear conditions stay unknown |

## Validity basis and failure conditions

The benefit comes from limiting extrapolation of conclusions and handling invalidated evidence precisely, both of which can be judged on fixtures. The main metrics are fewer wrong continued dispatches, no missed legitimate reopenings, and the extra model and validation cost this incurs.

If label matching relies on unstable text similarity, if any environment change causes a full retest, or if conservative rules keep blocking directions the original implementation succeeded on, that version does not enter automatic execution.

The theoretical reference is [de Kleer's An Assumption-based TMS](https://www.dekleer.org/Publications/An%20Assumption-Based%20TMS.pdf): conclusions can be associated with the set of assumptions they depend on. This route borrows condition and evidence maintenance without introducing a full ATMS, and does not treat that theory's properties as a guarantee for LLM semantic judgments.
