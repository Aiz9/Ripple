# R05 Test validity and discriminating experiments

Common capability goal: distinguish "the target condition was never tested" from "it did not reproduce under valid conditions", and restore a decidable state through budgeted diagnosis. The R05 number is kept for independent evaluation, but it is built as a predicate, validity and diagnosis module shared by every route; the protocol is in [shared experiment protocol and evaluation](shared-experiment-protocol-and-evaluation.md).

Implementation positioning: M0 starts with trace auditing and read-only labeling, and M2 takes it through the four gates together with the first version of R02. Passive checks and active discrimination are delivered and measured separately; no separate control loop is built for this capability.

## Derived from penetration-testing logic

Receiving a denial or error response cannot be read directly as "the system has no vulnerability". The request may have used an expired session, the wrong object or an invalid business state, or the result may simply be unobservable through the current channel.

A valid negative conclusion must at least show that normal requests still work, the test prerequisites hold, the method applies, and the effect it tries to verify can actually be seen. Whatever cannot be confirmed in a black box must stay unknown.

When the cause of a failure is unclear, the next request should prioritize discriminating between explanations. For example, checking the current identity with a known-good object, then checking whether the object exists as its owner, gradually separates session problems, resource problems and permission denials. That is more informative than cycling through test variants.

## What the original design already has, and what is added

[`internal/agent/retester.go`](../../internal/agent/retester.go) already requires outputting inconclusive when prerequisites are insufficient and requires a normal control before judging fixed; [`internal/agent/planner.go`](../../internal/agent/planner.go) already requires reviewing weak negative conclusions.

The added mechanism generalizes these principles into checkable records in the experiment interface, maintains validity and candidate causes during actual testing, and lets several workers share bounded diagnosis results by context version. It no longer relies only on a final natural-language summary to remind the model.

Machine checks must use registered inputs, observation requirements and oracle versions; the model's cause labels have suggestion authority only. A single status code or the model filling in "observed" is not enough to confirm a valid login, a working method or the absence of a problem.

## Decision and discrimination mechanism

| Content | Handling |
| --- | --- |
| Experiment prerequisites | Declare the required identity, normal baseline, object state, observation channel and method conditions |
| Actual evidence | Reference real controls and experiment results, and check whether the context is consistent |
| Failure explanation | Store candidate causes and supporting evidence; a status code alone cannot pin down a unique cause |
| Next discrimination | Choose the minimal in-scope request that can distinguish candidate causes at low cost |
| Final result | A conclusion is formed within valid conditions; with insufficient prerequisites it is undecidable, never written up as safe or fixed |

There is no need to fabricate probability distributions. V1 can use an explicit set of causes, a check order and a table of expected results; the set shrinks only when an observation genuinely rules out a candidate explanation.

## Key check logic

Session checks use the smallest operation that is known to require the identity and has an unambiguous semantic result. A public health page returning 200 only supports a transport-level judgment; a login page disguised as 200 cannot prove the identity is valid.

"Object does not exist" and "no permission" may both return 404. Distinguish them with a valid control from the object's owner; when they still cannot be distinguished, keep several causes and do not infer details of the permission implementation.

Normal controls can run before and after an experiment batch, or when a session or state changes, and are cached per context version. The cache cannot be reused across subjects, tenants or incompatible states, nor considered equally valid just because requests within a short time look similar.

The server may revoke a session or change state without a local version event, so the cache also needs a re-check deadline and abnormal-invalidation rules. The same context number does not mean health state can be reused forever; deadlines and re-check cost are set on fixtures.

Session health, R02's owner controls and R03's normal flows all use the common baseline's storage, references and invalidation mechanism, while each keeps its own purpose, conditions and oracle; they never substitute for one another, and three copies of raw observations are never stored. Diagnosis requests still run through the existing dispatch, claim and authorization paths; preparation cost cannot be hidden inside the baseline subsystem.

If normal functionality suddenly breaks after an experiment, it may be an environment change or a real defect triggered by this experiment. Keep the change as an independent lead; the current experiment suspends its conclusion first, then the cause is determined in a resettable environment -- it is never discarded wholesale as noise.

Experiments lacking echo or an external observation channel do not automatically get a negative conclusion. Black-box checks declare only the level of validity they can actually establish and cannot claim to have reached some internal code branch.

## Minimal implementation and integration

First read normal controls, errors and summaries from saved execution traces to form structured labels, and compare them with independent evaluation results. V1 sends no requests to the target and does not intercept existing free exploration.

V2 provides the experiment interface with prerequisite declarations, common predicates, baseline references and a discrimination budget; results enter the existing fact and evidence paths through the write-back gate. When a prerequisite cannot be fixed, an explicit blocking reason is returned, with no endless login refreshes, network retries or repeated object creation.

Every checker ships with gate decisions and sample reports showing the current conclusion eligibility, invalidation reasons and unchecked conditions. The new four-valued experiment results are presented through an adapter and do not directly replace the existing three-valued retest verdict. Automatic decision authority is promoted per predicate type; turning R05 on as a whole does not mean trusting every diagnosis rule.

Integration points are [`internal/agent/worker.go`](../../internal/agent/worker.go), [`internal/agent/tools.go`](../../internal/agent/tools.go), [`internal/server/engine.go`](../../internal/server/engine.go) and the existing execution records, with standalone retest conclusion boundaries as a reference. This mechanism does not cover arbitrary tool calls not wired into the experiment protocol.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R05-V1 | Trace audit, prerequisite table, predicate contracts, candidate causes and counterexamples | Decidable and missing samples kept apart; observe only, no claimed actual execution savings |
| R05-V2 | Common validity predicates, baselines and budgeted discrimination experiments | Passive checks and active recovery validated separately, gate logs and reports delivered, every extra request recorded |
| R05-V3 | Health state reused across workers and invalidated on context change | Concurrency and state-drift fixtures, cache boundaries, control results showing reduced duplicate diagnosis |

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R05-A | An expired session returns a 200 with a similar page structure | The normal control is recognized as failing; neither "not found" nor "fixed" is output |
| R05-B | A missing object and a normal permission denial both return 404 | Distinguished through a controlled owner control; stays unknown when evidence is insufficient |
| R05-C | Normal before the experiment, state pollution or a service error afterwards | The change and an independent lead are recorded; the invalidated baseline is no longer used to explain later results |
| R05-D | The operation may be effective but the existing channel cannot observe the effect | Outputs undecidable, avoiding treating no echo as no effect |

## Validity basis and failure conditions

The main benefit is fewer invalid experiments recorded as security conclusions, and faster recovery of decidable test conditions. Detection of real problems, the decidable proportion and extra cost must be examined together; nice false-positive numbers cannot be obtained by marking everything undecidable.

If the identity or state needed by the normal control and by the vulnerability test are incompatible, or a diagnosis loop consumes more budget without restoring valid testing, limit that checker's scope and fall back to suggestion mode.

[RESTler's FAQ](https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/FAQ.md) documents authentication or backend state anomalies during testing invalidating large numbers of requests, supporting the motivation for continuous validity checks. [AuthMatrix's documentation](https://github.com/SecurityInnovation/AuthMatrix) also lists invalid sessions as a source of false positives. Both support that the failure mechanism is real; the benefit of the autonomous discrimination flow is validated by ARTEX fixtures and paired experiments.
