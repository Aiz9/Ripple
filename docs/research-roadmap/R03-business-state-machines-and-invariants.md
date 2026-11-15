# R03 Business state machines and invariants

Route goal: first build repeatable state preparation and dynamic dependency extraction so the system reaches real business states; then, when independent rules exist, validate flow invariants. The first version targets resettable Web/API test flows and uses the [shared experiment protocol](shared-experiment-protocol-and-evaluation.md).

Review positioning: M3 delivers the V1 reachability infrastructure, and M4 validates the V2 counterexample capability according to rule sources. State preparation needs no prior proof of business rules and no new controller; the two kinds of benefit are evaluated separately.

## Derived from penetration-testing logic

Many business features depend on prerequisite objects, tokens and states. Requesting a later endpoint directly and getting a failure may only mean no object was created, a previous step was not submitted or an expired identifier was used; the later business boundary was never effectively tested.

A penetration test should first master one normal successful flow, then propose counterexamples to explicit rules. For example, if a controlled document must be submitted and approved before it can be published, change one prerequisite step, the order or the state at a time and observe the actual publishing result.

Observing a certain normal order does not prove the order must be followed. Only business requirements, user confirmation or grey-box rules can support constraints that must hold; otherwise anomaly candidates are recorded first, and different paths are not judged vulnerabilities directly.

## What the original design already has, and what is added

The existing Planner can already dispatch dependent steps serially with todos, and workers can perform multi-request operations during free exploration. That solves part of the execution-order problem.

V1 explicitly stores the business state under test, dynamic dependencies between requests and the reset method; V2 builds on it by adding sourced security invariants to construct comparable counterexamples. Dependencies between scheduled intents and the target application's own business state are two different layers.

Related integration points: [`internal/agent/planner.go`](../../internal/agent/planner.go), [`internal/agent/worker.go`](../../internal/agent/worker.go) and [`internal/traffic/traffic.go`](../../internal/traffic/traffic.go).

## State and invariant representation

| Record | Content to store |
| --- | --- |
| State instance | Test subject, controlled object, actual state fields or observable business facts |
| Operation transition | Pre-state, call, dynamic data sources, expected post-state and evidence |
| Security invariant | Rule, applicability conditions and independent source needed by V2; not required by V1 |
| Reset recipe | Explicit operations or an environment snapshot needed to restore a clean state |
| Counterexample sequence | Steps changed relative to the normal sequence and the expected violation effect |

A normal flow only proves certain states are reachable; it does not automatically prove every other path is illegitimate. Asynchronous jobs need an independent completion observation and a wait limit; HTTP 200, "request accepted" or a success message in the UI cannot replace the actual post-state.

For example, a rule could be "a controlled document without an approval record must not reach the published state". The experiment oracle reads the actual published state and approval link instead of just matching the publish endpoint's text.

## Generation and execution flow

1. Extract one successful flow from normal traces, documentation or available specs, and validate the producer/consumer relationships of dynamic identifiers.
2. Bind subject, object, actual post-state and reset recipe, and reach the state repeatedly; register the normal flow in the shared baseline. V1 delivery ends here.
3. With independent rules, enter V2: define observable invariants, then study one change such as a skipped step, local reordering or repetition.
4. Run the control and variant from a clean, comparable state, judging by actual business effect rather than a single response code.
5. Without rules, keep the reachable state and anomaly candidates; an invalid prerequisite affects only that experiment and never implies the whole feature is safe.

Limit depth and the number of changes first. When creating a prerequisite resource fails, fix the dependency first instead of appending many requests that are bound to be invalid; explicit failure states must also be distinguished from unobservable post-effects.

## Minimal implementation and integration

The first version has a human confirm one small flow, its parameter dependencies, an observable end state and the reset recipe. The structured HTTP executor is reused to extract object identifiers from real responses; the normal flow shares the baseline foundation with R02/R05, and every step's observation and failure position are kept, without first building a general business-modeling platform.

API specs can help generate requests; without specs, start from an actual successful trace. A successful control validates reachability but cannot independently prove an order must be followed. Rules can come from public requirements, user confirmation or grey-box config and do not require reading source code; with no rule source at all, business violations are not judged automatically, and the model must never write in limits that OpenAPI does not declare.

Automatic counterexample generation for supported operations comes after V2. Versions that change state need a resettable environment; when a write is uncertain, an async job has not finished or recovery fails, later controls stop and the reason and records are kept.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R03-V1 | Single flow, dynamic dependencies, state preparation and reset; no business invariants required | Repeatably reachable real states, baseline references, invalid-dependency and reset fixtures |
| R03-V2 | Bounded step-skipping, reordering, repetition and effect judgment under sourced invariants | Normal and violating controls, staying a candidate when rules are missing, full execution and preparation cost |
| R03-V3 | Subject and object lifecycle changes, linked with R02 permission relationships | Cross-condition flow records, re-preparation after dependency failure, branch budget and combination evaluation |

Concurrency/timing tests are not a default V1/V2 capability. If race conditions are studied later they need their own controllable scheduling, repeatability and state-judgment design; random concurrent requests are no substitute.

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R03-A | Document draft, submit, approve, publish, with a correct-rule version and a version missing a prerequisite check | Invariants are validated after reaching the real state; the missing check is identified and the correct implementation is not flagged |
| R03-B | Creating the object fails in an earlier step, and later requests all error | The dependency is judged invalid; not reaching the business state does not count as a completed test |
| R03-C | Legitimate optional steps and equivalent normal flows | Order differences not required by any rule are not judged vulnerabilities |
| R03-D | Asynchronous state update and one failed reset | Judged by the real post-state; outputs undecidable when a stable control is impossible |

## Validity basis and failure conditions

V1 is accepted on reachability of valid states, repeated success, correctness of dynamic dependencies and preparation cost; V2 additionally evaluates violation detection, false positives/negatives and variant cost under sourced rules. The two kinds of benefit are reported separately, and sequence length is not a depth metric.

When the source of business rules is unclear, state preparation can still be provided but stays at V1 without promoting violation conclusions. When the actual state is unobservable, resets leave residue or sequence cost runs out of control, narrow the supported flows; failed preparation must never count as effective coverage.

[RESTler](https://github.com/microsoft/restler-fuzzer) already implements request producer/consumer dependency analysis and stateful testing and can serve as an engineering reference; [OWASP WSTG's workflow circumvention testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/06-Circumvention_of_Work_Flows/) explains that business rules and flow misuse must be considered per application. ARTEX's added design drives state preparation from facts and traces, uses sourced invariants as the oracle, and feeds results back into continuous exploration.
