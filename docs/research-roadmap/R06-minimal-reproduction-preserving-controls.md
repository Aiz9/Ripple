# R06 Minimal reproduction preserving controls

Route goal: turn a discovered problem into a minimal necessary experiment that preserves the original proof relationship and reproduces in an independent environment, for use in later fix verification. Reduction follows the [shared experiment protocol](shared-experiment-protocol-and-evaluation.md) and does not chase the shortest request for its own sake.

Review positioning: advances with M3's existing retest and evidence workflow, reusing common baselines, machine predicates and the execution channel, without waiting for the other routes to finish and without building separate reporting or control loops.

## Derived from penetration-testing logic

A problem appearing in a long session does not mean handing over its last request will reproduce it. Necessary conditions may include object creation, a specific identity, a business state change or a prerequisite token, while other requests may be completely irrelevant.

Reduction should remove unnecessary content while preserving the original vulnerability's causal and permission relationships. If removing an identity field only yields a different error page, or switching objects reads public data, the response may still be anomalous but the original proof is not preserved.

So every reduction step must check the normal control, the original violation effect and key semantic conditions together. When the environment cannot repeat reliably, stop first instead of compressing an incidental result into a deceptively clean PoC.

## What the original design already has, and what is added

The existing evidence facilities store snapshots and versions, the reporter agent can verify evidence, and the standalone retest agent already requires minimal targeted verification. These mechanisms are in [`internal/evidence/store.go`](../../internal/evidence/store.go), [`internal/agent/finding_workflow.go`](../../internal/agent/finding_workflow.go) and [`internal/agent/retester.go`](../../internal/agent/retester.go).

What is added is an automatic reducer with explicit constraints, and an executable reproduction experiment formed from its result. It is more than adding another reporting or review agent.

## Conditions that must be preserved during reduction

| Condition | What is verified |
| --- | --- |
| Normal control | Operations that were allowed still produce the expected normal effect |
| Original violation assertion | The same kind of protected data or business effect is still observed |
| Subject and relationships | Identity, role, tenant, object ownership and permission expectations stay comparable |
| Necessary prerequisites | Dynamic identifiers, tokens, state and observation channel still hold |
| Independent reproduction | Can start from the declared initial state without relying on undeclared session leftovers |

New object IDs and sessions may be generated in a new fixture, but their correspondence and semantic conditions must be preserved. The same response code, the same anomalous string or still producing some 500 is not enough to prove it is still the original problem.

## Reduction flow

1. Read the original evidence, the actual execution trace and the explicit vulnerability assertion, and list the semantic conditions that cannot be removed.
2. Validate the original experiment and the normal control in a resettable environment to establish a repeatable baseline; if the original experiment cannot be reproduced, diagnose first instead of starting automatic reduction.
3. First try removing sequence fragments unrelated to the goal, then reduce independently removable parameters and structured fields. Object producer and consumer dependencies must be considered together.
4. Each candidate runs from a clean, comparable state and is accepted only when the normal control and the original violation assertion are both satisfied.
5. Within the budget, output the currently validated reduction, the preserved conditions and anything unresolved, without promising a global minimum.

Fields such as signatures, CSRF tokens and object creation cannot be handled by arbitrary string deletion. Parse and rebuild or regenerate the necessary dynamic values; when the protocol is not supported yet, protect that structure. Asynchronous, cached and probabilistic results need extra repeatability design and are not treated as deterministic oracles by default.

The original evidence stays unchanged; a reduced experiment is a new derived record carrying its source and evidence version. Redacted presentation is kept apart from the original evidence; a rewritten message can no longer be claimed to be the actual request.

## Minimal implementation and integration

V1 reads one clearly judged HTTP or small-sequence case, has a human confirm the conditions that cannot be removed, and produces reduction candidates offline. Candidates that were not re-executed are explicitly marked unvalidated and do not update the finding's conclusion.

V2 adds the oracle and dependency-aware reduction on a resettable fixture. When a write or state recovery is uncertain, the normal control fails or the evidence version changes, new candidates are no longer accepted and the validated records are kept.

Structured HTTP requests and small flows are supported first, reusing session, object-dependency and normal-control records. Evidence from other channels is judged by source and verifiability; without a reliable parser and effect oracle, the original structure is protected and suggestions are kept, never blindly deleting commands or fields.

Report updates reuse the existing evidence_version check. V3 can hand the reproduction recipe to the existing standalone retest path, but a single failure of the reduced recipe to reproduce cannot automatically mean fixed; the original trigger conditions, a comparable environment and the normal control must be checked.

Reduction runs also go through the common admission, write-back and completion rules, recording the basis for accepting or rejecting each candidate. Reports provide the original proof, the validated reduction and remaining conditions together; the experiment's not_reproduced and the existing retest verdict are stored separately.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R06-V1 | Explicit vulnerability assertion, locked protected conditions, structured reduction candidates | Differences between original and candidates, conditions that cannot be removed, unvalidated markers |
| R06-V2 | Control-preserving reduction in a resettable environment, sequence dependencies and budget | Real results of every candidate step, an independent reproduction experiment, semantic-fidelity counterexamples |
| R06-V3 | Store reproduction recipes and hook into retests and regression versions | Reproduction with new sessions and new controlled objects, controls against fixed and interfering versions, historical evidence traceability |

Re-running a reduction against a real target must keep the task's original scope and operating constraints. The first automatic reduction rounds are validated only in test environments with reset capability; without it, suggestion mode is kept.

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R06-A | A request has many irrelevant fields, but the subject, object and one key input must stay | After removing redundancy the same violation assertion and normal control still hold |
| R06-B | Removing the identity condition leads to a different page with the same status code | The candidate is rejected; page similarity does not count as reproducing the original vulnerability |
| R06-C | Triggerable only after object creation and a state change complete; extra queries can be removed | Producer/consumer and state dependencies are kept and a complete reproduction recipe is generated |
| R06-D | Environment drift, an intermittent result or a failed reset, with the original evidence version updated separately | Exit reduction or re-check; a single failure never marks it fixed or overwrites a new report |

## Validity basis and failure conditions

The reduction mechanism follows [The Debugging Book's Delta Debugging](https://www.debuggingbook.org/html/DeltaDebugger.html): remove part of the input, then check whether the original failure condition still holds. This route adds joint constraints of permission relationships, normal controls and business effects, avoiding treating any anomaly as the same problem.

The main benefits are more reliable independent reproduction, clearer necessary conditions and more accurate fix verification. The extra requests and reset cost of reduction must be reported; a shorter message cannot be counted directly as improved discovery capability.

If the oracle only matches status codes, object and permission relationships cannot be guaranteed, the original experiment is not repeatable or recovery leaves residue, automatic reduction is not performed. For those scenarios the complete evidence and a manual reproduction path are kept.
