# R02 Identity and object relationship differentials

Route goal: generate a small number of high-value experiments from explicit subject, object and permission relationships to validate real authorization boundaries. The first version focuses on read-only object access between authorized test accounts and uses the [shared experiment protocol](shared-experiment-protocol-and-evaluation.md).

Review positioning: the first end-to-end capability in M2, validating the four gates with two identities, pre-prepared controlled objects and the structured HTTP channel. Shares R05's predicate, observation and baseline facilities, builds no separate owner-control system, and does not depend on a new controller.

## Derived from penetration-testing logic

The core of authorization testing is not that some endpoint returns success, but that a subject who should not have a certain permission obtained a specified object or effect. You should know first who owns the object, who may share it and what state the operation is in, and only then compare different subjects.

Using controlled accounts and controlled objects each of them created reduces the noise of guessing whether an object exists. Having the owner prove the object exists first, then having another normally logged-in subject perform the same kind of operation, separates object problems, session problems and permission problems.

Differentials still need independent permission expectations. Public objects, shared files or collaborator relationships may legitimately allow cross-user access; a different owner or a similar response is never enough to report broken access control.

## What the original design already has, and what is added

[`internal/db/assets.go`](../../internal/db/assets.go) already supports Auth, Params and endpoint information; AuthItem's standard fields include credential type, username, password, token and notes, which can serve as execution input. Facts and evidence also already have recording paths.

What is added is the in-task relationship between subjects and objects, the source of permission expectations, a context-consistent experiment builder, and controls judged by semantic effect. It does not treat the credential array in generic assets as the target application's complete role and tenant model, nor does swapping a cookie count as innovation by itself.

## Data and experiment selection

| Record | Minimal content |
| --- | --- |
| Subject reference | Stable subject ID, confirmed role and tenant, session version and credential reference |
| Object binding | Actual object ID, creation or read evidence, ownership and sharing relationship, unique test marker |
| Permission expectation | Subject relationship, operation, object, business state, allow or deny and its independent source |
| Request recipe | Operation and parameter positions, subject injection, dynamic identifiers and token dependencies |
| Result assertion | Whether protected fields were read, or whether a specified business state change occurred |

Permission expectations can come from user-confirmed rules, verifiable business requirements or grey-box authorization config; rules proposed by the model start as hypotheses. A list that does not show an object, a field name that looks like "owner", or another user happening to receive a denial is never enough on its own to prove access should be forbidden.

Experiments are chosen by discovered relationship boundaries, such as same role with different owners, same operation with different roles, known different tenants, and private versus shared state. For each boundary a minimal experiment is generated first, instead of enumerating the full Cartesian product of subjects, endpoints and objects.

## Control and decision flow

1. Check the target scope, confirmed permission expectations and object bindings, and verify both subjects' login state.
2. Establish a normal control with the object owner, confirming the controlled object and its key fields really exist.
3. Request the same object and operation as the other subject, keeping conditions comparable and re-obtaining any CSRF or dynamic tokens for that subject.
4. Check the object's unique marker, protected fields or actual state change directly, redoing the normal control when needed to rule out state drift.
5. Only when the permission expectation, validity and violation effect all hold does it become a finding for that boundary; otherwise the output is normal denial, not reproduced, or undecidable.

When the subject changes, its associated tokens may have to change too; otherwise you may only be testing request-validation failure. Conversely, the owner's dynamic values and object context must not all be carried over to another subject without explanation, creating an unexplainable multi-factor change.

Response length, status code and text similarity can help with triage but cannot prove broken access control on their own. Field-level APIs support conclusions only about explicitly protected fields; returning public fields does not mean private content leaked. Write operations are judged by real effects and introduced only in a resettable environment.

## Minimal implementation and integration

Implement two test subjects, one controlled object type and one read-only assertion first. Subject sessions are resolved by reference by the structured HTTP executor; actual observations are saved first, then the summary and evaluation are registered through the write-back gate. Object mappings and identity-private state belong to the task and do not propagate just because assets are globally shared.

The owner control is registered as one use of the common baseline, bound to object, subject, state, permission rule and version. Session health and protected-marker matching are only local predicates; an actual violation requires the independent permission expectation, comparable conditions and the effect assertion together, and a model filling in "observed" cannot replace evaluation.

Separate sessions and prepared objects can isolate other experiments, but cross-identity permission comparisons still point at the same object under test. State operations by different subjects on the same object must be checked for shared-resource conflicts; different actors alone do not mean they can run in parallel.

Hooks into the experiment tool paths of [`internal/agent/tools.go`](../../internal/agent/tools.go) and [`internal/agent/worker.go`](../../internal/agent/worker.go), reusing the baseline, proof and verification evidence roles and version conventions in [`internal/agent/finding_workflow.go`](../../internal/agent/finding_workflow.go).

When a second valid identity, an object relationship or a permission rule is missing, the output lists the missing prerequisites and how to collect them; nothing is filled in by guessing. Common predicates are promoted capability by capability, and gate logs and reports show controls, rule sources, actual effects and reasons for undecidability together.

## Deliverables by version

| Version | Development scope | Acceptance artifacts |
| --- | --- | --- |
| R02-V1 | Two identities, a controlled object, an explicit private policy, HTTP read-only semantic assertions | End-to-end records through the four gates, raw controls and variants, object mapping, normal and vulnerable results, and reports |
| R02-V2 | Roles and tenants, sharing exceptions, dynamic objects, controlled write operations | Sparse experiment selector, session isolation, state reset and field-level counterexamples |
| R02-V3 | Wire business state and object lifecycle into permission experiments and output next-step suggestions | Integration with the R03 protocol, conditional result reuse, cross-round benefit and cost comparison |

V3 focuses on which relationship change is worth retesting, not on enlarging the enumeration. When a policy version or sharing relationship changes, applicability is re-checked instead of carrying an old private assumption forward.

## Minimal fixtures

| ID | Scenario | Expected result |
| --- | --- | --- |
| R02-A | Two users with the same role, a policy defining private objects, with a correct-denial version and a wrongly-allowing version | A violation is reported only when access is wrongly allowed and the protected marker appears |
| R02-B | The same object changes from private to legitimately shared, plus an always-public object | Judged by the real policy change; legitimate access is not treated as broken access control |
| R02-C | Expired session, wrong CSRF token, or a login page disguised as 200 | Judged an invalid or undecidable experiment; no security conclusion is output |
| R02-D | A cross-tenant object returns only public fields; another version additionally exposes protected fields | Distinguished by field and policy assertions, not just response similarity |

## Validity basis and failure conditions

The value of this route lies in validating permission relationships directly and removing the uncertainty from object guessing and invalid identities. Observe authorization-violation detection, false positives, false negatives and preparation cost; reporting only how many test combinations were generated is not acceptable.

If permission expectations come from model defaults, sessions cannot be isolated reliably, sharing exceptions are unclear or effects are unobservable, the conditions for automatically confirming vulnerabilities are not met. If preparing identities and objects costs more than it actually saves, narrow the scope to high-value operations.

[OWASP WSTG's IDOR testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References/) supports multi-user testing with known objects. [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) already has user, role, request and dynamic-dependency configuration. This route's increment is wiring relationship discovery, sparse selection, evidence judgment and plan feedback into ARTEX; those existing methods are not counted as new inventions.
