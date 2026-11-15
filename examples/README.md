# Import templates

These files contain illustrative schemas, not test evidence. They use reserved `.invalid` hosts and do not contact any service.

- `openapi.json`: discover routes and declared authentication. Select the consuming asset when importing; an API contract does not establish runtime usage or security coverage.
- `coverage-report.json`: map an existing report into explicit security-property test records. Replace the context, roles, parameter names, observation dates, actual outcomes and evidence references. Its default outcome is `not_performed` to avoid claiming a test ran.

Import sources under **Assessments → Import source**. A prior report is never reusable merely because it mentions an endpoint. Review its actual evidence, then use **Evidence → Review applicability**. A reviewed record still cannot be reused for a different role, parameter set, environment, implementation revision, or an expired freshness window.
