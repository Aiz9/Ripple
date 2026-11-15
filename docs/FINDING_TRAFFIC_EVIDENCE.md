# Multi-traffic evidence for findings

A finding's "Linked traffic" supports multi-select across pages, a role and note per item, ordering and unbinding. The traffic page can also multi-select records and link them to one existing finding in one go. Finding evidence inherited by a task is read-only; changes must be made in the source task.

The system setting "Agent automatic traffic binding" is off by default; it is read and changed through `agent_traffic_binding` on `/api/settings`. Turning it on increases token consumption from reviewing requests/responses, tool calls and prompts; the next agent round uses the new setting. When off, the automatic binding parameters and the backfill tool are hidden, no automatic-binding guidance is injected, and new automatic-binding submissions from already running sessions are rejected. Manual binding, traffic capture, reading saved evidence and exports are unaffected.

When on, the default flow is "finding recorded -> reporter agent triggered automatically -> traffic verified and bound -> report written against the latest evidence version". The reporting agent keeps the verification command, key output, real traffic IDs and their roles in `evidence`; the reporter agent combines the finding details and execution records, verifies with `traffic_search` / `traffic_get`, calls `bind_finding_traffic`, then reads the latest `version` and saves the report. With the switch off, the reporter agent gets no extra raw-traffic search/read tools and binds nothing automatically, but can still read manually bound snapshots and write reports.

Compatible with existing callers: `report_finding`'s `traffic_refs` / `evidence_hint_id` can still bind immediately and explicitly. Binding is optional: for non-HTTP findings such as TCP, or when nothing was captured or the exact record cannot be found, omitting references still allows reporting and report writing; keep other verifiable evidence such as command output and logs, and preferably explain why nothing is bound -- no new required field is added. Every submitted ID must be valid with a complete body. Any single failure rolls back the whole binding operation; when an explicit bind submitted with a report fails, the whole report is rolled back. Appending the same snapshot again adds no binding and does not overwrite the note.

## Agent IDs and report versions

`report_finding` gains an optional parameter; the array order is the initial evidence order:

```json
{
  "traffic_refs": [
    {"traffic_id": "real-traffic-ID", "role": "baseline", "note": "normal account request"},
    {"traffic_id": "another-real-traffic-ID", "role": "proof", "note": "reproduction request"}
  ]
}
```

Roles are `baseline` (normal control), `proof` (vulnerability proof), `verification` (additional verification) and `supporting` (supporting evidence, the default). Verify real records with `traffic_search` / `traffic_get` first; domain and time are only for filtering candidates and never imply task ownership.

The prompt follows [CyberStrikeAI's finding-reporting tool guidance](https://github.com/RuoJi6/CyberStrikeAI/blob/54d56774b8bd285817d16d48b70a4a5e6e0963f7/internal/app/vulnerability_tools.go), combined with this project's optional-binding convention, without adding a mandatory "reason for no capture" check. IDs must never be guessed, and probing again just to capture traffic should be avoided.

The first line of the return value is still `finding recorded: <exploration node ID>`; the JSON that follows provides the standalone finding record `finding_id`, the exploration node `finding_node_id` and a binding summary.

- `get_finding_traffic(finding_id)` uses the **standalone finding record ID** and returns the ordered list and `version`; passing `binding_id`, `side=request|response`, `offset` and `length` reads in segments of at most 8192 bytes each.
- `update_finding_report`'s `finding_id` **still uses the exploration node ID**. The new `evidence_version` carries the version actually read; if the evidence changes during generation the stale version is rejected and must be re-read and regenerated.
- When an older report call passes no version, it makes no claim to cover existing traffic evidence. After a binding, note, role or order changes, an existing report is flagged as needing an update.

With automatic binding on, `add_hint` / `add_task_hint` can store `traffic_refs` on a single hint or on each element of a batch `hints`. A planner reporting on someone's behalf can pass `evidence_hint_id` to pick the references from the corresponding hint in this task explicitly; inherited hints cannot be referenced. The system never guesses bindings from domain, time or browsing records. A failed submission creates no partial finding and does not trigger the report early.

When an existing finding is missing a binding, `bind_finding_traffic(finding_id, traffic_refs)` adds it without re-recording. `list_findings` / `list_task_findings` / `node_detail` / `get_task_node_detail` return explicit `finding_id` and `finding_node_id`; the old `id` keeps its exploration-node meaning.

At startup only optional properties are added to old tool schemas, the original default traffic tool bindings are extended to the reporter agent, and the backfill tool goes to the reporter agent by default. Custom binding lists, prompts, descriptions and enabled states are kept. Guidance is added uniformly after final tool assembly: the reporting role hands over existing evidence, and the reporter agent verifies, binds and writes the report. When a platform conversation lacks task context it should hand over to a task agent through a structured hint instead of reporting directly. Existing evidence should be handed over before a task is judged complete; nobody is forced to wait when there is no capture. A failed `report_finding` does not trigger the reporter agent.

## API

Base path: `/api/exploration/findings/{finding_id}/traffic`, using the standalone finding ID. Authentication is reused; `context_task` checks task visibility and inherited read-only status.

| Method / relative path | Request / response |
| --- | --- |
| `GET` | Ordered summary, evidence version, version adopted by the report |
| `POST` | `{"traffic_refs":[...]}` appends a whole batch |
| `PATCH /{binding_id}` | `{"version":1,"role":"proof","note":"note"}` |
| `DELETE /{binding_id}` | `{"version":1}` |
| `PUT /order` | `{"version":1,"binding_ids":["2","1"]}`, must be the complete list |
| `GET /{binding_id}` | Snapshot metadata and a bounded body preview |
| `GET /{binding_id}/body` | `side`, `offset`, `length`; `download=1` downloads the complete original bytes |

Version/order set conflicts and writes during archiving return `409`; writes to inherited evidence `403`; bindings that do not exist or do not belong to the finding `404`; traffic/attachment read and verification failures return explicit errors.

## Storage and migration

An idempotent PostgreSQL migration at startup adds `traffic_evidence_snapshots`, `finding_traffic_bindings`, and `findings.evidence_version` / `report_evidence_version` (default 0). Bindings are never guessed and backfilled from historical text.

A snapshot stores the original traffic ID, capture time, URL, method, status, request/response headers, body length and SHA-256. Bodies are stored by hash at `<data>/evidence/blobs/<first two chars>/<hash>.bin`, separate from the purgeable `data/traffic`, so several findings can share snapshots/bodies. Snapshots have no content-update API, and reads and exports fail when verification does not match.

The complete body is read under the original traffic write lock, including large body blobs and old directory records. Files are persisted and verified first, then the exploration node, intent relation, finding, snapshot and bindings are written in a single PostgreSQL transaction; the planner is notified only after commit. A failure may leave unreferenced files behind but never produces partial business records.

PostgreSQL advisory lock `7337741004` coordinates evidence files and SQL references; the task row lock forbids evidence changes once archiving is queued. Restore holds the evidence lock from body installation through metadata commit. Deleting a finding cascades to its bindings.

The cleaner runs hourly and reclaims only unreferenced content that is not part of an in-flight operation, after a delay of at least 24 hours. Normal traffic cleanup never touches the evidence directory. When backing up hot data, back up PostgreSQL and `data/evidence` together.

## Export and archiving

Markdown includes the ordered evidence list and version; JSON includes the metadata; CSV adds the count and binding IDs. `md-zip` keeps the finding Markdown and provides:

```text
evidence/<finding_id>/<binding_id>/
  manifest.json
  request.http
  response.http
  request.bin
  response.bin
```

Markdown references messages through relative links. Before the download is sent, attachment copying, hash verification, compression, disk sync and a CRC read check of every ZIP entry are completed; anything missing/corrupt fails the whole download. Complete attachments keep the original binary bytes.

Archive v3 collects snapshots and bodies through finding bindings, independent of the original traffic or domains. Hot data is cleaned only after the package is verified; shared evidence is kept. Restore verifies and installs bodies first, then restores metadata and bindings in a transaction, and supports retrying after failure. v1/v2 remain restorable, and missing new fields are explicitly set to 0.

## Verification and limits

Give each test package its own freshly created PostgreSQL test database via `ANDROIDLAB_PG_DSN`, so leftover task/model fixtures cannot trigger background runs. Run the related packages' full tests and confirm nothing is skipped because of missing configuration:

```sh
# Before each package, set ANDROIDLAB_PG_DSN to that package's own test database; an explicit configuration failure must error out.
go test ./<package> -count=1
go test -race -p 1 ./internal/evidence ./internal/db ./internal/agent ./internal/server -run 'TestEvidence|TestFindingTraffic|TestFindingEvidence|TestReportFindingAtomicContract|TestTaskArchive'
```

Front-end verification includes `npx tsc --noEmit`, Biome checks on the affected files, the Webpack build and the `NEXT_EXPORT=1` static export. Use a separate cache directory so a running development server is not overwritten.

Local end-to-end acceptance uses a separate port, controlled HTTP / domain HTTPS targets and a temporary data directory, covering both binding entry points, cross-page selection, ordering/notes, error messages, inherited read-only, downloads, and exporting, archiving, reclaiming hot bodies, restoring and verifying hashes after the original traffic is deleted.

The first version uses a global evidence coordination lock; during large binding/export batches or slow attachment downloads other evidence operations may wait. Evidence cannot be fabricated when recordings or complete bodies are missing. This feature does not change the capture switch and does not handle certificate problems when HTTPS targets an IP directly.
