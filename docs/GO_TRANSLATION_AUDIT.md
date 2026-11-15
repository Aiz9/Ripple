# Go source translation audit

The Go-source pass covers ARTEX and its bundled `norma` module. Comments and runtime instructions/messages use English. A Unicode-aware source scan finds no literal Han characters in any `.go` file.

Legacy input aliases, provider error markers, historical migration fingerprints, and Unicode test fixtures retain their original runtime values through escaped literals. Translating those values would break backward compatibility or remove Unicode coverage. Stored user prompts and existing database content are preserved.

## Behavior and validation

The review policy retains its detailed allow/ask/deny rules. English verdicts require the same complete, strict JSON structure as legacy verdicts. Regression tests cover all three actions, code fences, missing sections, and legacy Chinese responses. English model-review prefixes are recognized alongside legacy ones.

The longer English summarizer exposed a context-budget rounding issue. Summary chunks now shrink at UTF-8 boundaries until the fully assembled request fits its existing budget. Existing long-history, overflow, and call-cap tests pass. Cancellation labels retain the existing 40-character limit.

Validation completed:

- Main module compilation and `go vet ./...` pass.
- An embedded-frontend executable builds and its `-h` smoke check passes.
- Selected suites: **779 top-level tests passed**, **219 skipped**, no failures in that selection.
- Seven existing experimental SDK compaction failures were reproduced in an isolated overlay restoring the original untranslated production strings; they were excluded from the passing selection.
- Full integration remains unverified: PostgreSQL is not configured for tests here, and the environment prohibits local socket listeners. Socket-dependent test files were excluded; production network/database behavior was not simulated as passing.

The seven baseline failures are `TestAdaptiveGrowthTracksTheWindow`, `TestSuppressionReleaseFitsInsideTheWindow`, `TestMostlyCompetentModelStaysBounded`, `TestLongSessionStaysBounded`, `TestLongSessionWithPartiallyCompliantModel`, `TestOverflowLearningIsWiredIn`, and `TestTierTwoIsUnreachableOnSmallWindows`.

Tests increase confidence but cannot prove identical behavior from every model after a natural-language translation.

## File inventory

Counts describe the Chinese-bearing tokens at the beginning of this pass, not remaining untranslated text. String counts include compatibility values and test data that are deliberately preserved.

| File | String literals | Comment tokens |
| --- | ---: | ---: |
| `internal/agent/assembly.go` | 0 | 1 |
| `internal/agent/blackboard_inheritance_test.go` | 1 | 0 |
| `internal/agent/cancelcause.go` | 34 | 0 |
| `internal/agent/capture.go` | 1 | 0 |
| `internal/agent/capture_usage_test.go` | 0 | 2 |
| `internal/agent/chat.go` | 0 | 11 |
| `internal/agent/coldgraph.go` | 0 | 1 |
| `internal/agent/coldgraph_test.go` | 0 | 2 |
| `internal/agent/compaction.go` | 5 | 9 |
| `internal/agent/constraints.go` | 4 | 0 |
| `internal/agent/deferred_test.go` | 2 | 0 |
| `internal/agent/finding_recorder.go` | 1 | 0 |
| `internal/agent/finding_recorder_test.go` | 1 | 0 |
| `internal/agent/finding_workflow.go` | 11 | 0 |
| `internal/agent/goals.go` | 2 | 13 |
| `internal/agent/insert_assets_test.go` | 0 | 8 |
| `internal/agent/mainagent.go` | 0 | 21 |
| `internal/agent/noa.go` | 1 | 11 |
| `internal/agent/planner.go` | 18 | 47 |
| `internal/agent/prompt.go` | 0 | 3 |
| `internal/agent/prompt_now_test.go` | 6 | 0 |
| `internal/agent/prompt_test.go` | 11 | 1 |
| `internal/agent/promptcatalog.go` | 0 | 7 |
| `internal/agent/provider.go` | 10 | 63 |
| `internal/agent/provider_quota_test.go` | 1 | 0 |
| `internal/agent/review_context_test.go` | 9 | 0 |
| `internal/agent/side_questions_test.go` | 1 | 0 |
| `internal/agent/terminalreason.go` | 37 | 0 |
| `internal/agent/terminalreason_test.go` | 15 | 0 |
| `internal/agent/toolcatalog.go` | 0 | 36 |
| `internal/agent/tools.go` | 133 | 107 |
| `internal/agent/tools_digest.go` | 3 | 3 |
| `internal/agent/tools_insert.go` | 88 | 28 |
| `internal/agent/tools_nil_store_test.go` | 1 | 0 |
| `internal/agent/tools_overview_test.go` | 1 | 0 |
| `internal/agent/worker.go` | 14 | 50 |
| `internal/agent/wrapup.go` | 5 | 27 |
| `internal/config/config.go` | 5 | 0 |
| `internal/db/activity_page_test.go` | 2 | 0 |
| `internal/db/asset_dsl.go` | 0 | 1 |
| `internal/db/asset_intercept.go` | 0 | 2 |
| `internal/db/asset_intercept_match.go` | 0 | 29 |
| `internal/db/asset_intercept_match_test.go` | 25 | 8 |
| `internal/db/assets.go` | 0 | 1 |
| `internal/db/assets_test.go` | 5 | 9 |
| `internal/db/chat_mentions.go` | 1 | 0 |
| `internal/db/companies.go` | 0 | 4 |
| `internal/db/company_scope.go` | 1 | 3 |
| `internal/db/company_scope_consistency_test.go` | 2 | 2 |
| `internal/db/company_scope_test.go` | 17 | 11 |
| `internal/db/config.go` | 0 | 25 |
| `internal/db/config_test.go` | 3 | 0 |
| `internal/db/constants.go` | 0 | 1 |
| `internal/db/db.go` | 0 | 33 |
| `internal/db/exploration.go` | 0 | 38 |
| `internal/db/exploration_test.go` | 2 | 1 |
| `internal/db/finding_assets.go` | 0 | 59 |
| `internal/db/finding_assets_test.go` | 17 | 22 |
| `internal/db/finding_retests.go` | 3 | 10 |
| `internal/db/finding_retests_test.go` | 4 | 0 |
| `internal/db/finding_traffic.go` | 0 | 5 |
| `internal/db/findings.go` | 0 | 48 |
| `internal/db/findings_test.go` | 17 | 1 |
| `internal/db/intent_delete_test.go` | 22 | 8 |
| `internal/db/intercept.go` | 2 | 1 |
| `internal/db/intercept_detail_test.go` | 4 | 0 |
| `internal/db/intercept_filter_test.go` | 1 | 0 |
| `internal/db/intercept_seed_test.go` | 2 | 7 |
| `internal/db/llmretry.go` | 0 | 13 |
| `internal/db/llmretry_test.go` | 0 | 2 |
| `internal/db/nkey.go` | 0 | 6 |
| `internal/db/notification.go` | 4 | 108 |
| `internal/db/notification_delivery.go` | 0 | 84 |
| `internal/db/notification_test.go` | 126 | 81 |
| `internal/db/settings.go` | 0 | 4 |
| `internal/db/settings_insert_test.go` | 3 | 4 |
| `internal/db/side_questions.go` | 1 | 0 |
| `internal/db/task_archives.go` | 1 | 0 |
| `internal/db/task_archives_restore.go` | 1 | 0 |
| `internal/db/task_assets.go` | 1 | 0 |
| `internal/db/task_assets_context.go` | 0 | 1 |
| `internal/db/task_assets_test.go` | 4 | 0 |
| `internal/db/task_context.go` | 0 | 2 |
| `internal/db/task_context_unit_test.go` | 1 | 0 |
| `internal/db/task_intercept.go` | 0 | 1 |
| `internal/db/task_scope.go` | 0 | 7 |
| `internal/db/tasks.go` | 3 | 24 |
| `internal/db/tasks_test.go` | 8 | 2 |
| `internal/db/tools.go` | 0 | 2 |
| `internal/db/triggers.go` | 0 | 5 |
| `internal/enrich/enrich.go` | 0 | 1 |
| `internal/evidence/store.go` | 5 | 0 |
| `internal/guard/guard.go` | 5 | 3 |
| `internal/intercept/intercept.go` | 23 | 0 |
| `internal/intercept/prompt.go` | 4 | 0 |
| `internal/intercept/prompt_test.go` | 21 | 0 |
| `internal/intercept/retry.go` | 4 | 0 |
| `internal/intercept/retry_test.go` | 1 | 0 |
| `internal/intercept/review_context.go` | 1 | 0 |
| `internal/intercept/review_context_test.go` | 14 | 0 |
| `internal/intercept/trace.go` | 1 | 0 |
| `internal/intercept/trace_test.go` | 2 | 0 |
| `internal/llmpool/health.go` | 0 | 2 |
| `internal/llmrec/llmrec.go` | 0 | 6 |
| `internal/mcphttp/client.go` | 0 | 3 |
| `norma/harness/settlement_test.go` | 8 | 0 |
| `norma/harness/timeout_settle_test.go` | 8 | 0 |
| `norma/noa/archive.go` | 4 | 0 |
| `norma/noa/compress_test.go` | 2 | 0 |
| `norma/noa/edge_test.go` | 4 | 0 |
| `norma/noa/fuzz_test.go` | 4 | 0 |
| `norma/noa/nudgetext_test.go` | 1 | 0 |
| `norma/noa/prune_test.go` | 2 | 0 |
| `norma/noa/tokenize_test.go` | 4 | 0 |
| `norma/noa/types.go` | 0 | 1 |
| `norma/noaadapter/identity.go` | 0 | 1 |
| `norma/noaadapter/longsession_test.go` | 1 | 0 |
| `norma/noaadapter/project_test.go` | 1 | 0 |
| `norma/noaadapter/tierchain_test.go` | 2 | 0 |
| `norma/tool/deferred.go` | 0 | 1 |
| `norma/tool/shell_session.go` | 4 | 1 |
| `norma/tool/shell_session_test.go` | 0 | 1 |
| `norma/tool/shell_tools.go` | 46 | 6 |
| `norma/tool/task.go` | 3 | 0 |
| `internal/notify/channel.go` | 0 | 44 |
| `internal/notify/channels_test.go` | 85 | 31 |
| `internal/notify/dingtalk.go` | 0 | 32 |
| `internal/notify/email.go` | 0 | 44 |
| `internal/notify/email_test.go` | 35 | 40 |
| `internal/notify/event.go` | 0 | 23 |
| `internal/notify/feishu.go` | 0 | 28 |
| `internal/notify/filter.go` | 0 | 32 |
| `internal/notify/filter_test.go` | 45 | 9 |
| `internal/notify/html.go` | 0 | 13 |
| `internal/notify/http.go` | 0 | 74 |
| `internal/notify/http_test.go` | 21 | 16 |
| `internal/notify/markdown.go` | 0 | 52 |
| `internal/notify/mask.go` | 0 | 76 |
| `internal/notify/mask_test.go` | 49 | 51 |
| `internal/notify/notify.go` | 0 | 25 |
| `internal/notify/pack_test.go` | 39 | 27 |
| `internal/notify/redact_test.go` | 26 | 33 |
| `internal/notify/render.go` | 0 | 41 |
| `internal/notify/render_test.go` | 31 | 20 |
| `internal/notify/sign_test.go` | 10 | 10 |
| `internal/notify/ssrf_test.go` | 16 | 45 |
| `internal/notify/telegram.go` | 0 | 26 |
| `internal/notify/webhook.go` | 0 | 33 |
| `internal/notify/webhook_template_test.go` | 13 | 24 |
| `internal/notify/wecom.go` | 0 | 17 |
| `internal/report/fence_test.go` | 2 | 2 |
| `internal/report/findings.go` | 0 | 14 |
| `internal/report/findings_regression_test.go` | 9 | 0 |
| `internal/report/report.go` | 0 | 2 |
| `internal/selfupdate/bootstrap.go` | 35 | 48 |
| `internal/selfupdate/github.go` | 9 | 19 |
| `internal/selfupdate/selfupdate.go` | 1 | 48 |
| `internal/selfupdate/selfupdate_test.go` | 49 | 34 |
| `internal/selfupdate/stage.go` | 31 | 30 |
| `internal/server/assembly.go` | 9 | 2 |
| `internal/server/assets.go` | 0 | 1 |
| `internal/server/assets_scope_test.go` | 2 | 0 |
| `internal/server/auth.go` | 2 | 13 |
| `internal/server/auth_test.go` | 13 | 6 |
| `internal/server/chat_llm_resolve_test.go` | 0 | 1 |
| `internal/server/chat_mentions.go` | 9 | 0 |
| `internal/server/chat_mentions_test.go` | 29 | 0 |
| `internal/server/chatupload.go` | 0 | 4 |
| `internal/server/constraints_api.go` | 0 | 11 |
| `internal/server/conversations.go` | 1 | 7 |
| `internal/server/core_test.go` | 1 | 0 |
| `internal/server/customtool.go` | 1 | 18 |
| `internal/server/dto.go` | 0 | 24 |
| `internal/server/engine.go` | 36 | 90 |
| `internal/server/engine_emptyturn_test.go` | 38 | 6 |
| `internal/server/engine_timeout.go` | 9 | 19 |
| `internal/server/finding_filename_test.go` | 2 | 0 |
| `internal/server/finding_retests.go` | 2 | 0 |
| `internal/server/finding_retests_test.go` | 8 | 0 |
| `internal/server/finding_traffic.go` | 1 | 0 |
| `internal/server/finding_traffic_test.go` | 2 | 0 |
| `internal/server/finding_workflow.go` | 4 | 0 |
| `internal/server/finding_workflow_test.go` | 5 | 0 |
| `internal/server/findings_groups.go` | 0 | 3 |
| `internal/server/findings_groups_test.go` | 1 | 0 |
| `internal/server/goals.go` | 4 | 11 |
| `internal/server/goals_api.go` | 0 | 16 |
| `internal/server/intercept.go` | 0 | 2 |
| `internal/server/intercept_detail_test.go` | 2 | 0 |
| `internal/server/intercept_filter_test.go` | 2 | 0 |
| `internal/server/intercept_live_test.go` | 13 | 0 |
| `internal/server/intercept_retry_test.go` | 2 | 0 |
| `internal/server/intercept_review_test.go` | 3 | 0 |
| `internal/server/llmpool.go` | 4 | 5 |
| `internal/server/llmpool_test.go` | 0 | 1 |
| `internal/server/llmretry.go` | 0 | 21 |
| `internal/server/llmretry_test.go` | 0 | 2 |
| `internal/server/manager.go` | 6 | 43 |
| `internal/server/mcpdiscover.go` | 3 | 0 |
| `internal/server/mgmt_test.go` | 2 | 0 |
| `internal/server/notifier.go` | 16 | 131 |
| `internal/server/notify_api.go` | 0 | 40 |
| `internal/server/notify_api_test.go` | 132 | 102 |
| `internal/server/orchestration.go` | 59 | 98 |
| `internal/server/parsetarget_test.go` | 0 | 7 |
| `internal/server/platform_tools.go` | 15 | 3 |
| `internal/server/scheduler.go` | 6 | 1 |
| `internal/server/server.go` | 15 | 175 |
| `internal/server/server_mgmt.go` | 7 | 35 |
| `internal/server/skill_upload_test.go` | 33 | 6 |
| `internal/server/skill_zip.go` | 0 | 10 |
| `internal/server/sync_scopesentry.go` | 0 | 7 |
| `internal/server/task_archive_package.go` | 1 | 3 |
| `internal/server/task_archive_package_test.go` | 0 | 1 |
| `internal/server/task_control.go` | 0 | 8 |
| `internal/server/task_intercept.go` | 0 | 5 |
| `internal/server/task_llm.go` | 2 | 46 |
| `internal/server/task_llm_test.go` | 1 | 0 |
| `internal/server/task_metadata_test.go` | 1 | 0 |
| `internal/server/task_templates_test.go` | 3 | 0 |
| `internal/server/trigger_merge_test.go` | 6 | 2 |
| `internal/server/triggers.go` | 0 | 1 |
| `internal/server/update.go` | 3 | 49 |
| `internal/server/update_test.go` | 15 | 14 |
| `internal/server/webui_embed.go` | 0 | 1 |
| `internal/server/workspace.go` | 0 | 1 |
| `internal/sidequestion/context.go` | 13 | 0 |
| `internal/sidequestion/context_test.go` | 5 | 0 |
| `internal/sidequestion/request.go` | 3 | 0 |
| `internal/sidequestion/service.go` | 3 | 0 |
| `internal/sidequestion/sidequestion_test.go` | 1 | 0 |
| `internal/traffic/evidence.go` | 1 | 0 |
| `internal/traffic/reclaim_test.go` | 24 | 2 |
| `internal/traffic/traffic.go` | 72 | 5 |
| `internal/traffic/traffic_store_test.go` | 57 | 0 |
| `internal/traffic/upgrade_test.go` | 20 | 10 |
