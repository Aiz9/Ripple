# Android platform Logs

The **System → Logs** view receives backend standard logs and HTTP failures, Go panics, failed agent activities, Android runtime and API checks, browser exceptions/rejected promises/network failures, and launcher/subprocess diagnostics. Error details use the request ID where an HTTP request exists. Browser entries queue locally until authenticated delivery is available.

Logs are redacted before they enter the local journal, live stream, or database. The journal is stored at `data/logs/system.jsonl`; it restores across backend restarts and remains available when database persistence is delayed or unavailable. Launcher diagnostics use private atomic spool files in `data/logs/pending/` until the backend imports them. The Logs page paginates older journal/database entries; pausing freezes the displayed snapshot while capture continues.

The view's **Clear** action clears the current page only. It does not delete the local journal or database history. Do not treat a 4xx scope rejection as work performed: the status and rejection reason are logged, and the assessment does not store that evidence.

The capture boundary is the ARTEX backend, its launcher-owned child-process stderr, and browser errors reported by an authenticated session. External emulator/device processes are not owned or restarted by ARTEX. Details that never reach those channels (for example, an OS-level process kill with no stderr or a browser error before the app can start) cannot be recovered by the Logs view.
