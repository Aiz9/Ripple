// Package db is ARTEX's PostgreSQL source, replacing the old single-file SQLite graph.
// It opens connections, applies schema, and seeds built-in agents and variable catalogs.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns stays well below PostgreSQL's usual max_connections=100 but above nested
// connection depth: startup holds the schema advisory lock while seedBuiltins borrows another
// connection, so this limit must not cause self-deadlock.
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ANDROIDLAB_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql otherwise opens unlimited new connections until PostgreSQL rejects them
	// at max_connections, producing FATAL: sorry, too many clients already under load.
	// Capping the pool makes excess queries wait for free connections instead of failing,
	// avoiding callers confusing unavailable reads with absent data.
	// Leave headroom for psql/reset-password.sh and other instances, and lower this limit too
	// if the server's max_connections has been reduced.
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // Initial interactive-shell default; ON CONFLICT preserves subsequent user toggles.
	runSeconds            *int // Initial per-run wall-clock seconds; nil uses seed default 1200, 0 unlimited.
}

type promptVar struct{ name, desc, example, source string }

// intp returns a pointer for optional builtinAgent values such as runSeconds.
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a); seed agents and variable catalogs, not base tools.
// interactive_shell_default_v1 initializes planner/worker/mainagent/auto to true, respecting
// later toggles; interactiveShell here enables newly created agents immediately.
var builtinAgents = []builtinAgent{
	{"goals", "Goal decomposer", "goals", "Break penetration testing goals into independent, verifiable subgoals.", []promptVar{
		{"EngagementDescription", "Task description (target/background)", "Test example.com", "exploration"},
		// Now is a global runtime variable (server.globalPromptVars); do not repeat it per agent
		// or withGlobalVars would introduce duplicate names.
	}, false, nil},
	{"planner", "Planner", "planner", "Review progress, assess goals, and add exploration intents only for uncovered directions (one planning loop per task).", []promptVar{
		{"Goal", "Overall task goal", "Obtain administrator access to example.com", "exploration"},
		{"AssetSummary", "Asset count/type summary (optional)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "Main agent", "main", "Human interface: observe progress and turn user directions into hints or high-priority intents.", []promptVar{
		{"Goal", "Current task goal", "Obtain administrator access to example.com", "exploration"},
		{"AssetSummary", "Initial situation summary (optional)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "Confirmed findings summary (optional)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "Worker", "worker", "Claim one intent, execute it, persist facts/findings to the knowledge graph, then stop.", []promptVar{
		{"ProxyAddr", "Recording proxy address (controls conditional prompt text)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "Worker identity (optional)", "worker-1", "runtime"},
	}, false, nil},
	// Auto is the conversation-driven platform-operations agent, outside the pentest orchestration loop.
	{"auto", "Auto", "assistant", "Platform assistant: manage tasks and assets, and create or modify skills, custom tools, and MCP servers.", nil, false, nil},
	// Solo pentest is conversation-driven and handles reconnaissance through validation/cleanup; PTY defaults on.
	{"pentest", "Penetration tester", "assistant", "Independent penetration testing agent: reconnaissance, attack-surface discovery, exploitation, verification, and wrap-up, with its own planning and adversarial self-checks.", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// Remove old goals.Now entries after promoting Now to global scope, avoiding duplicate UI keys.
	// Legacy catalogs may still contain that per-agent entry.
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed built-in Playwright browser MCP once, disabled until users enable it,
	// with no default proxy. The traffic-capture switch injects/removes
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		return fmt.Errorf("seed intercept rules v4: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[Built in] Government websites (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[Built in] Government websites (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[Built in] Education websites (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[Built in] Education websites (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon":        {"auto", "pentest", "worker"},
	"android-security": {"auto", "pentest", "worker", "planner", "mainagent", "retester"},
}

// strixVulnSkills are the per-vulnerability methodology skills imported from Strix
// (Apache-2.0). They are bound to the testing agents so the planner can name them in
// add_intent(skills=…) (WorkerSkillNames reads the worker binding) and the worker /
// solo pentester can load them before testing a vulnerability class.
var strixVulnSkills = []string{
	"agentic_system_security", "argument_injection", "authentication_jwt",
	"broken_function_level_authorization", "browser_security", "business_logic",
	"csrf", "firebase", "header_injection", "http_request_smuggling", "idor",
	"information_disclosure", "insecure_deserialization", "insecure_file_uploads",
	"llm_prompt_injection", "mass_assignment", "nosql_injection", "open_redirect",
	"path_traversal_lfi_rfi", "prototype_pollution", "race_conditions", "rce",
	"semantic_confusion", "sql_injection", "ssrf", "ssti", "subdomain_takeover",
	"weak_password_detection", "xss", "xxe",
}

func init() {
	for _, name := range strixVulnSkills {
		builtinSkillVisibility[name] = []string{"worker", "pentest"}
	}
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// Destructive system commands (priority 100).
		{
			name:     "[Built in] Recursive forced deletion: rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "Recursive forced deletion (rm -rf / rm --recursive) is prohibited; it may permanently damage the system or target environment",
			priority: 100,
		},
		{
			name:     "[Built in] Delete critical system directories",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
			action:   "deny",
			message:  "Deleting critical system paths is prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Disk formatting: mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "Disk formatting (mkfs) is prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Disk device overwrite: dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Overwriting disk devices with dd is prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Fork bomb",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "Fork bombs are prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Shutdown / reboot",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "Shutdown and reboot commands are prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Kill all processes",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "kill -9 -1 and killall -9 (killing all processes) are prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Disk erasure: shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Erasing disk devices with shred/wipe is prohibited",
			priority: 100,
		},
		{
			name:     "[Built in] Flush firewall rules",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "Flushing firewall rules (iptables -F / nft flush) is prohibited",
			priority: 100,
		},
		// Destructive database operations (priority 90).
		{
			name:     "[Built in] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "DROP operations are prohibited; they can irreversibly destroy database objects",
			priority: 90,
		},
		{
			name:     "[Built in] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "TRUNCATE is prohibited; it may clear all table data",
			priority: 90,
		},
		{
			name:     "[Built in] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "MongoDB drop operations are prohibited",
			priority: 90,
		},
		{
			name:     "[Built in] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "Redis FLUSHALL / FLUSHDB is prohibited; it may erase all cached data",
			priority: 90,
		},
		// Destructive HTTP requests (priority 80).
		// Common ways agents issue DELETE:
		// 1. curl -X DELETE / --request DELETE through Bash or a generated script.
		// 2. Python HTTP client .delete().
		// 3. JS/generic script method: 'DELETE' / method="DELETE".
		{
			name:     "[Built in] curl / wget HTTP DELETE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "HTTP DELETE via curl/wget is prohibited; it may delete target data",
			priority: 80,
		},
		{
			name:     "[Built in] Python HTTP DELETE (requests/httpx/aiohttp)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "HTTP DELETE via Python clients is prohibited",
			priority: 80,
		},
		{
			name:     "[Built in] HTTP DELETE in scripts (JS/general)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "Declaring and sending HTTP DELETE in scripts is prohibited",
			priority: 80,
		},
		{
			name:     "[Built in] Bulk clear / wipe endpoints",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "Bulk clear or destructive endpoints (/clear /wipe /flush /purge, etc.) are prohibited",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// destructiveCommandPattern is the "[Built in] Destructive system commands"
// safety rule. It is scanned against the FULL tool_input of every tool (by
// design, so a destructive command cannot be smuggled into a file via Write and
// then executed). Because of that, the loose tokens shutdown|reboot|mkfs must
// NOT match those words wherever they appear in ordinary content — otherwise a
// benign analysis script (e.g. a callgraph helper that calls socket.shutdown()
// or executor.shutdown(), or a pentest step that runs `adb reboot` on the test
// device) gets its Write/Bash denied. So those tokens only match in command
// position: at the start of the input, right after a command separator
// (newline, ; & |), or after sudo. The always-destructive forms (fork bomb,
// dd if=, overwrite of /dev/sd, and rm -rf / against the root itself) match
// regardless of context; rm -rf is anchored so it does not fire on rm -rf
// /subdir (a common, legitimate temp-dir cleanup).
const destructiveCommandPattern = `(?i)(rm\s+-rf\s+/(?:\s|$|["'*&;|])|dd\s+if=|:\(\)\s*\{|>\s*/dev/sd|(?:^|[\n;&|]\s*|\bsudo\s+)(shutdown|reboot|halt|poweroff|mkfs)\b)`

// oldDestructiveCommandPatternV2 is the original (overly loose) pattern seeded by
// v2. seedDefaultInterceptRulesV4 migrates DBs still carrying it to
// destructiveCommandPattern, leaving a user-customized rule untouched.
const oldDestructiveCommandPatternV2 = `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`

// seedDefaultInterceptRulesV4 tightens the built-in destructive-command rule
// (see destructiveCommandPattern). It only rewrites a rule still carrying the
// exact v2 default pattern, so a user who edited or disabled it keeps their
// version. Own flag so it lands once on DBs that already ran v1/v2/v3.
func (d *DB) seedDefaultInterceptRulesV4() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v4"); v == "done" {
		return nil
	}
	if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$1, updated_at=now()
WHERE name='[Built in] Destructive system commands' AND pattern=$2`,
		destructiveCommandPattern, oldDestructiveCommandPatternV2); err != nil {
		return err
	}
	return d.SetSetting("intercept_default_rules_v4", "done")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are ordinary built-in rules; users can
// disable or delete them. The exfil rule ships DISABLED by default (its
// curl/wget/nc pipe pattern mis-fires on legitimate CTF/pentest reverse-shell and
// data-transfer pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedDefaultInterceptRulesV2() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v2"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[Built in] Destructive system commands",
			pattern:  destructiveCommandPattern,
			action:   "deny",
			message:  "Destructive command denied (rm -rf /, mkfs, dd, fork bomb, shutdown/reboot, disk overwrite)",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[Built in] Data exfiltration pipelines",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "Possible exfiltration pipeline denied (command output sent through curl/wget/nc)",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, 'tool_input', 'regex', $4, $5, $6, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v2", "done")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule. Own flag so it also lands on DBs that already
// ran v1/v2, where editing the v1 seed would have no effect.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

func (d *DB) seedDefaultInterceptRulesV3() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v3"); v == "done" {
		return nil
	}
	const name = "[Built in] Deletion endpoints"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 80, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		name,
		deleteEndpointPathPattern,
		"Deletion endpoints (/delete /remove /unlink /erase, etc.) are prohibited regardless of HTTP method; GET/POST may also delete actual target data",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_default_rules_v3", "done")
}
