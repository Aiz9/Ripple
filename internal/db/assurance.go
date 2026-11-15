package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Test-assurance state shared by a task's agents: the coverage ledger (what was
// tested and how each lead closed) and the threat model (who the attacker is, where
// the trust boundaries sit). Both are scoped to the exploration and cascade with it.

// Coverage outcomes. needs_follow_up = plausible but unproven, work still owed;
// blocked = cannot be completed in this environment (evidence names the blocker).
var CoverageOutcomes = []string{"reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up", "blocked"}

func validCoverageOutcome(o string) bool {
	for _, v := range CoverageOutcomes {
		if v == o {
			return true
		}
	}
	return false
}

// CoverageEntry is one surface×risk row of the ledger.
type CoverageEntry struct {
	ID        int64     `json:"id"`
	Surface   string    `json:"surface"`
	Risk      string    `json:"risk"`
	Outcome   string    `json:"outcome"`
	Evidence  string    `json:"evidence,omitempty"`
	IntentID  int64     `json:"intent_id,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RecordCoverage upserts the (surface, risk) row; a later call moves the same row
// to its new outcome instead of adding a second one. Every outcome except
// reported/no_issue_found must carry evidence: a negative or open conclusion
// without its reason is indistinguishable from "never looked".
func (s *ExplorationStore) RecordCoverage(surface, risk, outcome, evidence string, intentID int64, agent string) (int64, error) {
	surface, risk = strings.TrimSpace(surface), strings.ToLower(strings.TrimSpace(risk))
	outcome, evidence = strings.TrimSpace(outcome), strings.TrimSpace(evidence)
	if surface == "" || risk == "" {
		return 0, fmt.Errorf("surface and risk are required")
	}
	if !validCoverageOutcome(outcome) {
		return 0, fmt.Errorf("outcome must be one of %s", strings.Join(CoverageOutcomes, ", "))
	}
	if evidence == "" && outcome != "reported" && outcome != "no_issue_found" {
		return 0, fmt.Errorf("outcome %s requires evidence: name the control that blocks the attack (ruled_out), why the surface does not apply (not_applicable), what is unproven and what would prove it (needs_follow_up), or the concrete blocker (blocked)", outcome)
	}
	var iid sql.NullInt64
	if intentID > 0 {
		iid = sql.NullInt64{Int64: intentID, Valid: true}
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO task_test_coverage(exploration_id, surface, risk, outcome, evidence, intent_id, agent)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (exploration_id, surface, risk) DO UPDATE
  SET outcome=EXCLUDED.outcome, evidence=EXCLUDED.evidence,
      intent_id=COALESCE(EXCLUDED.intent_id, task_test_coverage.intent_id),
      agent=EXCLUDED.agent, updated_at=now()
RETURNING id`, s.expID, surface, risk, outcome, evidence, iid, agent).Scan(&id)
	return id, err
}

// ListCoverage returns ledger rows, filtered to one outcome when outcome != "".
func (s *ExplorationStore) ListCoverage(outcome string) ([]CoverageEntry, error) {
	rows, err := s.db.Query(`SELECT id, surface, risk, outcome, evidence, COALESCE(intent_id,0), agent, updated_at
FROM task_test_coverage WHERE exploration_id=$1 AND ($2='' OR outcome=$2)
ORDER BY surface, risk`, s.expID, outcome)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CoverageEntry{}
	for rows.Next() {
		var e CoverageEntry
		if err := rows.Scan(&e.ID, &e.Surface, &e.Risk, &e.Outcome, &e.Evidence, &e.IntentID, &e.Agent, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CoverageCounts returns row counts per outcome.
func (s *ExplorationStore) CoverageCounts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT outcome, count(*) FROM task_test_coverage WHERE exploration_id=$1 GROUP BY outcome`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var o string
		var n int
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		out[o] = n
	}
	return out, rows.Err()
}

// ThreatModelSections must all appear (case-insensitive) in a saved threat model.
var ThreatModelSections = []string{"overview", "trust boundaries", "attack surface", "severity calibration"}

// ThreatAmendment is one agent correction appended to the baseline.
type ThreatAmendment struct {
	Agent string    `json:"agent"`
	Text  string    `json:"text"`
	At    time.Time `json:"at"`
}

// ThreatModel is the task's shared baseline plus amendments.
type ThreatModel struct {
	Content    string            `json:"content"`
	Amendments []ThreatAmendment `json:"amendments"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// SaveThreatModel replaces the baseline (and clears amendments, which the new
// baseline is expected to fold in).
func (s *ExplorationStore) SaveThreatModel(content string) error {
	content = strings.TrimSpace(content)
	lower := strings.ToLower(content)
	var missing []string
	for _, sec := range ThreatModelSections {
		if !strings.Contains(lower, sec) {
			missing = append(missing, sec)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("threat model is missing required sections: %s", strings.Join(missing, ", "))
	}
	_, err := s.db.Exec(`
INSERT INTO task_threat_models(exploration_id, content) VALUES ($1,$2)
ON CONFLICT (exploration_id) DO UPDATE SET content=EXCLUDED.content, amendments='[]', updated_at=now()`, s.expID, content)
	return err
}

// AmendThreatModel appends a correction; fails when no baseline exists yet.
func (s *ExplorationStore) AmendThreatModel(agent, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("addendum must not be empty")
	}
	b, _ := json.Marshal([]ThreatAmendment{{Agent: agent, Text: text, At: time.Now().UTC()}})
	res, err := s.db.Exec(`UPDATE task_threat_models SET amendments = amendments || $2::jsonb, updated_at=now() WHERE exploration_id=$1`, s.expID, string(b))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no threat model saved for this task yet; save_threat_model first")
	}
	return nil
}

// GetThreatModel returns nil (no error) when none is saved.
func (s *ExplorationStore) GetThreatModel() (*ThreatModel, error) {
	var m ThreatModel
	var raw []byte
	err := s.db.QueryRow(`SELECT content, amendments, updated_at FROM task_threat_models WHERE exploration_id=$1`, s.expID).Scan(&m.Content, &raw, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(raw, &m.Amendments)
	return &m, nil
}

// WithdrawFinding removes a disproved finding from the task's results: the node
// goes to 'dismissed' (dropping out of list_findings/goal evidence) and its
// standalone record to false_positive, with a status-change notification.
func (s *ExplorationStore) WithdrawFinding(ctx context.Context, nodeID int64) error {
	return s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='dismissed', content_version=content_version+1
WHERE id=$1 AND exploration_id=$2 AND kind='finding' AND state='confirmed'`, nodeID, s.expID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("finding node %d is not a confirmed finding in this task", nodeID)
		}
		var fid int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&fid)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		_, _, _, _, err = SetFindingStatusTx(ctx, tx, fid, FindingFalsePositive)
		return err
	})
}
