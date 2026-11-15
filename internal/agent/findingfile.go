package agent

import (
	"context"
	"strings"

	"github.com/Autumn-27/artex/internal/db"
)

// findingBlock is a deterministically-verified finding ready to persist. It carries
// the full Phase-8 evidence schema; evidenceMarkdown renders it into the single
// evidence field the findings table stores, and fileFinding writes it through the
// same recorder path the human report_finding tool uses (dedup on, so repeated
// verifier runs enrich one finding instead of duplicating it).
type findingBlock struct {
	VulnClass          string   `json:"vulnclass"`
	Name               string   `json:"name"`
	Severity           string   `json:"severity"`
	Summary            string   `json:"summary"`
	AffectedEndpoint   string   `json:"affected_endpoint"`
	Method             string   `json:"method"`
	Preconditions      string   `json:"preconditions"`
	Reproduction       []string `json:"reproduction"`
	Expected           string   `json:"expected"`
	Actual             string   `json:"actual"`
	Impact             string   `json:"impact"`
	Remediation        string   `json:"remediation"`
	VerificationStatus string   `json:"verification_status"` // confirmed (deterministic)
	FiledFindingID     int64    `json:"filed_finding_id,omitempty"`
}

func (fb *findingBlock) evidenceMarkdown() string {
	var b strings.Builder
	w := func(h, v string) {
		if strings.TrimSpace(v) != "" {
			b.WriteString("**" + h + ":** " + v + "\n\n")
		}
	}
	w("Affected endpoint", strings.TrimSpace(fb.Method+" "+fb.AffectedEndpoint))
	w("Verification", fb.VerificationStatus+" (deterministic differential; not inferred from status code alone)")
	w("Preconditions", fb.Preconditions)
	if len(fb.Reproduction) > 0 {
		b.WriteString("**Reproduction:**\n")
		for i, s := range fb.Reproduction {
			b.WriteString(itoa(i+1) + ". " + s + "\n")
		}
		b.WriteString("\n")
	}
	w("Expected behaviour", fb.Expected)
	w("Actual behaviour", fb.Actual)
	w("Security impact", fb.Impact)
	w("Remediation", fb.Remediation)
	return strings.TrimRight(b.String(), "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		return "-" + string(d)
	}
	return string(d)
}

// fileFinding persists the block through the finding recorder (or the store's
// legacy path), deduping within the task. Returns the finding id and whether it was
// filed. It is a no-op (false) when there is no task/exploration context — e.g. the
// catalog shell or tests — so the verifier tools still return their evidence block.
func (t *ToolSet) fileFinding(ctx context.Context, fb *findingBlock, assetIDs []int64) (int64, bool) {
	if fb == nil || t.ts == nil {
		return 0, false
	}
	input := db.RecordFindingInput{
		TaskID:        t.taskID,
		ExplorationID: t.ts.ID(),
		VulnClass:     fb.VulnClass,
		Name:          fb.Name,
		Severity:      fb.Severity,
		Summary:       fb.Summary,
		Evidence:      fb.evidenceMarkdown(),
		Worker:        t.worker,
		AssetIDs:      assetIDs,
		Dedup:         true,
	}
	var rec *db.RecordedFinding
	var err error
	if t.findingRecorder != nil {
		rec, err = t.findingRecorder.Record(ctx, input, nil)
	} else {
		rec, err = t.ts.RecordFinding(ctx, input)
	}
	if err != nil || rec == nil {
		return 0, false
	}
	t.writes.Findings++
	if t.notifyFinding != nil {
		iid := t.ownerNode
		t.notifyFinding(iid, fb.Summary)
	} else if t.notify != nil {
		t.notify()
	}
	return rec.FindingID, true
}

// endpointAssetID upserts the endpoint into the inventory (observed) and returns
// its asset id to anchor the finding to, or nil when no asset store is available.
func (t *ToolSet) endpointAssetID(canonURL, method string) []int64 {
	if t.as == nil || canonURL == "" || method == "" {
		return nil
	}
	id, err := t.as.UpsertEndpoint(db.UpsertEndpointReq{URL: canonURL, Method: method, TaskID: t.taskID})
	if err != nil || id == 0 {
		return nil
	}
	return []int64{id}
}
