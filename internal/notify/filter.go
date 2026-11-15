package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter defines notification_channels.filter JSONB.
// Every field is optional; missing/malformed configuration falls back to no filtering.
type Filter struct {
	// MinSeverity: low/medium/high/critical threshold; empty means none.
	MinSeverity string `json:"min_severity"`
	// Empty TaskIDs/AssetIDs are unrestricted; nonempty requires intersection.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// Empty VulnClassInclude accepts all; otherwise any keyword must match.
	// Any VulnClassExclude match rejects, taking precedence over inclusion.
	// Case-insensitive substrings avoid regex mistakes silently disabling channels.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange opts into status transitions, meaningful for realtime only.
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter decodes channel filters.
//
// Never return errors: malformed config becomes zero Filter, matching everything.
// Extra notifications are preferable to silently missing a high-severity finding.
// Rejecting sends on parse failure would leave apparently configured channels sending nothing,
// the worst failure mode for a finding-notification system.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// Parse failure retains zero/no-filter state.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity accepts supported thresholds and empty for unrestricted.
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks constrained field values at channel-save time.
//
// Unknown thresholds become rank>=0, always true in Match; a typo such as hgih silently
// disables severity filtering and sends all findings.
// This avoids missing alerts but contradicts the operator's intended severity routing,
// potentially flooding a group without any visible misconfiguration warning.
// Reject that silent downgrade at the write boundary.
//
// Validate is write-only; reads remain tolerant through ParseFilter so historical bad data
// cannot prevent loading entire channels.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("Invalid minimum severity %q; choose low / medium / high / critical, or leave blank for any severity", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event belongs to a channel.
//
// Never errors; unexpected internal conditions match, like ParseFilter.
// Order: event type, severity, task/asset scope, vulnerability keywords.
func Match(f Filter, s Snapshot) bool {
	// Status transitions require explicit opt-in, disabled by default because most users expect
	// alerts for new findings rather than a log of every workflow transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclusion wins over simultaneous inclusion matches.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// Linear scans suffice for manually selected sets of tens of values; map construction costs
	// more than it saves at this scale.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold matches any keyword substring case-insensitively.
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
