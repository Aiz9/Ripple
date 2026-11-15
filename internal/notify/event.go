package notify

// Snapshot defines notification_events.snapshot JSONB. Finding transactions write it; server
// delivery/filtering reads it. This notification-domain contract lives here because DB only
// serializes and does not interpret its fields.
//
// Snapshot rather than requery mutable finding names/severity/status: notifications describe
// the conclusion at event time, not a later downgrade to low.
// This also avoids findings/tasks/assets joins during fanout/rendering.
type Snapshot struct {
	// Event type: finding_created / finding_status_changed.
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Nonempty only for finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is one finding to render for delivery.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets contains display names such as domains/IPs, resolved by the server;
	// this package does not access the database.
	Assets []string
	// DetailURL links to finding details; omit when public_base_url is unset.
	DetailURL string
	// Status-change only; render from -> to when both are nonempty.
	FromStatus string
	ToStatus   string
}

// IsStatusChange identifies a status-change item.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title prefers user-assigned name, falls back to vulnclass, then a placeholder;
// never return an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed finding)"
}

// Message is the complete content of one channel send.
type Message struct {
	// One item for realtime, a whole batch for digest.
	// Empty items are invalid; callers must provide at least one.
	Items []Item
	// Batch=true renders digest title, window, and counts.
	Batch bool
	// WindowMinutes is the configured digest period used only in batch wording.
	// Pass it explicitly instead of time.Since at rendering to preserve deterministic tests.
	WindowMinutes int
	// HomeURL is public_base_url; empty omits the dashboard entry.
	HomeURL string
}
