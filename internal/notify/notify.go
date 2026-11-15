// Package notify implements IM/email adapters for finding notifications.
//
// Leaf package depending only on the standard library, without DB/server knowledge.
// Configuration arrives as map[string]any corresponding to notification_channels.config JSONB;
// content arrives as Message. Signing, UTF-8 truncation, and filtering can therefore be tested
// independently of PostgreSQL, while the server handles orchestration.
//
// Channel implementations must be stateless: one instance serves multiple configurations,
// including bots of the same type, concurrently. Credentials arrive only through cfg;
// never cache Webhook URLs or other configuration in adapter fields.
package notify

// Channel identifiers also define valid notification_channels.kind values, validated by server
// allowlists instead of DB CHECK constraints to ease future extensions.
const (
	KindDingTalk = "dingtalk" // DingTalk custom bot.
	KindFeishu   = "feishu"   // Feishu/Lark custom bot.
	KindWeCom    = "wecom"    // WeCom group bot.
	KindWebhook  = "webhook"  // Generic Webhook with custom method/headers/JSON template.
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email.
)

// Event types matching notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind falls back when config kind is empty.
const InitKind = KindDingTalk

// severityRank maps comparable ordinals; unknown returns 0, failing any nonempty threshold
// to avoid uncertain low-value notifications.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns severity ordinal, 0 for unknown.
func SeverityRank(severity string) int { return severityRank[severity] }

// SeverityLabel returns English severity with emoji for titles/card colors.
// Echo unknown severity unchanged rather than inventing a label.
func SeverityLabel(severity string) string {
	switch severity {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	default:
		return severity
	}
}

// StatusLabel supplies English workflow labels for status-change messages.
func StatusLabel(status string) string {
	switch status {
	case "pending":
		return "Pending"
	case "in_progress":
		return "In progress"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Resolved"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False positive"
	case "ignored":
		return "Ignored"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk accepted"
	default:
		return status
	}
}

// AtLeast checks severity against min; empty min accepts all.
// Unknown severity ranks 0 and fails any nonempty min.
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
