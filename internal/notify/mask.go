package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix marks API credential placeholders; update handlers interpret these values as
// retaining the stored original.
//
// A prefix instead of empty/fixed text allows an identifying suffix (MaskedValue),
// helping users recognize bots without repasting credentials.
const MaskedPrefix = "__masked__"

// MaskedValue returns a masked representation:
//
// __masked__ for short values, exposing nothing.
// __masked__:...ab12cd reveals only the final six characters for identification.
//
// Webhook identifiers live at the end (WeCom key/Feishu bot ID), unlike shared URL prefixes.
// Six suffix characters identify a bot without reconstructing its credentials.
// This is a deliberate display/security tradeoff.
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked identifies unchanged API credential placeholders.
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig copies configuration and masks the adapter's credential fields.
//
// Unknown channel kinds return an empty map instead of possibly leaking raw credentials;
// an unavailable UI configuration is preferable to disclosure.
// Preserve noncredential fields for normal UI editing.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Mask nested structures such as headers as one credential; per-child secret declarations
		// add disproportionate complexity.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means destination changed without explicit credential
// choices; reject rather than silently forwarding or discarding secrets (PrepareConfigUpdate).
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // Changed destination keys.
	Missing []string // Credential keys lacking explicit choices.
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "Target address (" + strings.Join(e.Changed, ", ") + ") changed. Re-enter credential fields (" +
		strings.Join(e.Missing, ", ") + "): provide new values, or explicitly leave empty if credentials are no longer required." +
		"Existing credentials apply only to the old address; reusing them would send them to the new address."
}

// PrepareConfigUpdate merges config and handles security-sensitive destination changes.
//
// It replaces raw MergeConfig on channel updates, preventing a verified exfiltration path:
// destinations and credentials are independent fields; MergeConfig preserves omitted stored
// values, so address-only PATCHes could send existing real credentials to attacker endpoints.
// No credential knowledge is required to trigger that forwarding.
//
// webhook config.url -> attacker receives stored Authorization headers.
// telegram config.base_url -> attacker receives /bot<real-token>/sendMessage.
// email config.host -> attacker receives username/password after STARTTLS.
//
// No redirects are involved, so cross-host redirect protections do not prevent this.
// It defeats the promise that credentials are never revealed to the browser.
//
// Any changed destination requires an explicit decision for every credential key:
// - New value replaces it.
// - Explicit empty clears it when no credential is required.
// - Returned mask or omitted key is rejected.
//
// Masks mean reuse old credentials, authorized only for the old address. Do not automatically
// discard credentials either: optional Webhook headers/email password could silently disappear,
// with a successful update response but broken authentication, harder to diagnose than rejection.
// Require explicit operator intent.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("Channel type %q is not registered", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// Reject masked literals embedded in nonstring credentials such as headers objects.
	// MergeConfig recognizes masks only as whole strings; embedded sentinels would be stored as
	// real values, leaving __masked__ in the database and silently breaking authentication.
	// Prefer explicit rejection.
	//
	// Check before any early return, including unchanged destinations; the initial implementation
	// checked too late and tests caught that uncovered path.
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find actually changed destination keys; masks mean unchanged.
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// Unchanged destination uses normal merge: preserve masks, clear empties, replace others.
		return MergeConfig(stored, incoming), nil
	}

	// Changed destination requires explicit choices for every credential.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers rejects masks nested inside nonstring values.
//
// Masking requires the entire value to be a string; headers objects must be wholly masked
// or wholly submitted with real values. An embedded sentinel neither preserves the original
// nor avoids persisting a literal mask.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("Field %s contains mask marker %q: leave the whole field empty to retain it or provide a complete new value; embedded mask placeholders are not accepted",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares JSON encodings to tolerate number/int/float64 representations,
// preventing unchanged ports from being misclassified as changed.
//
// Normalize empty strings and absent keys first: MergeConfig deletes explicitly cleared keys,
// making these equivalent. Otherwise blank optional Telegram base_url (official endpoint)
// follows this failure sequence despite remaining unchanged:
// Blank destination has the same meaning as missing.
//
// Creation stores base_url empty; first save deletes it via MergeConfig.
// Second save submits empty against missing, incorrectly indicating destination change.
// Masked credentials then cause 400 requiring credentials again.
//
// Every subsequent save fails unless the user repastes the bot token despite changing nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue detects empty values.
// Match MergeConfig's strings.TrimSpace(s)==empty clearing behavior exactly,
// avoiding disagreement between deletion and equality checks.
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig overlays incoming configuration onto stored configuration.
//
// Rules:
// - Incoming masked values preserve originals.
// - Incoming empty strings explicitly clear/delete keys.
// - Other incoming values replace stored values.
// - Stored keys omitted from incoming remain unchanged for partial updates.
//
// Forms submit unfilled fields as empty strings; clearing semantics must be explicit rather
// than accidentally interpreting them as keep-original requests.
// Choose explicit clearing so users can remove wrong settings; omission separately expresses
// retaining an unchanged field.
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // Masked means unchanged: retain stored value.
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
