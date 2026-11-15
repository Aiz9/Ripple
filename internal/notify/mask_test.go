package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskedValueHidesBodyButKeepsTailHint(t *testing.T) {
	const secret = "https://oapi.dingtalk.com/robot/send?access_token=abcdef123456"
	got := MaskedValue(secret)
	if strings.Contains(got, "abcdef123456") {
		t.Fatalf("masked value leaked the full credential: %q", got)
	}
	if strings.Contains(got, "oapi.dingtalk.com") {
		t.Fatalf("masked value must not expose the address body: %q", got)
	}
	// Preserve final six characters so operators can identify bots.
	if !strings.HasSuffix(got, "123456") {
		t.Fatalf("should keep the last 6 characters as a recognition hint: %q", got)
	}
	if !IsMasked(got) {
		t.Fatalf("masked values must pass the IsMasked check: %q", got)
	}
}

func TestMaskedValueShortSecretGivesNoHint(t *testing.T) {
	// Short credentials must not reveal six characters, which could expose the entire secret.
	for _, s := range []string{"abc", "abcdef", ""} {
		got := MaskedValue(s)
		if got != MaskedPrefix {
			t.Fatalf("a credential of length %d should get no tail hint, got %q", len(s), got)
		}
		if s != "" && strings.Contains(got, s) {
			t.Fatalf("masked value contains the original: %q", got)
		}
	}
}

func TestMaskConfigMasksOnlySecrets(t *testing.T) {
	cfg := map[string]any{
		"webhook": "https://example.com/hook?token=SECRETVALUE",
		"secret":  "SECtest123456",
		"port":    float64(587),
		"host":    "smtp.example.com",
	}
	masked := MaskConfig(KindDingTalk, cfg)
	for _, k := range []string{"webhook", "secret"} {
		s, _ := masked[k].(string)
		if !IsMasked(s) {
			t.Errorf("%s should be masked, got %q", k, s)
		}
	}
	// Preserve noncredential fields for UI display.
	if masked["port"] != float64(587) {
		t.Errorf("non-credential field port must not be changed: %v", masked["port"])
	}
}

func TestMaskConfigUnknownKindReturnsEmpty(t *testing.T) {
	// Unknown kinds return empty config rather than possibly revealing raw credentials.
	got := MaskConfig("nope", map[string]any{"webhook": "https://x/y?token=LEAK"})
	if len(got) != 0 {
		t.Fatalf("an unknown channel kind should return an empty config, got %v", got)
	}
}

func TestMaskConfigDoesNotMutateInput(t *testing.T) {
	// Display masking must never mutate real stored values.
	cfg := map[string]any{"webhook": "https://example.com/hook", "secret": "SECtest123456"}
	_ = MaskConfig(KindDingTalk, cfg)
	if IsMasked(cfg["secret"].(string)) {
		t.Fatal("MaskConfig modified its argument, which would overwrite real credentials with masked values")
	}
}

func TestMergeConfigKeepsStoredOnMaskedIncoming(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET", "method": "POST"}
	// User changed method only; browser submits masks plus new method.
	incoming := map[string]any{
		"webhook": MaskedValue("https://real/hook"),
		"secret":  MaskedValue("REALSECRET"),
		"method":  "PUT",
	}
	got := MergeConfig(stored, incoming)
	if got["webhook"] != "https://real/hook" || got["secret"] != "REALSECRET" {
		t.Fatalf("masked fields should keep the stored value, got %v", got)
	}
	if got["method"] != "PUT" {
		t.Fatalf("changed fields should take effect, got %v", got["method"])
	}
}

func TestMergeConfigEmptyStringClears(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET"}
	got := MergeConfig(stored, map[string]any{"secret": ""})
	if _, ok := got["secret"]; ok {
		t.Fatalf("an empty string should clear the field, got %v", got)
	}
	// Preserve omitted fields for partial updates.
	if got["webhook"] != "https://real/hook" {
		t.Fatalf("unmentioned fields should be kept, got %v", got)
	}
}

func TestMergeConfigKeepsUnmentionedStoredKeys(t *testing.T) {
	stored := map[string]any{"host": "smtp.example.com", "port": float64(587), "password": "pw"}
	got := MergeConfig(stored, map[string]any{"port": float64(465)})
	if got["host"] != "smtp.example.com" || got["password"] != "pw" {
		t.Fatalf("unmentioned fields should be kept, got %v", got)
	}
	if got["port"] != float64(465) {
		t.Fatalf("mentioned fields should be updated, got %v", got["port"])
	}
}

// TestPrepareConfigUpdateBlocksDestinationSwap enforces the central security invariant:
// changing destinations cannot forward old credentials.
//
// Use attack-shaped address-only updates omitting credentials, not only valid defensive inputs;
// the latter could pass even with protection disabled.
func TestPrepareConfigUpdateBlocksDestinationSwap(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
		// wantMissing names credential keys expected in the error.
		wantMissing string
	}{
		{
			name: "\u901a\u7528 Webhook \u6539\u5730\u5740\u60f3\u6cbf\u7528 Authorization \u5934",
			kind: KindWebhook,
			stored: map[string]any{
				"url":     "https://legit.example.com/hook",
				"headers": map[string]any{"Authorization": "Bearer REAL-TOKEN"},
			},
			incoming:    map[string]any{"url": "https://attacker.tld/c"},
			wantMissing: "headers",
		},
		{
			name:        "Telegram \u6539 base_url \u60f3\u628a Bot Token \u53d1\u5230\u81ea\u5df1\u7684\u7aef\u70b9",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld"},
			wantMissing: "bot_token",
		},
		{
			name:        "\u90ae\u4ef6\u6539 SMTP \u4e3b\u673a\u60f3\u4ea4\u51fa\u5bc6\u7801",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"host": "smtp.attacker.tld"},
			wantMissing: "password",
		},
		{
			name:        "\u90ae\u4ef6\u5173\u6389 TLS \u4e5f\u5fc5\u987b\u91cd\u65b0\u8868\u6001\u5bc6\u7801",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "tls": false, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"tls": true},
			wantMissing: "password",
		},
		{
			// Masks mean reuse-old and must also be rejected on changed destinations.
			name:        "\u56de\u4f20\u63a9\u7801\u51ed\u636e + \u65b0\u5730\u5740",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld", "bot_token": MaskedValue("123456:REAL")},
			wantMissing: "bot_token",
		},
		{
			name:        "\u9489\u9489\u6539 Webhook \u60f3\u6cbf\u7528\u52a0\u7b7e\u5bc6\u94a5",
			kind:        KindDingTalk,
			stored:      map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=OLD", "secret": "REALSEC"},
			incoming:    map[string]any{"webhook": "https://attacker.tld/hook"},
			wantMissing: "secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err == nil {
				t.Fatalf("changing the address without restating credentials should be rejected; got config %v", merged)
			}
			var target *ErrDestinationChangedWithoutCredentials
			if !errors.As(err, &target) {
				t.Fatalf("should return a dedicated error type so the API can give an actionable hint, got %T: %v", err, err)
			}
			found := false
			for _, m := range target.Missing {
				if m == tc.wantMissing {
					found = true
				}
			}
			if !found {
				t.Fatalf("should name the missing credential key %q, got %v", tc.wantMissing, target.Missing)
			}
			// Errors should guide operators to a correction.
			if !strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("the error should mention %q: %v", tc.wantMissing, err)
			}
		})
	}
}

// TestPrepareConfigUpdateAllowsLegitimateEdits prevents false positives on normal editing,
// which would tempt removal or bypass of annoying protections.
func TestPrepareConfigUpdateAllowsLegitimateEdits(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
	}{
		{
			name:     "\u53ea\u6539\u540d\u5b57\uff08\u914d\u7f6e\u539f\u6837\u56de\u4f20\uff09",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "headers": map[string]any{"Authorization": "Bearer REAL"}},
			incoming: map[string]any{"url": MaskedValue("https://legit.example.com/hook")},
		},
		{
			name:     "\u53ea\u6539\u8bf7\u6c42\u65b9\u6cd5\uff0c\u5730\u5740\u4e0e\u51ed\u636e\u90fd\u4e0d\u52a8",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "method": "POST"},
			incoming: map[string]any{"method": "PUT"},
		},
		{
			name:     "\u6362\u5730\u5740\u5e76**\u540c\u65f6**\u7ed9\u65b0\u51ed\u636e",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": map[string]any{"Authorization": "Bearer NEW"}},
		},
		{
			name:     "\u6362\u5730\u5740\u5e76\u663e\u5f0f\u58f0\u660e\u4e0d\u518d\u9700\u8981\u51ed\u636e",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": ""},
		},
		{
			name:     "Telegram \u6539 chat_id\uff08\u4e0d\u662f\u76ee\u7684\u5730\uff09",
			kind:     KindTelegram,
			stored:   map[string]any{"bot_token": "t", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming: map[string]any{"chat_id": "-100200"},
		},
		{
			name:     "\u90ae\u4ef6\u6539\u6536\u4ef6\u4eba\uff08\u4e0d\u662f\u76ee\u7684\u5730\uff09",
			kind:     KindEmail,
			stored:   map[string]any{"host": "smtp.corp.com", "port": 587, "password": "PW", "from": "a@b.c", "to": []any{"x@y.z"}},
			incoming: map[string]any{"to": []any{"new@y.z"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err != nil {
				t.Fatalf("a legitimate edit was blocked by mistake: %v", err)
			}
			if merged == nil {
				t.Fatal("should return the merged result")
			}
		})
	}
}

// TestPrepareConfigUpdatePortTypeTolerance covers unchanged int/float64 port equivalence.
// Frontend and DB JSON representations may differ even for the same numeric port.
// Direct equality could falsely demand password re-entry after an unrelated name edit,
// undermining trust in the guard.
func TestPrepareConfigUpdatePortTypeTolerance(t *testing.T) {
	stored := map[string]any{"host": "smtp.corp.com", "port": float64(587), "password": "PW"}
	// Same port submitted as int.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 587}); err != nil {
		t.Fatalf("identical port values (differing only in type) must not count as an address change: %v", err)
	}
	// A genuinely changed port still requires rejection.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 25}); err == nil {
		t.Fatal("a port change should be blocked")
	}
}

// TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination covers optional destinations:
// Telegram empty base_url means official API.
//
// Previously second and subsequent saves failed permanently:
//
// Creation stored base_url empty directly, without MergeConfig.
// First save deleted the empty key.
// Second save compared incoming empty with stored missing as changed.
// Masked bot_token then caused 400 destination-change/credential-reentry error.
//
// User could save again only by repasting a token despite changing nothing.
func TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination(t *testing.T) {
	stored := map[string]any{"bot_token": "123:ABC", "chat_id": "-100", "base_url": ""}

	// Frontend buildConfig submits every defined field, masks for credentials and empty strings
	// for blank text boxes. Reproduce that complete form, not only changed keys.
	submit := func() map[string]any {
		return map[string]any{
			"bot_token": MaskedValue("123:ABC"),
			"chat_id":   "-100",
			"base_url":  "",
		}
	}

	// First save changes name only, returning config unchanged.
	merged, err := PrepareConfigUpdate(KindTelegram, stored, submit())
	if err != nil {
		t.Fatalf("the first save was blocked by mistake: %v", err)
	}
	if _, ok := merged["base_url"]; ok {
		t.Fatal("precondition changed: an empty string should be removed by MergeConfig \u2014\u2014this case covers exactly the step after the key disappears")
	}

	// Second save submits exactly the same content.
	merged2, err := PrepareConfigUpdate(KindTelegram, merged, submit())
	if err != nil {
		t.Fatalf("the second save was blocked by mistake (the user changed nothing): %v", err)
	}
	// Third save proves stable repeatability rather than a one-time fix.
	if _, err := PrepareConfigUpdate(KindTelegram, merged2, submit()); err != nil {
		t.Fatalf("the third save was blocked by mistake: %v", err)
	}
	// Preserve credentials throughout; blank-destination handling must not clear them.
	if got := merged2["bot_token"]; got != "123:ABC" {
		t.Fatalf("Bot Token should keep its stored value, got %v", got)
	}
}

// TestPrepareConfigUpdateStillGuardsBlankDestinationChanges pairs with repeat-save coverage:
// treating empty and missing equally must not permit real destination swaps.
// Both directions can forward Telegram's URL-embedded token to a new endpoint,
// so each is a credential-sensitive destination change.
func TestPrepareConfigUpdateStillGuardsBlankDestinationChanges(t *testing.T) {
	// Direction 1: blank/official to custom endpoint.
	official := map[string]any{"bot_token": "123:ABC", "chat_id": "-100"}
	if _, err := PrepareConfigUpdate(KindTelegram, official, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "https://tg-proxy.attacker.tld",
	}); err == nil {
		t.Fatal("switching from the official address to a self-hosted one must require re-entering the Token")
	}

	// Direction 2: custom endpoint cleared back to official.
	proxied := map[string]any{"bot_token": "123:ABC", "base_url": "https://proxy.internal/bot"}
	if _, err := PrepareConfigUpdate(KindTelegram, proxied, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "",
	}); err == nil {
		t.Fatal("clearing the self-hosted address (back to the official API) is also an address change and must require re-entering the Token")
	}
}

func TestDestinationKeysDeclaredForEveryKind(t *testing.T) {
	// Missing DestinationKeys declarations would leave PrepareConfigUpdate unable to protect channels.
	for kind, ch := range registry {
		if len(ch.DestinationKeys()) == 0 {
			t.Errorf("channel %s declares no destination keys, so protection against leaking credentials on address change does not apply to it", kind)
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential keys", kind)
		}
	}
}

func TestSecretKeysDeclaredForEveryKind(t *testing.T) {
	// Compiler enforces SecretKeys implementation; also require nonempty declarations so no channel
	// accidentally echoes its credentials to browsers in plaintext.
	expect := map[string]bool{
		KindDingTalk: true, KindFeishu: true, KindWeCom: true,
		KindWebhook: true, KindTelegram: true, KindEmail: true,
	}
	for kind, ch := range registry {
		if !expect[kind] {
			t.Errorf("channel %s has no masking expectation registered in the test", kind)
			continue
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential fields, so its config would be echoed in plain text", kind)
		}
	}
}

// TestPrepareConfigUpdateRejectsMaskedInContainer closes an audited path: embedded masks in
// nonstring structures such as webhook.headers are not recognized by MergeConfig,
// which would store __masked__ as real header content, silently breaking authentication.
// Reject this shape instead of accepting a success response.
func TestPrepareConfigUpdateRejectsMaskedInContainer(t *testing.T) {
	stored := map[string]any{
		"url":     "https://legit.example.com/hook",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
	}
	// Object containing an embedded mask sentinel.
	incoming := map[string]any{
		"headers": map[string]any{"Authorization": MaskedPrefix},
	}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, incoming); err == nil {
		t.Fatal("a mask sentinel inside a struct should be rejected (otherwise the literal would be stored)")
	}
	// Whole objects with actual new values remain accepted.
	ok := map[string]any{"headers": map[string]any{"Authorization": "Bearer NEW"}}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, ok); err != nil {
		t.Fatalf("a normal submission of new request headers must not be blocked: %v", err)
	}
}
