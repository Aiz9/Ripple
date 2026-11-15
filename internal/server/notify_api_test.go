package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/internal/db"
	"github.com/Autumn-27/artex/internal/notify"
)

// End-to-end finding -> event -> fanout -> real HTTP tests.
//
// Never call global Notifier.step: exercise only fixture channels via stepRealtime/stepDigest.
// Global step scans all enabled channels and could send test findings into real DingTalk/WeCom
// groups in a configured development database.
// Channel-specific sends strictly limit effects to test-owned fake receivers.
//
// Cleanup removes test events/cascaded deliveries and channels, leaving no real-channel backlog.
//
// stepRealtime/stepDigest return no values, so assert observable receiver content and delivery
// state rather than stubbed return values.
// This exercises the actual call path.

// notifyFixture is shared test setup.
type notifyFixture struct {
	s       *Server
	pg      *db.DB
	request func(method, path, body string) *httptest.ResponseRecorder
	n       *Notifier
	// Owned task/exploration isolates finding records from other tests.
	taskID int64
	expID  int64
	// Cleanup events created after cleanupMark.
	cleanupMark int64
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	// Local fake receivers require explicit AllowLocalTargets override; production defaults deny
	// loopback to prevent sensitive-service/metadata SSRF.
	// Default-deny coverage lives in notify/ssrf_test.go.
	t.Setenv(notify.AllowLocalTargetsEnv, "1")
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg

	// Build a task because trafficEvidenceServer does not expose exploration ID needed for
	// finding registration.
	task, err := s.m.CreateTask("\u901a\u77e5\u63a8\u9001\u6d4b\u8bd5", "\u63a8\u9001\u884c\u4e3a\u9a8c\u8bc1", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID) })

	var mark int64
	if err := pg.QueryRow(`SELECT COALESCE(max(id),0) FROM notification_events`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	// Mark preexisting events fanned out to isolate this fixture.
	//
	// FanOutPendingEvents globally expands all pending events to matching channels, including
	// trafficEvidenceServer's initial finding and any leftovers from other cases.
	// Without isolation those events reach this fixture's channels, making exact-count assertions
	// intermittently fail depending on test order, harder to diagnose than deterministic errors.
	// Keep fixture effects self-contained.
	if _, err := pg.Exec(`UPDATE notification_events SET fanned_out = true WHERE id <= $1 AND NOT fanned_out`, mark); err != nil {
		t.Fatal(err)
	}

	f := &notifyFixture{s: s, pg: pg, request: request, n: newNotifier(s), taskID: taskID, expID: task.ExpID, cleanupMark: mark}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM notification_events WHERE id > $1`, f.cleanupMark); err != nil {
			t.Logf("cleaning up notification events failed: %v", err)
		}
	})
	// Ensure global notification switch is on; other tests may have disabled it.
	if err := pg.SetBool(settingNotifyEnabled, true); err != nil {
		t.Fatal(err)
	}
	return f
}

// record uses the real evidence/finding persistence path, returning finding ID.
// That transaction also registers the notification event, the feature's integration point.
func (f *notifyFixture) record(t *testing.T, vulnclass, severity string) int64 {
	t.Helper()
	out, err := f.s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID:        f.taskID,
		ExplorationID: f.expID,
		Worker:        "test",
		VulnClass:     vulnclass,
		Name:          vulnclass,
		Severity:      severity,
		Summary:       vulnclass + " \u7684\u6458\u8981",
		Evidence:      "poc",
	}, nil)
	if err != nil {
		t.Fatalf("recording the finding failed: %v", err)
	}
	return out.FindingID
}

// channel reads configuration for per-channel step calls.
func (f *notifyFixture) channel(t *testing.T, id int64) *db.NotificationChannel {
	t.Helper()
	ch, err := f.pg.NotificationChannelByID(context.Background(), id)
	if err != nil {
		t.Fatalf("reading the channel failed: %v", err)
	}
	return ch
}

// deliver fans out events and runs one round for the specified channel only.
func (f *notifyFixture) deliver(t *testing.T, chID int64, baseURL string) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	f.n.stepRealtime(ctx, f.channel(t, chID), 50, baseURL)
}

// createChannel uses HTTP to cover validation too.
func (f *notifyFixture) createChannel(t *testing.T, payload map[string]any) int64 {
	t.Helper()
	raw, _ := json.Marshal(payload)
	r := f.request("POST", "/api/notify/channels", string(raw))
	if r.Code != 200 {
		t.Fatalf("creating the channel failed %d: %s", r.Code, r.Body)
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &res); err != nil || res.ID == 0 {
		t.Fatalf("creating the channel returned an unexpected response: %s (%v)", r.Body, err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM notification_channels WHERE id=$1`, res.ID) })
	return res.ID
}

// fakeWebhook records received request bodies.
type fakeWebhook struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []map[string]any
}

func newFakeWebhook(t *testing.T) *fakeWebhook {
	t.Helper()
	f := &fakeWebhook{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWebhook) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeWebhook) body(t *testing.T, i int) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bodies) {
		t.Fatalf("fake receiver got only %d requests, cannot fetch request %d of them", len(f.bodies), i)
	}
	return f.bodies[i]
}

func (f *fakeWebhook) last(t *testing.T) map[string]any {
	t.Helper()
	if f.count() == 0 {
		t.Fatal("fake receiver got no requests at all")
	}
	return f.body(t, f.count()-1)
}

// markdownText extracts body across platform field conventions:
// DingTalk Markdown/ActionCard text; WeCom Markdown content.
func markdownText(t *testing.T, body map[string]any) string {
	t.Helper()
	for _, key := range []string{"markdown", "actionCard"} {
		section, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"text", "content"} {
			if s, ok := section[field].(string); ok && s != "" {
				return s
			}
		}
	}
	t.Fatalf("no recognizable body in the request: %v", body)
	return ""
}

// agePendingBatch makes pending rows old enough for digest readiness.
func (f *notifyFixture) agePendingBatch(t *testing.T, chID int64) {
	t.Helper()
	if _, err := f.pg.Exec(`UPDATE notification_deliveries SET created_at = now() - interval '2 hours'
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyEndToEndRealtimeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u5b9e\u65f6\u63a8\u9001",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "SQL\u6ce8\u5165", "high")
	f.deliver(t, chID, "")

	if hook.count() != 1 {
		t.Fatalf("should send 1 message, actually %d", hook.count())
	}
	text := markdownText(t, hook.last(t))
	for _, want := range []string{"SQL\u6ce8\u5165", "High", "Summary"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message body is missing %q:\n%s", want, text)
		}
	}
	// Delivery transitions to sent.
	var pending int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state <> $2`,
		chID, db.NotifyStateSent).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("after delivery %d items still not marked sent", pending)
	}
}

func TestNotifyChannelAPIMasksSecretsAndPreservesOnUpdate(t *testing.T) {
	f := newNotifyFixture(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u63a9\u7801\u7528\u4f8b",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=abc123456", "secret": "SECabcdef123456"},
	})

	r := f.request("GET", "/api/notify/channels", "")
	if r.Code != 200 {
		t.Fatalf("listing channels failed %d: %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "abc123456") || strings.Contains(r.Body.String(), "SECabcdef123456") {
		t.Fatalf("the API echo leaked credentials: %s", r.Body)
	}
	var listed struct {
		Channels []struct {
			ID         int64          `json:"id"`
			Config     map[string]any `json:"config"`
			SecretKeys []string       `json:"secret_keys"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var mine *struct {
		ID         int64          `json:"id"`
		Config     map[string]any `json:"config"`
		SecretKeys []string       `json:"secret_keys"`
	}
	for i := range listed.Channels {
		if listed.Channels[i].ID == chID {
			mine = &listed.Channels[i]
		}
	}
	if mine == nil {
		t.Fatal("the new channel does not appear in the list")
	}
	if !notify.IsMasked(fmt.Sprint(mine.Config["webhook"])) || !notify.IsMasked(fmt.Sprint(mine.Config["secret"])) {
		t.Fatalf("credential fields should be masked values: %v", mine.Config)
	}
	if len(mine.SecretKeys) == 0 {
		t.Fatal("the API should tell the front end which fields are credentials")
	}

	// Name-only PATCH with masked credentials preserves actual secrets.
	body, _ := json.Marshal(map[string]any{
		"name":   "\u6539\u540d\u540e",
		"config": map[string]any{"webhook": fmt.Sprint(mine.Config["webhook"]), "secret": fmt.Sprint(mine.Config["secret"])},
	})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("update failed %d: %s", r.Code, r.Body)
	}
	cfg := f.channelConfig(t, chID)
	if cfg["webhook"] != "https://oapi.dingtalk.com/robot/send?access_token=abc123456" {
		t.Fatalf("sending back the mask overwrote the real credential: %v", cfg["webhook"])
	}
	if cfg["secret"] != "SECabcdef123456" {
		t.Fatalf("sending back the mask overwrote the secret value: %v", cfg["secret"])
	}
	if f.channel(t, chID).Name != "\u6539\u540d\u540e" {
		t.Fatal("name not updated")
	}

	// Explicit empty secret clears it, unlike unchanged-mask preservation.
	body, _ = json.Marshal(map[string]any{"config": map[string]any{"secret": ""}})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("clearing secret failed %d: %s", r.Code, r.Body)
	}
	if _, still := f.channelConfig(t, chID)["secret"]; still {
		t.Fatal("an empty string should clear the secret")
	}
}

func (f *notifyFixture) channelConfig(t *testing.T, id int64) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(f.channel(t, id).Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestNotifyChannelAPICreateValidation(t *testing.T) {
	f := newNotifyFixture(t)
	cases := []struct {
		name    string
		payload map[string]any
		wantSub string
	}{
		{"invalid kind", map[string]any{"name": "x", "kind": "nope", "config": map[string]any{}}, "Invalid channel type"},
		{"missing name", map[string]any{"kind": notify.KindDingTalk, "config": map[string]any{"webhook": "https://e.com/h"}}, "Missing channel name"},
		{"missing webhook", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{}}, "webhook URL"},
		{"webhook invalid scheme", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{"webhook": "file:///etc/passwd"}}, "Invalid webhook URL"},
		{"invalid mode", map[string]any{"name": "x", "kind": notify.KindDingTalk, "mode": "sometimes", "config": map[string]any{"webhook": "https://e.com/h"}}, "Invalid notification mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			r := f.request("POST", "/api/notify/channels", string(raw))
			if r.Code != 400 {
				t.Fatalf("should return 400, got %d: %s", r.Code, r.Body)
			}
			if !strings.Contains(r.Body.String(), tc.wantSub) {
				t.Fatalf("the error should mention %q, got %s", tc.wantSub, r.Body)
			}
		})
	}
	if r := f.request("DELETE", "/api/notify/channels/99999999", ""); r.Code != 404 {
		t.Fatalf("deleting a missing channel should return 404, got %d", r.Code)
	}
}

func TestNotifyFilterBlocksBelowThreshold(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u4ec5\u4e25\u91cd",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"min_severity": "critical"},
	})
	f.record(t, "\u4f4e\u5371\u95ee\u9898", "low")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a finding below the threshold must not create a delivery, got %d items", n)
	}
	f.n.stepRealtime(context.Background(), f.channel(t, chID), 50, "")
	if hook.count() != 0 {
		t.Fatal("a filtered finding must not send a message")
	}
}

func TestNotifyDigestBatchesMultipleFindingsIntoOneMessage(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u6c47\u603b\u63a8\u9001",
		"kind":   notify.KindDingTalk,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	for i := 0; i < 3; i++ {
		f.record(t, fmt.Sprintf("\u6c47\u603b\u6f0f\u6d1e%d", i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)

	// Not due: no send.
	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 0 {
		t.Fatal("the digest batch was sent before it was due")
	}

	// After aging, three rows become one message.
	f.agePendingBatch(t, chID)
	f.n.stepDigest(ctx, ch, 50, "")
	if got := hook.count(); got != 1 {
		t.Fatalf("three items should be merged into one message, actually sent %d messages", got)
	}
	text := markdownText(t, hook.last(t))
	if !strings.Contains(text, "last") || !strings.Contains(text, "3 new findings") {
		t.Fatalf("digest message lacks the count/time-window text:\n%s", text)
	}
	for i := 1; i <= 3; i++ {
		if !strings.Contains(text, fmt.Sprintf("\u6c47\u603b\u6f0f\u6d1e%d", i)) {
			t.Fatalf("digest message lacks item %d of the batch:\n%s", i, text)
		}
	}
	// Batch members share batch_id.
	var distinct, total int
	if err := f.pg.QueryRow(`SELECT count(DISTINCT batch_id), count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&distinct, &total); err != nil {
		t.Fatal(err)
	}
	if total != 3 || distinct != 1 {
		t.Fatalf("the three deliveries should share one batch_id, got distinct=%d total=%d", distinct, total)
	}
}

func TestNotifyDisabledChannelDoesNotSend(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":    "\u505c\u7528\u6e20\u9053",
		"kind":    notify.KindDingTalk,
		"enabled": false,
		"config":  map[string]any{"webhook": hook.URL},
	})
	f.record(t, "\u505c\u7528\u671f\u95f4\u7684\u6f0f\u6d1e", "critical")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a disabled channel must not create deliveries, got %d items", n)
	}
}

func TestNotifyStatusChangeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u72b6\u6001\u53d8\u66f4\u8ba2\u9605",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"on_status_change": true},
	})
	finding := f.record(t, "\u72b6\u6001\u53d8\u66f4\u7528\u4f8b", "high")
	r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"fixed"}`)
	if r.Code != 200 {
		t.Fatalf("changing status failed %d: %s", r.Code, r.Body)
	}
	f.deliver(t, chID, "")

	// Two possible messages: fixed transition and finding_created can both send this round.
	// Status change is newer, but search all rather than relying on order.
	found := false
	for i := 0; i < hook.count(); i++ {
		text := markdownText(t, hook.body(t, i))
		if strings.Contains(text, "Status change") && strings.Contains(text, "Fixed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no message containing the status change \u2192 fixed received (total %d messages)", hook.count())
	}
}

func TestNotifyStatusChangeSuppressedByDefault(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u4e0d\u8ba2\u9605\u72b6\u6001\u53d8\u66f4",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "\u4e0d\u8ba2\u9605\u53d8\u66f4", "high")
	if r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"false_positive"}`); r.Code != 200 {
		t.Fatalf("changing status failed %d: %s", r.Code, r.Body)
	}
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
WHERE d.channel_id=$1 AND e.kind=$2`, chID, notify.EventFindingStatusChanged).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a channel not subscribed to status changes must not get status-change deliveries, got %d items", n)
	}
}

func TestNotifyTestMessageEndpoint(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u6d4b\u8bd5\u53d1\u9001",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", chID), ""); r.Code != 200 {
		t.Fatalf("test send failed %d: %s", r.Code, r.Body)
	}
	if hook.count() != 1 {
		t.Fatalf("the fake receiver should get 1 test message, got %d", hook.count())
	}
	// Test message is unmistakable, not a real finding.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "test") {
		t.Fatalf("the test message should say it is a test: %s", text)
	}
	// Return original adapter diagnostics for broken configuration.
	badID := f.createChannel(t, map[string]any{
		"name":   "\u574f\u5730\u5740",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", badID), ""); r.Code != 502 {
		t.Fatalf("a delivery failure should return 502, got %d: %s", r.Code, r.Body)
	}
}

func TestNotifyDeliveriesHistoryAndRetry(t *testing.T) {
	f := newNotifyFixture(t)
	// Guaranteed unreachable endpoint produces failed delivery.
	chID := f.createChannel(t, map[string]any{
		"name":   "\u5931\u8d25\u91cd\u8bd5",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	f.record(t, "\u4f1a\u5931\u8d25\u7684\u63a8\u9001", "high")
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)
	// Send until retry budget is exhausted.
	for i := 0; i < db.MaxNotifyAttempts; i++ {
		f.n.stepRealtime(ctx, ch, 50, "")
		if _, err := f.pg.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE channel_id=$1`, chID); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := f.pg.QueryRow(`SELECT state FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStateFailed {
		t.Fatalf("after retries are exhausted it should be failed, got %s", state)
	}

	r := f.request("GET", fmt.Sprintf("/api/notify/deliveries?channel_id=%d&state=failed", chID), "")
	if r.Code != 200 {
		t.Fatalf("querying history failed %d: %s", r.Code, r.Body)
	}
	var hist struct {
		Deliveries []struct {
			ID        int64  `json:"id"`
			State     string `json:"state"`
			LastError string `json:"last_error"`
			Attempts  int    `json:"attempts"`
			Title     string `json:"title"`
		} `json:"deliveries"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Total != 1 || len(hist.Deliveries) != 1 {
		t.Fatalf("should find 1 failed delivery, got total=%d len=%d", hist.Total, len(hist.Deliveries))
	}
	if hist.Deliveries[0].LastError == "" {
		t.Fatal("history should include the failure reason, otherwise users cannot debug it")
	}
	if hist.Deliveries[0].Attempts < db.MaxNotifyAttempts {
		t.Fatalf("attempts should be recorded, got %d", hist.Deliveries[0].Attempts)
	}
	if hist.Deliveries[0].Title != "\u4f1a\u5931\u8d25\u7684\u63a8\u9001" {
		t.Fatalf("history should carry the finding title, got %q", hist.Deliveries[0].Title)
	}

	// Manual retry returns pending and resets attempts.
	if r := f.request("POST", fmt.Sprintf("/api/notify/deliveries/%d/retry", hist.Deliveries[0].ID), ""); r.Code != 200 {
		t.Fatalf("resend failed %d: %s", r.Code, r.Body)
	}
	var attempts int
	if err := f.pg.QueryRow(`SELECT state, attempts FROM notification_deliveries WHERE id=$1`, hist.Deliveries[0].ID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStatePending || attempts != 0 {
		t.Fatalf("after a resend it should be pending and attempts=0, got %s/%d", state, attempts)
	}
}

func TestNotifyMetaAndSettingsRoundTrip(t *testing.T) {
	f := newNotifyFixture(t)
	r := f.request("GET", "/api/notify/meta", "")
	if r.Code != 200 {
		t.Fatalf("meta failed: %s", r.Body)
	}
	var meta struct {
		Kinds []struct {
			Kind       string   `json:"kind"`
			SecretKeys []string `json:"secret_keys"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Kinds) != len(notify.Kinds()) {
		t.Fatalf("meta should list all %d channels, got %d", len(notify.Kinds()), len(meta.Kinds))
	}
	for _, k := range meta.Kinds {
		if len(k.SecretKeys) == 0 {
			t.Errorf("channel %s reports no credential fields", k.Kind)
		}
	}

	// Round-trip three global settings; trim slash to avoid //function links.
	if r := f.request("PUT", "/api/settings", `{"notify_public_base_url":"https://artex.example.com/","notify_digest_interval_min":15,"notify_enabled":true}`); r.Code != 200 {
		t.Fatalf("writing settings failed %d: %s", r.Code, r.Body)
	}
	t.Cleanup(func() {
		f.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, settingNotifyPublicBaseURL, settingNotifyDigestMinutes)
	})
	payload := f.s.settingsPayload()
	if payload["notify_public_base_url"] != "https://artex.example.com" {
		t.Fatalf("link-back URL not normalized: %v", payload["notify_public_base_url"])
	}
	if payload["notify_digest_interval_min"] != 15 {
		t.Fatalf("digest period not applied: %v", payload["notify_digest_interval_min"])
	}

	// Reject invalid values.
	for _, body := range []string{
		`{"notify_public_base_url":"ftp://x"}`,
		`{"notify_digest_interval_min":0}`,
		`{"notify_digest_interval_min":99999}`,
	} {
		if r := f.request("PUT", "/api/settings", body); r.Code != 400 {
			t.Errorf("%s should return 400, got %d", body, r.Code)
		}
	}
}

// TestNotifyDeepLinkUsesPublicBaseURL requires one-item ActionCard with detail button when
// public_base_url is configured.
func TestNotifyDeepLinkUsesPublicBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u56de\u94fe",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "\u5e26\u56de\u94fe\u7684\u6f0f\u6d1e", "high")
	f.deliver(t, chID, "https://artex.example.com")

	body := hook.last(t)
	card, _ := body["actionCard"].(map[string]any)
	if card == nil {
		t.Fatalf("with a link-back it should use ActionCard, got msgtype=%v", body["msgtype"])
	}
	want := fmt.Sprintf("https://artex.example.com/function/findings/detail?id=%d", finding)
	if card["singleURL"] != want {
		t.Fatalf("wrong link-back\nwant %s\ngot %v", want, card["singleURL"])
	}
}

// TestNotifyNoDeepLinkWithoutBaseURL falls back to Markdown without external base rather than
// emitting bad localhost/relative links.
func TestNotifyNoDeepLinkWithoutBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "\u65e0\u56de\u94fe",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "\u65e0\u56de\u94fe\u7684\u6f0f\u6d1e", "high")
	f.deliver(t, chID, "")

	body := hook.last(t)
	if body["msgtype"] != "markdown" {
		t.Fatalf("without an external URL it should send markdown, got %v", body["msgtype"])
	}
	if text := markdownText(t, body); strings.Contains(text, "View details") {
		t.Fatalf("without an external URL there must be no detail link:\n%s", text)
	}
}

// TestNotifyDigestSegmentsAndDefersRemainder verifies the silent-loss fix end to end.
//
// WeCom's 4096-byte bound requires splitting between whole items; mark included rows delivered,
// return others to queue. Previously marking the full batch successful lost omitted findings
// from message/failure history while falsely reporting complete success.
// Retain every unrendered item for later delivery.
//
// Assert included count, pending remainder, no retry-budget charge for deferral, and next-round
// progress rather than permanent blockage.
func TestNotifyDigestSegmentsAndDefersRemainder(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	// WeCom is the tightest limit among six adapters, at 4096 bytes.
	chID := f.createChannel(t, map[string]any{
		"name":   "\u5206\u6bb5\u6c47\u603b",
		"kind":   notify.KindWeCom,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	const total = 60
	// Long titles make 60 entries certainly require segmentation.
	longName := strings.Repeat("\u8d85\u957f\u6f0f\u6d1e\u540d\u79f0", 6)
	for i := 0; i < total; i++ {
		f.record(t, longName+strconv.Itoa(i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	f.agePendingBatch(t, chID)
	ch := f.channel(t, chID)

	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 1 {
		t.Fatalf("should send only one message, got %d", hook.count())
	}

	var sent, pending int
	if err := f.pg.QueryRow(`SELECT
    count(*) FILTER (WHERE state=$2),
    count(*) FILTER (WHERE state=$3)
  FROM notification_deliveries WHERE channel_id=$1`, chID, db.NotifyStateSent, db.NotifyStatePending).
		Scan(&sent, &pending); err != nil {
		t.Fatal(err)
	}
	if sent == 0 {
		t.Fatal("some items should be marked delivered")
	}
	if pending == 0 {
		t.Fatalf("a batch of %d items cannot all fit in 4096 bytes, some should remain pending;sent=%d", total, sent)
	}
	if sent+pending != total {
		t.Fatalf("item counts do not add up: sent=%d pending=%d total=%d (neither delivered nor pending = lost)", sent, pending, total)
	}
	// Message must accurately state remaining count.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "remaining") {
		t.Fatalf("the message should state that some items are not included:\n%.400s", text)
	}

	// Deferred rows must not consume retries.
	var maxAttempts int
	if err := f.pg.QueryRow(`SELECT COALESCE(max(attempts),0) FROM notification_deliveries
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	if maxAttempts > 0 {
		t.Fatalf("deferred items must not consume retries (otherwise they would fail after a few messages), got attempts=%d", maxAttempts)
	}

	// Repeat until every item is delivered across multiple rounds. This proves
	// segmentation neither stalls nor discards the remainder, beyond a two-round assumption.
	rounds := 0
	for {
		var undelivered int
		if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries
WHERE channel_id=$1 AND state <> $2 AND state <> $3`, chID, db.NotifyStateSent, db.NotifyStateFailed).
			Scan(&undelivered); err != nil {
			t.Fatal(err)
		}
		if undelivered == 0 {
			break
		}
		rounds++
		if rounds > total+5 {
			t.Fatalf("segmented delivery does not converge: after %d rounds %d items are still unresolved", rounds, undelivered)
		}
		before := hook.count()
		f.n.stepDigest(ctx, ch, 50, "")
		if hook.count() == before {
			t.Fatalf("round %d made no progress; the remaining %d items would be stuck forever", rounds, undelivered)
		}
	}
	if rounds < 2 {
		t.Fatalf("a 4096 byte message cannot hold %d findings with long titles, so it should take several rounds, but used only %d rounds", total, rounds)
	}
	// Every round after the first is continuation only, without channel-rejected items.
	var failed int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state=$2`,
		chID, db.NotifyStateFailed).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Fatalf("the fake receiver always succeeds, so there should be no failed items, got %d", failed)
	}
}

// TestNotifyBackoffMatchesAttemptBudget prevents retry-policy/backoff drift.
//
// Backoff length must match the attempt budget.
// Independent constants can drift during future changes.
// Increasing attempts without extending backoff silently reuses the final delay for later attempts,
// producing unexplained pacing changes instead of a runtime error.
// Assert equal lengths so CI exposes drift.
func TestNotifyBackoffTableMatchesAttemptBudget(t *testing.T) {
	if len(notifyBackoff) != db.MaxNotifyAttempts {
		t.Fatalf("number of backoff steps (%d) and max attempts (%d) differ\u2014\u2014change one and you must change the other",
			len(notifyBackoff), db.MaxNotifyAttempts)
	}
	// Backoff intervals must be nondecreasing to avoid worsening throttling.
	for i := 1; i < len(notifyBackoff); i++ {
		if notifyBackoff[i] < notifyBackoff[i-1] {
			t.Fatalf("backoff intervals must be non-decreasing: step %d is %v < step %d is %v",
				i, notifyBackoff[i], i-1, notifyBackoff[i-1])
		}
	}
}

// TestNotifyRateLimitDoesNotConsumeRetryBudget requires token checks before claims.
// Claim-then-discard increments attempts for throttled unsent deliveries,
// exhausting budgets on waiting alone.
func TestNotifyRateLimitDoesNotConsumeRetryBudget(t *testing.T) {
	// Test token bucket directly without unnecessary Server fixtures.
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// One per minute: full bucket permits at most one.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now); got != 1 {
		t.Fatalf("with a full bucket at 1 per minute, should take 1 token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("after tokens run out it should return 0, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(30*time.Second)); got != 0 {
		t.Fatalf("half a period must not refill a whole token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Minute)); got != 1 {
		t.Fatalf("a full period should refill 1 token, got %d", got)
	}
	// Unlimited channels still use finite per-round bounds.
	if got := n.takeTokens(2, 0, notifyUnlimitedBurstPerTick+10, now); got != notifyUnlimitedBurstPerTick {
		t.Fatalf("unlimited should return the per-round cap %d, got %d", notifyUnlimitedBurstPerTick, got)
	}
	// Per-channel buckets are independent.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("channel 1 bucket should still be empty, got %d", got)
	}
}

// TestNotifyTakeTokensKeepsUnusedTokens enforces taking only want.
//
// Draining before caller-side capping discarded 95 of 100 tokens when only five were needed,
// and even charged rounds with no pending deliveries.
// That made advertised full-rate backlog bursts impossible.
func TestNotifyTakeTokensKeepsUnusedTokens(t *testing.T) {
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// Initially full 100-token bucket; request five.
	if got := n.takeTokens(1, 100, 5, now); got != 5 {
		t.Fatalf("want=5 should take exactly 5 tokens, got %d", got)
	}
	// Remaining 95 must still exist.
	// Do not advance time; remaining tokens must come from stored capacity, not refill.
	if got := n.takeTokens(1, 100, 95, now); got != 95 {
		t.Fatalf("remaining tokens should still be available (want 95), got %d\u2014\u2014the bucket was drained by a whole round", got)
	}
	if got := n.takeTokens(1, 100, 1, now); got != 0 {
		t.Fatalf("bucket is empty, should return 0, got %d", got)
	}
	// want<=0 deducts nothing; empty rounds are free.
	n2 := &Notifier{buckets: map[int64]*notifyBucket{}}
	if got := n2.takeTokens(1, 20, 0, now); got != 0 {
		t.Fatalf("want=0 should return 0, got %d", got)
	}
	if got := n2.takeTokens(1, 20, 20, now); got != 20 {
		t.Fatalf("want=0 must not consume tokens, should still allow the full 20, got %d", got)
	}
}

// TestDigestTickPlanDecouplesBatchSizeFromSendBudget preserves distinct units.
//
// Tying batch size to rate allowance makes 20/min refill one token each 3-second tick,
// producing one-finding digests with misleading 30-minute digest headings.
// This silent regression behaves like no aggregation at all.
// End-to-end cases manually pass large stepDigest limits, bypassing step's calculation,
// so directly assert the planning decision here.
func TestDigestTickPlanDecouplesBatchSizeFromSendBudget(t *testing.T) {
	tokens, claimLimit := digestTickPlan()
	// One batch = one message = one request = one token, regardless of finding count.
	if tokens != 1 {
		t.Fatalf("a digest batch sends one message and should consume exactly 1 token, got %d", tokens)
	}
	if claimLimit != db.MaxDigestBatchSize {
		t.Fatalf("digest batch size should be the in-memory cap db.MaxDigestBatchSize=%d, got %d",
			db.MaxDigestBatchSize, claimLimit)
	}
	// Batch size must greatly exceed per-round send allowance, preventing these dimensions
	// from collapsing into one number.
	if claimLimit <= notifyMaxSendsPerChannelPerTick {
		t.Fatalf("digest batch size %d must not be limited by the per-round request budget %d \u2014\u2014"+
			"the request budget is 'how many requests to send', derived from the lease, while 'how many findings fit in a batch' is a different dimension",
			claimLimit, notifyMaxSendsPerChannelPerTick)
	}
}

// TestNotifyTickBudgetFitsWithinLease prevents independent-constant drift.
//
// Derive per-channel send cap from lease duration: worst-case serial send time must remain
// below lease or another instance can reclaim and duplicate later sends before completion.
// These three constants live separately; changing any could silently break the relation,
// so lock it with an assertion.
func TestNotifyTickBudgetFitsWithinLease(t *testing.T) {
	worst := time.Duration(notifyMaxSendsPerChannelPerTick) * notifySendTimeout
	if worst >= notifyLease {
		t.Fatalf("worst-case time for one channel round %v must not reach or exceed the lease %v"+
			" (notifyMaxSendsPerChannelPerTick=%d × notifySendTimeout=%v) -- "+
			"changing any one of these three constants requires re-checking the other two",
			worst, notifyLease, notifyMaxSendsPerChannelPerTick, notifySendTimeout)
	}
}
