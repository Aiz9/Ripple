package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/internal/notify"
)

// These tests require real PostgreSQL (skip without it): FOR UPDATE SKIP LOCKED, make_interval,
// JSONB, and multirow IN placeholder construction can compile yet fail at runtime, so actual
// database execution is required to validate them.

func notifyTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// newTestChannel creates a channel removed automatically after testing.
func newTestChannel(t *testing.T, d *DB, kind, mode string, filter string) *NotificationChannel {
	t.Helper()
	if filter == "" {
		filter = `{}`
	}
	ch := &NotificationChannel{
		Name:       "\u6d4b\u8bd5\u6e20\u9053-" + t.Name(),
		Kind:       kind,
		Mode:       mode,
		Config:     json.RawMessage(`{"webhook":"https://example.com/hook"}`),
		Filter:     json.RawMessage(filter),
		RatePerMin: 100,
	}
	id, err := d.SaveNotificationChannel(context.Background(), ch)
	if err != nil {
		t.Fatalf("creating the channel failed: %v", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_channels WHERE id=$1`, id) })
	ch.ID = id
	return ch
}

// addTestEvent inserts directly without a finding to test fanout/delivery.
func addTestEvent(t *testing.T, d *DB, kind string, findingID int64, snap notify.Snapshot) int64 {
	t.Helper()
	snap.Kind = kind
	snap.FindingID = findingID
	id, err := d.AddNotificationEvent(context.Background(), kind, findingID, snap)
	if err != nil {
		t.Fatalf("writing the event failed: %v", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_events WHERE id=$1`, id) })
	return id
}

func TestNotificationAssetNamesResolvesAndPreservesOrder(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	// Domains, IPs, and URLs each have distinct display conventions.
	insertAsset := func(query, value string) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(query, value).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	domID := insertAsset(`INSERT INTO assets(type, domain) VALUES('subdomain',$1) RETURNING id`, "a.example.com")
	ipID := insertAsset(`INSERT INTO assets(type, ip) VALUES('ip',$1) RETURNING id`, "10.1.2.3")
	svcID := insertAsset(`INSERT INTO assets(type, url) VALUES('service',$1) RETURNING id`, "https://a.example.com/admin")
	t.Cleanup(func() {
		d.Exec(`DELETE FROM assets WHERE id IN ($1,$2,$3)`, domID, ipID, svcID)
	})

	// Intentionally unordered IDs include one nonexistent row.
	got, err := d.NotificationAssetNames(ctx, []int64{svcID, 999999999, domID, ipID, svcID})
	if err != nil {
		t.Fatalf("parsing asset names failed: %v", err)
	}
	want := []string{"https://a.example.com/admin", "a.example.com", "10.1.2.3"}
	if len(got) != len(want) {
		t.Fatalf("asset name count mismatch, want %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order/value mismatch, want %v got %v", want, got)
		}
	}
}

// TestRecordNotificationEventTxUnwindsOnFailure exercises savepoint isolation:
// force notification_events INSERT failure with a temporary always-false constraint, then assert
// false is returned and the surrounding transaction still executes subsequent statements.
//
// Without SAVEPOINT the whole PostgreSQL transaction aborts; every later statement fails with
// current transaction is aborted, reproducing a notification-table issue preventing finding
// persistence.
//
// End with ROLLBACK, not COMMIT: PostgreSQL ALTER TABLE is transactional; committing would
// permanently retain the temporary constraint and break subsequent tests.
// Rollback automatically undoes DDL. We only need to prove the transaction remains usable,
// not actually commit it.
func TestRecordNotificationEventTxUnwindsOnFailure(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	// Defensively remove a constraint left by historical runs.
	if _, err := d.Exec(`ALTER TABLE notification_events DROP CONSTRAINT IF EXISTS notify_test_never`); err != nil {
		t.Fatal(err)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // Undo temporary constraint as described above.

	// NOT VALID applies only to future writes, ignoring historical event rows that might violate it
	// and otherwise prevent adding the constraint.
	if _, err := tx.ExecContext(ctx, `ALTER TABLE notification_events ADD CONSTRAINT notify_test_never CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("adding the temporary constraint failed: %v", err)
	}
	if RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, 1, notify.Snapshot{Severity: "high"}) {
		t.Fatal("reported a successful write under a constraint that must fail")
	}
	// Key assertion: transaction still works.
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("the transaction was poisoned (savepoint did not take effect): %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	// Confirm rollback removed DDL so later tests are unaffected.
	var exists bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='notify_test_never')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("the temporary constraint was not undone by the rollback and would pollute later cases")
	}
}

func TestFanOutRoutesEventsByFilter(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	all := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	onlyCritical := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{"min_severity":"critical"}`)
	sqlOnly := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{"vulnclass_include":["SQL"]}`)

	highSQL := addTestEvent(t, d, notify.EventFindingCreated, 1001, notify.Snapshot{Severity: "high", VulnClass: "SQL\u6ce8\u5165"})
	lowXSS := addTestEvent(t, d, notify.EventFindingCreated, 1002, notify.Snapshot{Severity: "low", VulnClass: "XSS"})
	criticalXSS := addTestEvent(t, d, notify.EventFindingCreated, 1003, notify.Snapshot{Severity: "critical", VulnClass: "XSS"})

	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	cases := []struct {
		name    string
		eventID int64
		channel int64
		want    bool
	}{
		{"accept-all channel receives high", highSQL, all.ID, true},
		{"accept-all channel receives low", lowXSS, all.ID, true},
		{"critical-only channel skips high", highSQL, onlyCritical.ID, false},
		{"critical-only channel receives critical", criticalXSS, onlyCritical.ID, true},
		{"SQL-only channel receives SQL", highSQL, sqlOnly.ID, true},
		{"SQL-only channel skips XSS", lowXSS, sqlOnly.ID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var exists bool
			if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM notification_deliveries WHERE event_id=$1 AND channel_id=$2)`,
				tc.eventID, tc.channel).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists != tc.want {
				t.Fatalf("delivery exists: want %v got %v", tc.want, exists)
			}
		})
	}

	// Repeated fanout must not create duplicate deliveries (fanned_out idempotence).
	events, deliveries, err := d.FanOutPendingEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if events != 0 || deliveries != 0 {
		t.Fatalf("an already dispatched event must not be processed again, got events=%d deliveries=%d", events, deliveries)
	}
}

// TestFanOutMarksEventsWithNoMatchingChannel covers events matching no channel.
// Mark them fanned out anyway, avoiding permanent rescanning on every tick.
func TestFanOutMarksEventsWithNoMatchingChannel(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	pick := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, "{\"vulnclass_include\":[\"\u7edd\u4e0d\u5339\u914d\u7684\u7c7b\u578b\"]}")
	_ = pick

	ev := addTestEvent(t, d, notify.EventFindingCreated, 2001, notify.Snapshot{Severity: "high", VulnClass: "XSS"})
	_, deliveries, err := d.FanOutPendingEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 {
		t.Fatalf("no delivery expected, got %d", deliveries)
	}
	var fanned bool
	if err := d.QueryRowContext(ctx, `SELECT fanned_out FROM notification_events WHERE id=$1`, ev).Scan(&fanned); err != nil {
		t.Fatal(err)
	}
	if !fanned {
		t.Fatal("events matching no channel must still be marked dispatched, otherwise they are rescanned forever")
	}
}

func TestClaimRealtimeDeliveriesHonorsLeaseAndMode(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	realtime := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	digest := newTestChannel(t, d, notify.KindDingTalk, NotifyModeDigest, `{}`)

	addTestEvent(t, d, notify.EventFindingCreated, 3001, notify.Snapshot{Severity: "high", VulnClass: "XSS"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}

	// Realtime claims must touch realtime delivery only, leaving digest rows unchanged.
	got, err := d.ClaimRealtimeDeliveries(ctx, realtime.ID, 10, time.Minute)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("should claim 1 item, got %d", len(got))
	}
	if got[0].State != NotifyStateSending || got[0].Attempts != 1 {
		t.Fatalf("after claiming it should be sending and attempts=1, got state=%s attempts=%d", got[0].State, got[0].Attempts)
	}
	// Joined rendering context includes channel config, event snapshot, and finding ID.
	if got[0].Channel == nil || len(got[0].Channel.Config) == 0 {
		t.Fatal("claimed result lacks the channel config, rendering would fail")
	}
	if got[0].FindingID != 3001 {
		t.Fatalf("finding id not carried over from the event, got %d", got[0].FindingID)
	}

	// A second claim before lease expiry returns empty, ensuring two dispatchers cannot deliver
	// the same row concurrently.
	again, err := d.ClaimRealtimeDeliveries(ctx, realtime.ID, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("must not be claimed again within the lease, got %d items", len(again))
	}

	// Realtime claiming must not touch digest channels.
	left, err := d.ClaimRealtimeDeliveries(ctx, digest.ID, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("a realtime claim must not take digest channel deliveries, got %d items", len(left))
	}
}

// TestClaimExpiredLeaseRecovers verifies crashed sending rows become claimable after lease
// expiry rather than remaining stuck forever.
func TestClaimExpiredLeaseRecovers(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	addTestEvent(t, d, notify.EventFindingCreated, 4001, notify.Snapshot{Severity: "high"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	first, err := d.ClaimRealtimeDeliveries(ctx, ch.ID, 10, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim failed: %v (%d items)", err, len(first))
	}
	// Move lease into the past to simulate expiry.
	if _, err := d.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE id=$1`, first[0].ID); err != nil {
		t.Fatal(err)
	}
	second, err := d.ClaimRealtimeDeliveries(ctx, ch.ID, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Fatalf("a sending row with an expired lease should be claimable again, got %d items", len(second))
	}
	if second[0].Attempts != 2 {
		t.Fatalf("reclaiming should increment attempts, got %d", second[0].Attempts)
	}
}

func TestClaimSkipsDisabledChannel(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	addTestEvent(t, d, notify.EventFindingCreated, 5001, notify.Snapshot{Severity: "high"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	// Disabling marks existing unsent rows skipped.
	if err := d.SetNotificationChannelEnabled(ctx, ch.ID, false); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM notification_deliveries WHERE channel_id=$1`, ch.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != NotifyStateSkipped {
		t.Fatalf("pending deliveries of a disabled channel should be marked skipped, got %s", state)
	}
	got, err := d.ClaimRealtimeDeliveries(ctx, ch.ID, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a disabled channel must not be claimable, got %d items", len(got))
	}
}

func TestDigestBatchDueAndStableBatchID(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeDigest, `{}`)
	for i := 0; i < 3; i++ {
		addTestEvent(t, d, notify.EventFindingCreated, int64(6000+i), notify.Snapshot{Severity: "high"})
	}
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}

	// A newly created batch of age zero is not due in a 30-minute period.
	due, err := d.DigestBatchDue(ctx, ch.ID, 30*time.Minute)
	if err != nil {
		t.Fatalf("checking batch expiry failed: %v", err)
	}
	if due {
		t.Fatal("a freshly created batch must not expire immediately")
	}

	// Age all three rows to simulate a due batch.
	if _, err := d.Exec(`UPDATE notification_deliveries SET created_at = now() - interval '40 minutes' WHERE channel_id=$1`, ch.ID); err != nil {
		t.Fatal(err)
	}
	due, err = d.DigestBatchDue(ctx, ch.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !due {
		t.Fatal("a batch past its period should be judged expired")
	}

	batch, err := d.ClaimDigestBatch(ctx, ch.ID, MaxDigestBatchSize, time.Minute)
	if err != nil {
		t.Fatalf("claiming the digest batch failed: %v", err)
	}
	if len(batch) != 3 {
		t.Fatalf("a digest should claim all 3 items at once, got %d items", len(batch))
	}
	if batch[0].BatchID == nil {
		t.Fatal("a digest batch must write batch_id, otherwise history cannot show these were sent together")
	}
	firstBatchID := *batch[0].BatchID
	for _, dl := range batch {
		if dl.BatchID == nil || *dl.BatchID != firstBatchID {
			t.Fatalf("the same batch should share batch_id, got %v vs %d", dl.BatchID, firstBatchID)
		}
	}

	// Reschedule the entire failed batch and reclaim it; COALESCE must retain original batch_id
	// so retries preserve the fact that these items were sent together.
	//
	// Reschedule all members, matching the digest engine's one-message/all-members semantics.
	// Rescheduling only one would leave others leased and reclaim only that single item,
	// invalidating the test of whole-batch identity.
	allIDs := make([]int64, 0, len(batch))
	for _, dl := range batch {
		allIDs = append(allIDs, dl.ID)
	}
	if err := d.RescheduleDeliveries(ctx, allIDs, time.Second, "\u6a21\u62df\u5931\u8d25"); err != nil {
		t.Fatal(err)
	}
	// Expire the lease to simulate elapsed backoff.
	if _, err := d.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE channel_id=$1`, ch.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := d.ClaimDigestBatch(ctx, ch.ID, MaxDigestBatchSize, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(reclaimed) != 3 {
		t.Fatalf("reclaiming should get all 3 items, got %d", len(reclaimed))
	}
	if reclaimed[0].BatchID == nil || *reclaimed[0].BatchID != firstBatchID {
		t.Fatalf("after a retry batch_id should keep its value %d, got %v", firstBatchID, reclaimed[0].BatchID)
	}
}

func TestDeliveryStateTransitions(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	addTestEvent(t, d, notify.EventFindingCreated, 7001, notify.Snapshot{Severity: "high"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	got, err := d.ClaimRealtimeDeliveries(ctx, ch.ID, 10, time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim failed: %v (%d)", err, len(got))
	}
	id := got[0].ID

	if err := d.RescheduleDeliveries(ctx, []int64{id}, time.Second, "\u7f51\u7edc\u6296\u52a8"); err != nil {
		t.Fatal(err)
	}
	var state, lastErr string
	if err := d.QueryRow(`SELECT state, last_error FROM notification_deliveries WHERE id=$1`, id).Scan(&state, &lastErr); err != nil {
		t.Fatal(err)
	}
	if state != NotifyStatePending || lastErr != "\u7f51\u7edc\u6296\u52a8" {
		t.Fatalf("after requeue it should be pending with the reason recorded, got state=%s err=%q", state, lastErr)
	}

	if err := d.FailDeliveries(ctx, []int64{id}, "\u91cd\u8bd5\u8017\u5c3d"); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT state FROM notification_deliveries WHERE id=$1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != NotifyStateFailed {
		t.Fatalf("should be failed, got %s", state)
	}

	// Manual retry resets attempts and becomes due now, without inheriting the old failure budget.
	if err := d.RetryNotificationDelivery(ctx, id); err != nil {
		t.Fatalf("resend failed: %v", err)
	}
	var attempts int
	var next time.Time
	if err := d.QueryRow(`SELECT state, attempts, next_attempt_at FROM notification_deliveries WHERE id=$1`, id).Scan(&state, &attempts, &next); err != nil {
		t.Fatal(err)
	}
	if state != NotifyStatePending || attempts != 0 {
		t.Fatalf("after a resend it should be pending and attempts=0, got state=%s attempts=%d", state, attempts)
	}
	if next.After(time.Now().Add(time.Second)) {
		t.Fatal("a resend should be claimable immediately")
	}

	// Delivered rows cannot be retried.
	if err := d.MarkDeliveriesSent(ctx, []int64{id}); err != nil {
		t.Fatal(err)
	}
	if err := d.RetryNotificationDelivery(ctx, id); err == nil {
		t.Fatal("a delivered delivery must not be resendable")
	}
}

func TestListNotificationDeliveriesPagingAndFilter(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	for i := 0; i < 5; i++ {
		addTestEvent(t, d, notify.EventFindingCreated, int64(8000+i), notify.Snapshot{Severity: "high", Name: "\u5206\u9875\u6d4b\u8bd5"})
	}
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimRealtimeDeliveries(ctx, ch.ID, 10, time.Minute); err != nil {
		t.Fatal(err)
	}

	page1, total, err := d.ListNotificationDeliveries(ctx, NotificationDeliveryFilter{ChannelID: ch.ID, State: NotifyStateSending}, 1, 2)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if total != 5 {
		t.Fatalf("total should be 5, got %d", total)
	}
	if len(page1) != 2 {
		t.Fatalf("per page 2 items, got %d", len(page1))
	}
	// Newest first: first-page ID exceeds second-page ID.
	page2, _, err := d.ListNotificationDeliveries(ctx, NotificationDeliveryFilter{ChannelID: ch.ID, State: NotifyStateSending}, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 || page2[0].ID >= page1[0].ID {
		t.Fatalf("pages should list newest first, got page1[0]=%d page2[0]=%d", page1[0].ID, page2[0].ID)
	}
	// History returns rendering context so UI can show what was sent.
	if page1[0].ChannelName == "" || page1[0].FindingID == 0 {
		t.Fatalf("history item lacks display fields: %+v", page1[0])
	}

	// State filtering finds no pending rows.
	pending, totalPending, err := d.ListNotificationDeliveries(ctx, NotificationDeliveryFilter{ChannelID: ch.ID, State: NotifyStatePending}, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if totalPending != 0 || len(pending) != 0 {
		t.Fatalf("there should be no pending deliveries, got %d items (total=%d)", len(pending), totalPending)
	}
}

func TestSetFindingStatusWithNotifyOnlyEmitsOnRealChange(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	tk, err := d.CreateTask("\u901a\u77e5\u72b6\u6001\u53d8\u66f4\u6d4b\u8bd5", "\u76ee\u6807", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	f, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "test", VulnClass: "SQL\u6ce8\u5165", Name: "\u72b6\u6001\u53d8\u66f4\u7528\u4f8b",
		Severity: "high", Summary: "\u6458\u8981",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_events WHERE finding_id=$1`, f.FindingID) })

	// Count the finding_created event inserted with the finding as baseline.
	var base int
	if err := d.QueryRow(`SELECT count(*) FROM notification_events WHERE finding_id=$1`, f.FindingID).Scan(&base); err != nil {
		t.Fatal(err)
	}
	if base < 1 {
		t.Fatal("recording a finding must register a notification event in the same transaction")
	}

	// Same status must not generate duplicate notification noise.
	from, found, notified, err := d.SetFindingStatusWithNotify(ctx, f.FindingID, "pending")
	if err != nil || !found {
		t.Fatalf("setting status failed: found=%v err=%v", found, err)
	}
	if notified {
		t.Fatal("no notification event should be registered when the status does not change")
	}
	if from != "pending" {
		t.Fatalf("should return the previous status pending, got %q", from)
	}

	// Real transition creates an event with correct from/to.
	from, found, notified, err = d.SetFindingStatusWithNotify(ctx, f.FindingID, "fixed")
	if err != nil || !found {
		t.Fatalf("setting status failed: found=%v err=%v", found, err)
	}
	if !notified {
		t.Fatal("a notification event should be registered when the status actually changes")
	}
	if from != "pending" {
		t.Fatalf("from should be pending, got %q", from)
	}
	var snapshot []byte
	if err := d.QueryRow(`SELECT snapshot FROM notification_events WHERE finding_id=$1 AND kind=$2`,
		f.FindingID, notify.EventFindingStatusChanged).Scan(&snapshot); err != nil {
		t.Fatalf("status-change event not found: %v", err)
	}
	var snap notify.Snapshot
	if err := json.Unmarshal(snapshot, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.FromStatus != "pending" || snap.ToStatus != "fixed" {
		t.Fatalf("wrong status transition in the snapshot: %s \u2192 %s", snap.FromStatus, snap.ToStatus)
	}
	// Snapshot contains rendering fields so status-change messages are not empty shells.
	if snap.VulnClass != "SQL\u6ce8\u5165" || snap.Severity != "high" || snap.Name != "\u72b6\u6001\u53d8\u66f4\u7528\u4f8b" {
		t.Fatalf("snapshot lacks render fields: %+v", snap)
	}
	var status string
	if err := d.QueryRow(`SELECT status FROM findings WHERE id=$1`, f.FindingID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "fixed" {
		t.Fatalf("status should be updated to fixed, got %s", status)
	}

	// Missing finding: found=false, no error.
	if _, found, _, err := d.SetFindingStatusWithNotify(ctx, 999999999, "fixed"); err != nil || found {
		t.Fatalf("a missing finding should return found=false with no error, got found=%v err=%v", found, err)
	}
}

func TestNotificationStatsSnapshot(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	addTestEvent(t, d, notify.EventFindingCreated, 9001, notify.Snapshot{Severity: "high"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	stats, err := d.NotificationStatsSnapshot(ctx)
	if err != nil {
		t.Fatalf("stats failed: %v", err)
	}
	if stats.Channels < 1 || stats.ChannelsOn < 1 {
		t.Fatalf("wrong channel counts: %+v", stats)
	}
	if stats.Pending < 1 {
		t.Fatalf("pending deliveries should be counted: %+v", stats)
	}
	// Newly created backlog age is near zero, neither negative nor huge.
	if stats.BacklogAgeMS < 0 || stats.BacklogAgeMS > int64(time.Hour/time.Millisecond) {
		t.Fatalf("invalid backlog age: %d ms", stats.BacklogAgeMS)
	}
	_ = ch
}

func TestNotificationChannelCRUDRoundTrip(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	ch := &NotificationChannel{
		Name:       "CRUD \u5f80\u8fd4",
		Kind:       notify.KindEmail,
		Mode:       NotifyModeDigest,
		Config:     json.RawMessage(`{"host":"smtp.example.com","port":587,"from":"a@b.c","to":["x@y.z"]}`),
		Filter:     json.RawMessage(`{"min_severity":"medium","on_status_change":true}`),
		RatePerMin: 42,
	}
	id, err := d.SaveNotificationChannel(ctx, ch)
	if err != nil {
		t.Fatalf("\u65b0\u5efa\u5931\u8d25: %v", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_channels WHERE id=$1`, id) })

	got, err := d.NotificationChannelByID(ctx, id)
	if err != nil {
		t.Fatalf("\u8bfb\u53d6\u5931\u8d25: %v", err)
	}
	if got.Mode != NotifyModeDigest || got.RatePerMin != 42 || got.Name != "CRUD \u5f80\u8fd4" {
		t.Fatalf("\u5f80\u8fd4\u5b57\u6bb5\u4e0d\u4e00\u81f4: %+v", got)
	}
	if !got.IsEnabled() {
		t.Fatal("\u9ed8\u8ba4\u5e94\u4e3a\u542f\u7528")
	}
	var cfg map[string]any
	if err := json.Unmarshal(got.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["host"] != "smtp.example.com" {
		t.Fatalf("\u914d\u7f6e\u672a\u6b63\u786e\u843d\u5e93: %v", cfg)
	}
	var filter notify.Filter
	if err := json.Unmarshal(got.Filter, &filter); err != nil {
		t.Fatal(err)
	}
	if filter.MinSeverity != "medium" || !filter.OnStatusChange {
		t.Fatalf("\u8fc7\u6ee4\u6761\u4ef6\u672a\u6b63\u786e\u843d\u5e93: %+v", filter)
	}

	// Read after update.
	got.Name = "\u6539\u540d\u4e86"
	off := false
	got.Enabled = &off
	if _, err := d.SaveNotificationChannel(ctx, got); err != nil {
		t.Fatal(err)
	}
	after, err := d.NotificationChannelByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != "\u6539\u540d\u4e86" || after.IsEnabled() {
		t.Fatalf("\u66f4\u65b0\u672a\u751f\u6548: %+v", after)
	}

	// Deleting a missing row returns not found rather than silent success.
	if err := d.DeleteNotificationChannel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.NotificationChannelByID(ctx, id); err != ErrNotificationChannelNotFound {
		t.Fatalf("\u671f\u671b ErrNotificationChannelNotFound\uff0c\u5f97\u5230 %v", err)
	}
	if err := d.DeleteNotificationChannel(ctx, id); err != ErrNotificationChannelNotFound {
		t.Fatalf("\u91cd\u590d\u5220\u9664\u5e94\u62a5\u4e0d\u5b58\u5728\uff0c\u5f97\u5230 %v", err)
	}
}

// TestSaveNotificationChannelKeepsExplicitZeroRate locks in the corrected behavior:
// 0 is valid and means unlimited; the DB must not replace it with a default.
//
// The old <=0 fallback contradicted docs/UI/takeTokens, silently changing explicit zero
// into 20 for DingTalk/WeCom/Telegram or 100 for Feishu.
// Operators thought rate limits were removed while actual sending remained throttled,
// without any notice. Only request bodies distinguish missing from explicit zero,
// so the server applies defaults (notifyCreateChannel), while the DB merely stores.
func TestSaveNotificationChannelKeepsExplicitZeroRate(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	// Explicit zero/unlimited must persist unchanged.
	unlimited := &NotificationChannel{
		Name: "\u4e0d\u9650\u6d41", Kind: notify.KindDingTalk, RatePerMin: 0,
		Config: json.RawMessage(`{"webhook":"https://example.com/h"}`),
	}
	id, err := d.SaveNotificationChannel(ctx, unlimited)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_channels WHERE id=$1`, id) })
	got, err := d.NotificationChannelByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.RatePerMin != 0 {
		t.Fatalf("\u663e\u5f0f 0 \u8868\u793a\u4e0d\u9650\u6d41\uff0c\u5fc5\u987b\u539f\u6837\u4fdd\u5b58\uff0c\u5f97\u5230 %d", got.RatePerMin)
	}
	if got.Mode != NotifyModeRealtime {
		t.Fatalf("\u9ed8\u8ba4\u6a21\u5f0f\u5e94\u4e3a realtime\uff0c\u5f97\u5230 %s", got.Mode)
	}

	// Reject negative input instead of silently substituting another value.
	bad := &NotificationChannel{
		Name: "\u8d1f\u9650\u6d41", Kind: notify.KindDingTalk, RatePerMin: -1,
		Config: json.RawMessage(`{"webhook":"https://example.com/h"}`),
	}
	if _, err := d.SaveNotificationChannel(ctx, bad); err == nil {
		t.Fatal("\u8d1f\u9650\u6d41\u5e94\u88ab\u62d2\u7edd")
	}
}

// TestDeleteChannelCascadesDeliveries verifies history cascades with deleted configuration,
// but events remain because other channels may reference them.
func TestDeleteChannelCascadesDeliveries(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{}`)
	ev := addTestEvent(t, d, notify.EventFindingCreated, 9101, notify.Snapshot{Severity: "high"})
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := d.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, ch.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("\u524d\u7f6e\u6761\u4ef6\u4e0d\u6210\u7acb\uff1a\u672a\u4ea7\u751f\u6295\u9012")
	}
	if err := d.DeleteNotificationChannel(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := d.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, ch.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Fatalf("\u6e20\u9053\u5220\u9664\u540e\u5176\u6295\u9012\u5e94\u7ea7\u8054\u5220\u9664\uff0c\u4ecd\u6709 %d \u6761", after)
	}
	var evExists bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM notification_events WHERE id=$1)`, ev).Scan(&evExists); err != nil {
		t.Fatal(err)
	}
	if !evExists {
		t.Fatal("\u5220\u6e20\u9053\u4e0d\u5e94\u8fde\u5e26\u5220\u9664\u4e8b\u4ef6\u672c\u8eab")
	}
}

// TestClaimDigestBatchHonorsCallerLimit closes an audited gap: digest sends previously bypassed
// token-bucket allowance, which was deducted but unused, making rate_per_min ineffective.
// limit now participates in claiming constraints.
func TestClaimDigestBatchHonorsCallerLimit(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeDigest, `{}`)
	for i := 0; i < 10; i++ {
		addTestEvent(t, d, notify.EventFindingCreated, int64(7000+i), notify.Snapshot{Severity: "high"})
	}
	if _, _, err := d.FanOutPendingEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	// limit=3 claims only three rows, leaving others stored.
	got, err := d.ClaimDigestBatch(ctx, ch.ID, 3, time.Minute)
	if err != nil {
		t.Fatalf("\u9886\u53d6\u5931\u8d25: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("\u5e94\u6309\u8c03\u7528\u65b9\u9650\u6d41\u989d\u5ea6\u53ea\u9886 3 \u6761\uff0c\u5f97\u5230 %d", len(got))
	}
	// limit=0 means no current allowance: claim nothing without error.
	if got, err := d.ClaimDigestBatch(ctx, ch.ID, 0, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("\u989d\u5ea6\u4e3a 0 \u65f6\u5e94\u9886 0 \u6761\u4e14\u4e0d\u62a5\u9519\uff0c\u5f97\u5230 %d \u6761 err=%v", len(got), err)
	}
}

// TestFinishFindingRetestEmitsStatusChange closes the audited consistency gap where fixed
// retests updated status directly without notification-aware persistence.
// on_status_change channels previously missed these transitions entirely, although UI status
// changed; operators discovered it only by opening the platform.
//
// Every status-changing path must register its change event.
func TestFinishFindingRetestEmitsStatusChange(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()

	tk, err := d.CreateTask("\u590d\u6d4b\u63a8\u9001\u6d4b\u8bd5", "\u76ee\u6807", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	f, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "test", VulnClass: "SQL\u6ce8\u5165", Name: "\u590d\u6d4b\u76ee\u6807",
		Severity: "high", Summary: "\u6458\u8981",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM notification_events WHERE finding_id=$1`, f.FindingID) })

	// Create a retest and advance it directly to completion.
	rt, _, _, err := d.CreateFindingRetest(ctx, f.FindingID, "\u590d\u6838")
	if err != nil {
		t.Fatal(err)
	}
	if rt.ConversationID == nil {
		t.Fatal("\u590d\u6d4b\u5e94\u5173\u8054\u4e00\u4e2a\u4f1a\u8bdd")
	}
	// Enter running before recording a verdict, matching real lifecycle.
	if ok, err := d.StartFindingRetest(ctx, rt.ID); err != nil || !ok {
		t.Fatalf("\u542f\u52a8\u590d\u6d4b\u5931\u8d25: ok=%v err=%v", ok, err)
	}
	if err := d.RecordFindingRetestResult(ctx, *rt.ConversationID, "fixed", "\u5df2\u4fee\u590d", "\u8bc1\u636e"); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFindingRetest(rt.ID, "completed", ""); err != nil {
		t.Fatalf("\u7ed3\u675f\u590d\u6d4b\u5931\u8d25: %v", err)
	}

	var status string
	if err := d.QueryRow(`SELECT status FROM findings WHERE id=$1`, f.FindingID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != FindingFixed {
		t.Fatalf("\u590d\u6d4b\u5224\u5df2\u4fee\u590d\u540e\u72b6\u6001\u5e94\u4e3a fixed\uff0c\u5f97\u5230 %s", status)
	}

	// Require exactly one status-change event with correct from/to.
	var snapshot []byte
	err = d.QueryRow(`SELECT snapshot FROM notification_events WHERE finding_id=$1 AND kind=$2 ORDER BY id DESC LIMIT 1`,
		f.FindingID, notify.EventFindingStatusChanged).Scan(&snapshot)
	if err != nil {
		t.Fatalf("\u590d\u6d4b\u5224\u5df2\u4fee\u590d\u5e94\u767b\u8bb0\u72b6\u6001\u53d8\u66f4\u63a8\u9001\u4e8b\u4ef6\uff08\u5426\u5219\u914d\u4e86 on_status_change \u7684\u6e20\u9053\u6536\u4e0d\u5230\uff09: %v", err)
	}
	var snap notify.Snapshot
	if err := json.Unmarshal(snapshot, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.FromStatus != "pending" || snap.ToStatus != FindingFixed {
		t.Fatalf("\u5feb\u7167\u7684\u72b6\u6001\u6d41\u8f6c\u4e0d\u5bf9: %s \u2192 %s", snap.FromStatus, snap.ToStatus)
	}
	// Snapshot must include all rendering fields.
	if snap.Name != "\u590d\u6d4b\u76ee\u6807" || snap.Severity != "high" {
		t.Fatalf("\u5feb\u7167\u7f3a\u5c11\u6e32\u67d3\u5b57\u6bb5: %+v", snap)
	}
}
