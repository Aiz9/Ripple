package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Aiz9/ripple/internal/db"
	"github.com/Aiz9/ripple/internal/notify"
)

// Global settings-table keys; no new tables required.
const (
	// settingNotifyEnabled defaults on as a maintenance kill switch; actual feature activation
	// depends on having configured channels.
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the external platform address for finding-detail links,
	// for example https://artex.example.com; empty omits backlink buttons.
	// Added because no existing external-base-URL setting was reusable.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes configures digest period in minutes.
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick polls every 3 seconds, bounding realtime responsiveness and contributing most
	// finding-save-to-IM delay.
	notifyTick = 3 * time.Second
	// notifyLease must substantially exceed worst-case sending time (HTTP timeout 15 seconds),
	// preventing two dispatchers from concurrently sending the same leased row.
	// Lease duration protects cross-process claim ownership.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick bounds events expanded each round, avoiding one large historical
	// backlog explosion when channels are first enabled.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is default digest period.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick caps per-tick sends even without channel rate limits,
	// preventing unlimited settings plus thousands of findings from blocking a tick for too long.
	// Keep scheduling latency bounded.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick caps one channel's sends each tick.
	//
	// Derive cap from the 3-minute lease: too many serial worst-case sends outlive later rows'
	// leases. Single-process ticks do not overlap, but another process sharing the DB can reclaim
	// expired rows while the original sender is still active, creating duplicate notifications
	// and double attempt increments, possibly failing still-running deliveries.
	// Total worst-case batch time must fit the lease with margin.
	//
	// 180s/30s=6 leaves zero margin; choose 5 for 150s worst case plus 30s headroom.
	// TestNotifyTickBudgetFitsWithinLease locks the relationship across notifyLease,
	// notifySendTimeout, and this cap.
	// Changing any of those requires rechecking the invariant.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout bounds each delivery and also determines the per-tick send cap;
	// their product must stay below notifyLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff indexes retries by completed attempt count.
// Three total attempts including first, matching db.MaxNotifyAttempts; change together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Notifier drives finding notification delivery.
//
// Independent goroutine alongside Scheduler, started by server.New; its 3-second responsiveness
// differs from business triggers, and stuck delivery must not block agent scheduling.
// Keep failure domains independent.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu protects the small, low-contention bucket set; one mutex suffices,
	// avoiding unnecessary finer-grained synchronization.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is a per-channel token bucket.
//
// Constant refill avoids fixed-minute boundary bursts, where 20 sends just before reset
// plus 20 immediately after appear as 40/sec to the platform.
// A reset-counter window would violate intended delivery rates.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends; server.New starts it once.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step first fans out new events, then sends due deliveries.
//
// Log any failure without stopping the loop; notification faults must never become process faults.
// Independent ticks retry naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] failed to dispatch events: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] failed to read channels: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// Tokens count messages/HTTP requests, not findings.
		// Realtime is one finding per message; digest merges a full batch into one message,
		// consuming one token.
		//
		// Check allowance before claiming in both modes; reversing the order burns attempts on
		// throttled rows that were never sent.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns this tick's token consumption and batch memory bound.
//
// Separate units are why this helper exists:
//
//   - tokens counts messages: one batch means one HTTP request, always one token,
//     so rate_per_min still limits digest messages.
//   - claimLimit counts findings, constrained by memory independently of request allowance.
//
// Previously the per-tick request budget (derived from leases) was misused as batch size,
// making rate=20/min refill one token per 3-second tick and emit one-finding digests.
// Keep batching separate from delivery-rate accounting.
// This degenerates digest into realtime messages with digest wording, each announcing one finding,
// making db.MaxDigestBatchSize unreachable.
//
// Existing end-to-end tests manually passed a large stepDigest limit and bypassed allowance
// calculation in step, so isolate the decision here and lock it with
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims/sends one finding per message for a channel.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim realtime deliveries channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("Channel type %q is not registered", ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// Rendering failure is local data corruption, not retryable.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest merges due channel deliveries into one message.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] failed to check digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("Channel type %q is not registered", ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// Explicitly fail corrupted snapshots excluded from rendering; otherwise they belong to neither
	// included nor failed and escape success updates, remaining sending until lease expiry
	// repeatedly reclaims them.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := "Cannot parse event snapshot; finding cannot be rendered as a message"
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] failed to mark invalid-snapshot delivery channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d deliveries with unparseable snapshots channel=%d", len(skipped), ch.ID)
	}
	// included[i] must match msg.Items[i] exactly so sender-reported first-K packed items map
	// to the correct delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions states.
//
// Digest members share one send outcome: all delivered or all retry; partial retry would
// corrupt one-message batch semantics.
//
// Exception: channel size segmentation reports first K included items; retain K+1 onward
// for subsequent batches rather than marking them successful and silently losing findings
// from both messages and failure history.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// Bound each send so one channel cannot stall all remaining channels in this tick.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// Delivered count above input count is a renderer bug; clamp to all delivered and log,
			// preserving coherent stored records.
			log.Printf("[notify] channel reported %d delivered above total %d channel=%s; treating all as delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] failed to mark delivered channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// Size-limited remainder queues immediately for next tick.
			// DeferDeliveries, not RescheduleDeliveries: omission is not failure, so undo the optimistic
			// attempt increment instead of consuming retry budget.
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf("Message reached the channel length limit; only the first %d entries were delivered. The rest remain for the next batch.", delivered)); err != nil {
				log.Printf("[notify] failed to queue remaining segments channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// Zero delivered without error is a failure requiring backoff, preventing endless reclaim
		// without any terminal marking.
		err = fmt.Errorf("Channel did not report delivery count (delivered=%d)", delivered)
	}

	// Decide failure per delivery, never from the maximum attempt count of the batch.
	//
	// maxAttempts-based batch failure previously dragged fresh rows into failed alongside older
	// already-retried rows, losing new findings without their own retry opportunities.
	// Mixed attempt counts require individual decisions.
	// Do not let old rows exhaust new rows' budgets.
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] failed to mark failure state channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf("Still failing after %d retries: %s", db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] failed to mark failure state channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// Group rescheduling by the three backoff levels, avoiding 500 separate UPDATE round trips
	// for a large batch.
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] failed to reschedule delivery channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d retries exhausted=%d pending retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns all entries absent from keep by pointer identity.
// Explicitly handle deliveries omitted from messages, never leave ambiguous states.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt selects adapter and parses config.
// Unknown kind returns false for immediate failure, not unlimited retries.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// Invalid JSON becomes empty map; adapter Validate supplies specific missing-field guidance,
		// more actionable than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders one finding message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch parses snapshots individually; one bad row must not discard the entire digest.
// Skip only corrupt entries.
//
// included and msg.Items must correspond one-to-one by index.
// Callers mark first K delivered based on channel packing. Skipping bad snapshots without
// removing their delivery rows from included shifts indices, marking corrupt rows delivered
// and good rows omitted.
// Caller explicitly fails bad rows in stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// Bad snapshots enter neither message nor included; caller must mark them failed,
			// never count them as delivered.
			log.Printf("[notify] skipped invalid snapshot in digest delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf("All %d digest deliveries have unparseable snapshots", len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor turns snapshots into items, resolving asset names and detail links.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// Missing asset names should not block alerts; omitting one display line is preferable
		// to losing the notification.
		log.Printf("[notify] failed to resolve asset names finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// Detail route: web/src/app/(main)/function/findings/detail/page.tsx,
		// using query parameter id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens returns at most want tokens from a channel's bucket.
//
// One token is one message/HTTP request; realtime requests item count,
// digest requests one for the whole batch.
//
// Capacity is ratePerMin, refilled steadily; <=0 returns a large finite allowance,
// preventing unlimited backlog from stalling a round.
//
// want prevents draining unused tokens beyond per-round caps, discarding burst capacity
// until refill and even charging rounds without pending deliveries.
// Take only what callers can actually use.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// Refill using actual elapsed time at ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// Add a tiny epsilon before integer conversion: floating accumulation such as 0.5+0.5
	// may produce 0.9999999999, otherwise truncating a full token to zero.
	// 1e-9 is far below one token and does not permit meaningful overdraft.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the global switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL trims trailing slashes from external backlink base.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval falls back to default for absent/invalid values.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot reads the delivery event snapshot.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf("Event snapshot for delivery %d is empty", dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf("Failed to parse event snapshot for delivery %d: %w", dl.ID, err)
	}
	if snap.Kind == "" {
		// Event-row kind is authoritative; snapshot kind may come from older versions.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
