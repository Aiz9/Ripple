package devicelab

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Leases serializes device-bound work per serial. Runtime slots are global, but
// a device runs one active test at a time; observers (logcat, Frida, proxy)
// attach to the lease holder instead of taking their own lease.
type Leases struct {
	mu     sync.Mutex
	held   map[string]*Lease
	notify chan struct{}
}

// Lease is held by one owner for one serial until Release.
type Lease struct {
	Serial   string
	Owner    string
	Acquired time.Time
	expiry   time.Time // zero = no expiry
	leases   *Leases
	once     sync.Once
}

// expired reports whether a TTL lease has lapsed. A lapsed lease is reclaimable so
// a holder that crashed or forgot to Release cannot deadlock the serial forever.
func (x *Lease) expired() bool {
	return !x.expiry.IsZero() && time.Now().After(x.expiry)
}

// NewLeases returns an empty lease table.
func NewLeases() *Leases {
	return &Leases{held: map[string]*Lease{}, notify: make(chan struct{})}
}

// TryAcquire takes the lease if free and never blocks.
func (l *Leases) TryAcquire(serial, owner string) (*Lease, bool) {
	return l.TryAcquireTTL(serial, owner, 0)
}

// TryAcquireTTL takes the lease if free (or the current holder's TTL has lapsed)
// and never blocks. ttl<=0 means no expiry.
func (l *Leases) TryAcquireTTL(serial, owner string, ttl time.Duration) (*Lease, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur := l.held[serial]; cur != nil && !cur.expired() {
		return nil, false
	}
	lease := &Lease{Serial: serial, Owner: owner, Acquired: time.Now(), leases: l}
	if ttl > 0 {
		lease.expiry = lease.Acquired.Add(ttl)
	}
	l.held[serial] = lease
	return lease, true
}

// Acquire waits until the lease is free or ctx ends. ttl<=0 means no expiry.
func (l *Leases) Acquire(ctx context.Context, serial, owner string, ttl time.Duration) (*Lease, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		// Check ownership and subscribe to release under the same lock. Otherwise
		// a release between the check and reading notify can be missed forever.
		if cur := l.held[serial]; cur == nil || cur.expired() {
			lease := &Lease{Serial: serial, Owner: owner, Acquired: time.Now(), leases: l}
			if ttl > 0 {
				lease.expiry = lease.Acquired.Add(ttl)
			}
			l.held[serial] = lease
			l.mu.Unlock()
			return lease, nil
		}
		wait := l.notify
		holder := l.held[serial].Owner
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device %s busy (held by %s): %w", serial, holder, ctx.Err())
		case <-wait:
		}
	}
}

// Holder returns the current owner of a serial ("" when free or lapsed).
func (l *Leases) Holder(serial string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur := l.held[serial]; cur != nil && !cur.expired() {
		return cur.Owner
	}
	return ""
}

// globalLeases serializes live, session-bound work (e.g. an authenticated login to
// one account) across concurrent worker goroutines in this process. Task 774 lost
// work when three intents logged into the same account at once, each evicting the
// previous session; a shared lease gives workers a real mutex instead of the ad-hoc
// run-log-mtime convention they used (and raced).
var globalLeases = NewLeases()

// GlobalLeases returns the process-wide live-work lease table.
func GlobalLeases() *Leases { return globalLeases }

// Release frees the lease; it is idempotent.
func (x *Lease) Release() {
	x.once.Do(func() {
		l := x.leases
		l.mu.Lock()
		if l.held[x.Serial] == x {
			delete(l.held, x.Serial)
		}
		close(l.notify)
		l.notify = make(chan struct{})
		l.mu.Unlock()
	})
}
