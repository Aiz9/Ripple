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
	leases   *Leases
	once     sync.Once
}

// NewLeases returns an empty lease table.
func NewLeases() *Leases {
	return &Leases{held: map[string]*Lease{}, notify: make(chan struct{})}
}

// TryAcquire takes the lease if free and never blocks.
func (l *Leases) TryAcquire(serial, owner string) (*Lease, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur := l.held[serial]; cur != nil {
		return nil, false
	}
	lease := &Lease{Serial: serial, Owner: owner, Acquired: time.Now(), leases: l}
	l.held[serial] = lease
	return lease, true
}

// Acquire waits until the lease is free or ctx ends.
func (l *Leases) Acquire(ctx context.Context, serial, owner string) (*Lease, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		// Check ownership and subscribe to release under the same lock. Otherwise
		// a release between TryAcquire and reading notify can be missed forever.
		if l.held[serial] == nil {
			lease := &Lease{Serial: serial, Owner: owner, Acquired: time.Now(), leases: l}
			l.held[serial] = lease
			l.mu.Unlock()
			return lease, nil
		}
		wait := l.notify
		holder := ""
		if cur := l.held[serial]; cur != nil {
			holder = cur.Owner
		}
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device %s busy (held by %s): %w", serial, holder, ctx.Err())
		case <-wait:
		}
	}
}

// Holder returns the current owner of a serial ("" when free).
func (l *Leases) Holder(serial string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur := l.held[serial]; cur != nil {
		return cur.Owner
	}
	return ""
}

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
