package devicelab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EgressGuard prevents the approved app UID from sending IPv4/IPv6 traffic.
// Until a scope-enforcing proxy is connected, autonomous local checks run with
// network access denied. Other applications' rules and traffic are untouched.
var ErrEgressNoRoot = errors.New("autonomous egress isolation requires root")

type EgressGuard struct {
	device  *Device
	path    string
	UID     int    `json:"uid"`
	Tag     string `json:"tag"`
	Serial  string `json:"serial"`
	Package string `json:"package"`
}

func egressPath(dir, serial string) string { return statePath(dir, serial) + ".egress" }

func (g *EgressGuard) rule() []string {
	return []string{"-m", "owner", "--uid-owner", itoa(g.UID), "-m", "comment", "--comment", g.Tag, "-j", "REJECT"}
}

// allowRule exempts the app's loopback traffic from the egress REJECT so it can
// still reach the recording proxy published over `adb reverse` (127.0.0.1).
// All captured traffic is subject to the proxy's own scope enforcement; direct,
// non-proxy egress to the network remains blocked by rule(). Without this
// exemption the guard also drops proxy-bound traffic, so network-dependent apps
// hang on startup and cannot be assessed dynamically.
func (g *EgressGuard) allowRule() []string {
	return []string{"-m", "owner", "--uid-owner", itoa(g.UID), "-o", "lo", "-m", "comment", "--comment", g.Tag, "-j", "ACCEPT"}
}

func (d *Device) StartEgressGuard(ctx context.Context, dir string, uid int) (*EgressGuard, error) {
	if !d.HasRoot() {
		return nil, ErrEgressNoRoot
	}
	if uid < 10000 || dir == "" {
		return nil, fmt.Errorf("autonomous egress isolation requires an application UID and a recovery directory")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	g := &EgressGuard{device: d, path: egressPath(dir, d.Serial), UID: uid, Tag: "artex-egress-" + hex.EncodeToString(nonce[:]), Serial: d.Serial, Package: d.Package}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".egress-state-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return nil, err
	}
	if err = os.Rename(f.Name(), g.path); err != nil {
		return nil, err
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		// Insert the REJECT first, then the loopback ACCEPT above it, so the
		// proxy exemption is evaluated before the blanket reject.
		for _, spec := range [][]string{g.rule(), g.allowRule()} {
			args := append([]string{tool, "-w", "5", "-I", "OUTPUT", "1"}, spec...)
			if _, err := d.rootShell(ctx, args...); err != nil {
				return g, fmt.Errorf("install %s app egress rule: %w", tool, err)
			}
			args = append([]string{tool, "-w", "5", "-C", "OUTPUT"}, spec...)
			if _, err := d.rootShell(ctx, args...); err != nil {
				return g, fmt.Errorf("verify %s app egress rule: %w", tool, err)
			}
		}
	}
	return g, nil
}

// Revert deletes only the exact rules journaled by this run. Failed cleanup
// retains the journal so a later run can recover instead of losing ownership.
func (g *EgressGuard) Revert(ctx context.Context) error {
	if g == nil || g.device == nil {
		return nil
	}
	var failures []error
	for _, tool := range []string{"ip6tables", "iptables"} {
		out, err := g.device.rootShell(ctx, tool, "-w", "5", "-S", "OUTPUT")
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect %s egress rules: %w", tool, err))
			continue
		}
		for strings.Contains(out, g.Tag) {
			removed := false
			for _, spec := range [][]string{g.rule(), g.allowRule()} {
				check := append([]string{tool, "-w", "5", "-C", "OUTPUT"}, spec...)
				if _, err = g.device.rootShell(ctx, check...); err != nil {
					continue // this rule is not present; try the next
				}
				args := append([]string{tool, "-w", "5", "-D", "OUTPUT"}, spec...)
				if _, err = g.device.rootShell(ctx, args...); err != nil {
					failures = append(failures, fmt.Errorf("remove %s egress rule: %w", tool, err))
					break
				}
				removed = true
			}
			if !removed {
				break
			}
			if out, err = g.device.rootShell(ctx, tool, "-w", "5", "-S", "OUTPUT"); err != nil {
				failures = append(failures, fmt.Errorf("inspect %s egress rules: %w", tool, err))
				break
			}
		}
		out, err = g.device.rootShell(ctx, tool, "-w", "5", "-S", "OUTPUT")
		if err != nil || strings.Contains(out, g.Tag) {
			failures = append(failures, fmt.Errorf("%s egress cleanup could not be verified", tool))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if err := os.Remove(g.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (d *Device) RecoverEgress(ctx context.Context, dir string) error {
	path := egressPath(dir, d.Serial)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var g EgressGuard
	if err = json.Unmarshal(raw, &g); err != nil {
		return fmt.Errorf("invalid egress recovery journal")
	}
	if g.Serial != d.Serial || g.UID < 10000 || !packagePattern.MatchString(g.Package) || !strings.HasPrefix(g.Tag, "artex-egress-") || len(g.Tag) != len("artex-egress-")+32 {
		return fmt.Errorf("invalid egress recovery identity")
	}
	if _, err = hex.DecodeString(strings.TrimPrefix(g.Tag, "artex-egress-")); err != nil {
		return fmt.Errorf("invalid egress recovery tag")
	}
	g.device, g.path = d, path
	priorDevice := *d
	priorDevice.Package = g.Package
	if err = priorDevice.ForceStop(ctx); err != nil {
		return fmt.Errorf("stop approved app before egress recovery: %w", err)
	}
	return g.Revert(ctx)
}
