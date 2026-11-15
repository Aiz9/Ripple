package devicelab

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Transparent redirection routes a proxy-unaware app's TLS/HTTP straight to the
// recording proxy at the network layer, instead of relying on the Android system
// HTTP proxy. This is the only way to capture frameworks that ignore the system
// proxy — most importantly Flutter (Dart's HttpClient), which is why the engine's
// go-mitmproxy saw no API traffic from Flutter banking apps before this.
//
// The app's egress to :443/:80 is NAT-redirected (by UID, so only the target app)
// to a loopback port that an adb-reverse tunnel forwards to the host's transparent
// shim; the shim peeks the TLS SNI and feeds the connection to go-mitmproxy as an
// explicit CONNECT, so all of go-mitmproxy's MITM + recording still applies.

const transparentTag = "artex-transparent-mitm"

// redirectRuleSpec builds one iptables nat OUTPUT rule (sans table/chain/-A|-D)
// that redirects a UID's TCP traffic for dport to the shim on loopback. Kept pure
// so the exact rule is unit-testable without a device.
func redirectRuleSpec(uid, shimPort, dport int) []string {
	return []string{
		"-p", "tcp",
		"-m", "owner", "--uid-owner", strconv.Itoa(uid),
		"--dport", strconv.Itoa(dport),
		"!", "-d", "127.0.0.1",
		"-m", "comment", "--comment", transparentTag,
		"-j", "DNAT", "--to-destination", "127.0.0.1:" + strconv.Itoa(shimPort),
	}
}

// AppUID resolves the Linux UID the package runs as (so redirection targets only
// the app under test, not the whole device).
func (d *Device) AppUID(ctx context.Context, pkg string) (int, error) {
	// `stat` on the app's data dir is the most portable source of the UID.
	out, err := d.rootShell(ctx, "stat", "-c", "%u", "/data/data/"+pkg)
	if err == nil {
		if uid, perr := strconv.Atoi(strings.TrimSpace(out)); perr == nil && uid > 0 {
			return uid, nil
		}
	}
	// Fallback: dumpsys package … userId=10xxx.
	out, err = d.shell(ctx, "dumpsys", "package", pkg)
	if err != nil {
		return 0, fmt.Errorf("resolve app uid: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "userId="); i >= 0 {
			field := strings.TrimSpace(line[i+len("userId="):])
			field = strings.Fields(field + " ")[0]
			if uid, perr := strconv.Atoi(field); perr == nil && uid > 0 {
				return uid, nil
			}
		}
	}
	return 0, fmt.Errorf("could not determine UID for %s", pkg)
}

// EnableTransparentRedirect installs the NAT rules (requires root). shimPort is the
// device-loopback port (an adb-reverse tunnel to the host shim). Idempotent: it
// clears any prior artex rules first.
func (d *Device) EnableTransparentRedirect(ctx context.Context, uid, shimPort int) error {
	if !d.HasRoot() {
		return fmt.Errorf("transparent redirection requires root")
	}
	_ = d.ClearTransparentRedirect(ctx)
	// REDIRECT/DNAT to loopback from the OUTPUT chain needs route_localnet.
	if _, err := d.rootShell(ctx, "sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"); err != nil {
		return fmt.Errorf("enable route_localnet: %w", err)
	}
	for _, dport := range []int{443, 80} {
		args := append([]string{"iptables", "-w", "5", "-t", "nat", "-A", "OUTPUT"}, redirectRuleSpec(uid, shimPort, dport)...)
		if _, err := d.rootShell(ctx, args...); err != nil {
			_ = d.ClearTransparentRedirect(ctx)
			return fmt.Errorf("install redirect rule for :%d: %w", dport, err)
		}
	}
	return nil
}

// ClearTransparentRedirect removes every artex-tagged NAT rule, restoring normal
// egress. Safe to call unconditionally (e.g. deferred cleanup).
func (d *Device) ClearTransparentRedirect(ctx context.Context) error {
	out, err := d.rootShell(ctx, "iptables", "-w", "5", "-t", "nat", "-S", "OUTPUT")
	if err != nil {
		return err
	}
	var firstErr error
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, transparentTag) || !strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			continue
		}
		// Turn the printed "-A OUTPUT …" into a delete.
		del := append([]string{"iptables", "-w", "5", "-t", "nat", "-D"}, strings.Fields(strings.TrimSpace(line)[len("-A "):])...)
		if _, derr := d.rootShell(ctx, del...); derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return firstErr
}
