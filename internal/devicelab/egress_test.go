package devicelab

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEgressJournalRecoveryAndOwnedRuleCleanup(t *testing.T) {
	rules := map[string]string{}
	failDelete := false
	stopped := ""
	d, _ := New("device", "com.original.app", "", func(_ context.Context, _ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if strings.Contains(line, "am force-stop") {
			stopped = line
			return "", nil
		}
		tool := "iptables"
		if strings.Contains(line, "ip6tables") {
			tool = "ip6tables"
		}
		if strings.Contains(line, "-I OUTPUT") {
			for i, arg := range args {
				if arg == "--comment" {
					rules[tool] = args[i+1]
				}
			}
		}
		if strings.Contains(line, "-D OUTPUT") {
			if failDelete {
				return "", errors.New("simulated cleanup failure")
			}
			if !strings.Contains(line, rules[tool]) || !strings.Contains(line, "--uid-owner 10001") {
				t.Fatal("cleanup was not scoped to owned UID and tag")
			}
			delete(rules, tool)
		}
		if strings.Contains(line, "-S OUTPUT") {
			return "-A OUTPUT --comment unrelated-user-rule\n" + rules[tool], nil
		}
		return "", nil
	})
	d.rootMode = "adbd"
	dir := t.TempDir()
	guard, err := d.StartEgressGuard(context.Background(), dir, 10001)
	if err != nil || len(rules) != 2 {
		t.Fatalf("guard setup failed: %v", err)
	}
	if st, err := os.Stat(guard.path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("recovery journal is not private")
	}
	failDelete = true
	if guard.Revert(context.Background()) == nil {
		t.Fatal("cleanup failure was ignored")
	}
	if _, err = os.Stat(guard.path); err != nil {
		t.Fatal("failed cleanup discarded recovery state")
	}
	failDelete = false
	d.Package = "com.next.app"
	if err = d.RecoverEgress(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 || !strings.Contains(stopped, "com.original.app") {
		t.Fatal("recovery did not stop original app and remove owned rules")
	}
	if _, err = os.Stat(guard.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful recovery did not clear journal")
	}
}

func TestEgressRejectsSystemUIDAndCorruptRecovery(t *testing.T) {
	d, _ := New("device", "com.example.app", "", func(context.Context, string, ...string) (string, error) {
		t.Fatal("invalid guard touched device")
		return "", nil
	})
	d.rootMode = "adbd"
	dir := t.TempDir()
	if _, err := d.StartEgressGuard(context.Background(), dir, 2000); err == nil {
		t.Fatal("system UID accepted")
	}
	if err := os.WriteFile(egressPath(dir, d.Serial), []byte(`{"serial":"device","uid":10001,"tag":"unowned","package":"com.example.app"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if d.RecoverEgress(context.Background(), dir) == nil {
		t.Fatal("unowned recovery tag accepted")
	}
}
