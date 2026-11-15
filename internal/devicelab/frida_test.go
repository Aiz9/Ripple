package devicelab

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFridaReadinessRequiresInitializedHooks(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		commandErr   error
		valid        bool
	}{
		{"script loaded only", `ANDROIDLAB_EVENT {"kind":"ready"}`, nil, false},
		{"zero hooks", `ANDROIDLAB_EVENT {"kind":"hooks_ready","groups":0}`, nil, false},
		{"initialized hooks", `ANDROIDLAB_EVENT {"kind":"hooks_ready","groups":3}`, nil, true},
		{"failed session", `ANDROIDLAB_EVENT {"kind":"hooks_ready","groups":3}`, errors.New("process failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, _ := New("device", "com.example.app", "", func(_ context.Context, name string, args ...string) (string, error) {
				if name != "frida" || !strings.Contains(strings.Join(args, " "), "-f com.example.app") {
					t.Fatal("observer was not bound to the approved package")
				}
				if !tc.valid {
					cancel()
				}
				return tc.output, tc.commandErr
			})
			_, _, err := d.FridaSpawn(ctx, "// test script", 3, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestFridaVersionMatchIsChecked(t *testing.T) {
	for _, server := range []string{"17.22.2", "16.0.0"} {
		t.Run(server, func(t *testing.T) {
			d, _ := New("device", "com.example.app", "", func(_ context.Context, name string, args ...string) (string, error) {
				if name == "frida" {
					return "17.22.2\n", nil
				}
				line := strings.Join(args, " ")
				if strings.Contains(line, "frida-server --version") {
					return server + "\n", nil
				}
				if strings.Contains(line, "getprop") {
					return "x86_64", nil
				}
				return "root 123 frida-server", nil
			})
			check, err := d.CheckFrida(context.Background())
			if (err == nil) != (server == "17.22.2") || check.ServerVersion != server {
				t.Fatalf("server=%s check=%+v err=%v", server, check, err)
			}
		})
	}
}
