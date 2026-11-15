package devicelab

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveExplore(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	_ = d.ForceStop(ctx)
	if _, err := d.Launch(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	dests := d.drawerDestinations(ctx)
	t.Logf("drawer destinations (%d): %v", len(dests), dests)
	n := 0
	res := d.Explore(ctx, ExplorerConfig{MaxSteps: 60, MaxMinutes: 4}, func(c string) string {
		n++
		return "ARTEX-CANARY-live-" + itoa(n)
	})
	t.Logf("explore: screens=%d steps=%d fieldsTyped=%d visited=%v notes=%v", res.Screens, res.Steps, res.FieldsTyped, res.Visited, res.Notes)
	_ = os.Stdout
}
