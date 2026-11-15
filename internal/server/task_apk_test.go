package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// TestCreateAPKTaskUnifiesWithWebPipeline verifies that an uploaded APK can be
// run through the SAME web task pipeline: POST /api/tasks/apk creates a normal
// task (so it appears in the Current tasks list) whose seeded objective targets
// the local APK for a MASVS audit.
func TestCreateAPKTaskUnifiesWithWebPipeline(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)

	app := uploadAPKWithEntries(t, s, "unify.apk", map[string]string{
		"AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.unify"><application/></manifest>`,
	})

	// Missing apk_id → 400.
	if r := request("POST", "/api/tasks/apk", `{}`); r.Code != 400 {
		t.Fatalf("empty apk_id = %d, want 400", r.Code)
	}

	// Valid APK → 201, a normal task.
	r := request("POST", "/api/tasks/apk", `{"apk_id":"`+app.ID+`"}`)
	if r.Code != 201 {
		t.Fatalf("create APK task = %d: %s", r.Code, r.Body.String())
	}
	var task struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.ID == "" || !strings.Contains(task.Name, "com.example.unify") {
		t.Fatalf("unexpected task DTO: %+v", task)
	}
	t.Cleanup(func() {
		if id, err := strconv.ParseInt(strings.TrimSpace(task.ID), 10, 64); err == nil {
			s.m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, id)
			s.m.pg.DeleteTask(id)
		}
	})

	// It shows in the same Current tasks list as web tasks.
	list := request("GET", "/api/tasks", "")
	if list.Code != 200 {
		t.Fatalf("list tasks = %d", list.Code)
	}
	if !strings.Contains(list.Body.String(), task.ID) {
		t.Fatal("APK task not present in the unified /api/tasks list")
	}

	// The seeded objective must target the local APK (not a URL) with MASVS guidance.
	detail := request("GET", "/api/tasks/"+task.ID, "")
	if detail.Code != 200 {
		t.Fatalf("get task = %d", detail.Code)
	}
	for _, must := range []string{"com.example.unify", app.APKPath, "MASVS"} {
		if !strings.Contains(detail.Body.String(), must) {
			t.Errorf("task detail missing %q", must)
		}
	}
}
