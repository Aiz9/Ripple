package staticx

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStaticCacheRequiresCompleteSourcesAndMatchingTools(t *testing.T) {
	root := t.TempDir()
	versions := map[string]string{"jadx": "1", "aapt2": "2"}
	f := &Facts{Package: "com.example", SHA256: "approved", SourceRoot: root,
		CacheVersion: cacheVersion, ToolVersions: versions, Complete: true}
	app := filepath.Join(root, "sources", "com", "example")
	if err := os.MkdirAll(app, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "facts.json")
	if err := publishFacts(path, f); err != nil {
		t.Fatal(err)
	}
	if cachedFacts(path, "approved", versions) == nil {
		t.Fatal("complete matching cache was not reused")
	}
	if cachedFacts(path, "other-build", versions) != nil || cachedFacts(path, "approved", map[string]string{"jadx": "upgraded", "aapt2": "2"}) != nil {
		t.Fatal("build or tool upgrade reused stale analysis")
	}
	f.Complete = false
	if err := publishFacts(path, f); err != nil {
		t.Fatal(err)
	}
	if cachedFacts(path, "approved", versions) != nil {
		t.Fatal("partial decompilation reused as complete")
	}
	f.Complete = true
	f.CacheVersion--
	if err := publishFacts(path, f); err != nil {
		t.Fatal(err)
	}
	if cachedFacts(path, "approved", versions) != nil {
		t.Fatal("old extractor version reused")
	}
	f.CacheVersion = cacheVersion
	if err := publishFacts(path, f); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(app); err != nil {
		t.Fatal(err)
	}
	if cachedFacts(path, "approved", versions) != nil {
		t.Fatal("missing source tree reused as complete")
	}
}

func TestFailedDecompilerIsRetriedAndDoesNotLeakOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based subprocess fixture")
	}
	root := t.TempDir()
	fail := filepath.Join(root, "fail")
	t.Setenv("ARTEX_STATIC_TEST_FAIL", fail)
	if err := os.WriteFile(fail, []byte("retry"), 0600); err != nil {
		t.Fatal(err)
	}
	jadx := `#!/bin/sh
if [ "$1" = --version ]; then echo jadx-fixture-1; exit 0; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = -d ]; then shift; dest=$1; fi
  shift
done
mkdir -p "$dest/sources/com/example"
if [ -f "$ARTEX_STATIC_TEST_FAIL" ]; then echo 'error password=fixture-private-value'; exit 1; fi
printf 'package com.example; class App {}' > "$dest/sources/com/example/App.java"
`
	aapt := `#!/bin/sh
case "$1 $2" in
  'version ') echo aapt-fixture-1;;
  'dump packagename') echo com.example;;
  'dump xmltree') printf 'E: manifest\n  E: application\n';;
  'dump resources') exit 0;;
  *) exit 1;;
esac
`
	for name, body := range map[string]string{"jadx": jadx, "aapt2": aapt} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	apk := filepath.Join(root, "fixture.apk")
	if err := os.WriteFile(apk, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	f, err := Analyze(context.Background(), apk, cache)
	if err != nil || f.Complete {
		t.Fatalf("failed decompilation was trusted: complete=%v err=%v", f != nil && f.Complete, err)
	}
	for _, warning := range f.Warnings {
		if warning == "error password=fixture-private-value" {
			t.Fatal("raw tool diagnostic entered findings context")
		}
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	f, err = Analyze(context.Background(), apk, cache)
	if err != nil || !f.Complete {
		t.Fatalf("retry did not produce complete facts: warnings=%v err=%v", f.Warnings, err)
	}
	again, err := Analyze(context.Background(), apk, cache)
	if err != nil || again.SourceRoot != f.SourceRoot {
		t.Fatal("complete result was not reused")
	}
}
