package androidapk

import "testing"

func TestApiPathLikely(t *testing.T) {
	good := []string{"/v1/accounts/{id}", "/api/users/profile", "/oauth/token", "/payments/transfer", "/users/:id/cards", "/v2/wallet/balance"}
	for _, p := range good {
		if !apiPathLikely(p) {
			t.Errorf("expected API path: %q", p)
		}
	}
	bad := []string{"/data/data/com.app/files", "/res/drawable/icon.png", "/system/lib/x.so", "/assets/index.html", "/a/b.png", "/fonts/roboto.ttf"}
	for _, p := range bad {
		if apiPathLikely(p) {
			t.Errorf("expected NON-API path rejected: %q", p)
		}
	}
}

func TestDexAPIPaths(t *testing.T) {
	// Gate: no HTTP-client marker -> no extraction (avoids filesystem-path noise).
	noClient := []byte("random bytes /v1/accounts/{id} and /payments/transfer here")
	if got := dexAPIPaths(noClient); len(got) != 0 {
		t.Errorf("without an HTTP client marker, expected no paths, got %v", got)
	}
	// With a retrofit marker, API paths are extracted and filesystem paths are not.
	withClient := []byte("retrofit2/http/GET /v1/accounts/{id} /payments/transfer /data/data/com.x/cache /res/drawable/a.png")
	got := dexAPIPaths(withClient)
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	if !set["/v1/accounts/{id}"] || !set["/payments/transfer"] {
		t.Errorf("expected API paths extracted, got %v", got)
	}
	if set["/data/data/com.x/cache"] || set["/res/drawable/a.png"] {
		t.Errorf("filesystem paths must be filtered, got %v", got)
	}
}
