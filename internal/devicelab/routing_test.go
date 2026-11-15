package devicelab

import "testing"

func TestRedirectRuleSpec(t *testing.T) {
	spec := redirectRuleSpec(10123, 9901, 443)
	joined := ""
	for _, s := range spec {
		joined += s + " "
	}
	for _, want := range []string{"--uid-owner 10123", "--dport 443", "DNAT --to-destination 127.0.0.1:9901", transparentTag, "! -d 127.0.0.1"} {
		found := false
		for i := 0; i+len(splitN(want)) <= len(spec); i++ {
			if match(spec[i:], splitN(want)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("rule spec missing %q; got: %s", want, joined)
		}
	}
}

func splitN(s string) []string {
	var out, cur = []string{}, ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
func match(hay, needle []string) bool {
	if len(hay) < len(needle) {
		return false
	}
	for i := range needle {
		if hay[i] != needle[i] {
			return false
		}
	}
	return true
}
