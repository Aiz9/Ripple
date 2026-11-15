package guard

import "testing"

func TestAPKScopeViolation(t *testing.T) {
	block := []string{
		"nmap -p- 172.67.137.112",
		"nmap --top-ports 1000 bankxp.shangrilabank.com",
		"masscan 10.0.0.0/8 -p1-65535",
		"rustscan -a 1.2.3.4",
		"naabu -host example.com",
		"adb -s 127.0.0.1:6555 install insecurebankv2.apk",
		"adb install /tmp/other.apk",
		"pm install /data/local/tmp/x.apk",
	}
	for _, c := range block {
		if apkScopeViolation(c) == "" {
			t.Errorf("should block but allowed: %q", c)
		}
	}
	allow := []string{
		"curl -sk https://bankxp.shangrilabank.com/webbackend/v2/token",
		"npm install",
		"pip install -r requirements.txt",
		"apt-get install -y jadx",
		"go install ./cmd/artex",
		"jadx -d out app.apk",
		"adb -s 127.0.0.1:6555 shell pm list packages",
		"curl -s http://127.0.0.1:8080 -p 443", // single port flag, not a range
		"grep -p foo file",
	}
	for _, c := range allow {
		if r := apkScopeViolation(c); r != "" {
			t.Errorf("should allow but blocked: %q -> %s", c, r)
		}
	}
}
