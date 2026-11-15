package staticx

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reElem = regexp.MustCompile(`^\s*E: ([\w-]+)`)
	// Matches: A: [ns:]name(0x..)=<value>. Value is a quoted string, a
	// (type 0x..)0x.. typed literal, or a bare token (true/false/35).
	reAttr = regexp.MustCompile(`A: (?:.*:)?([A-Za-z][A-Za-z0-9]*)(?:\(0x[0-9a-f]+\))?=(?:"([^"]*)"|\(type 0x[0-9a-f]+\)(0x[0-9a-f]+)|([A-Za-z0-9_.@-]+))`)
)

// aaptAttrValue extracts an attribute name and value from an aapt2 xmltree line.
func aaptAttrValue(line string) (string, string) {
	m := reAttr.FindStringSubmatch(line)
	if m == nil {
		return "", ""
	}
	name := m[1]
	switch {
	case m[2] != "":
		return name, m[2]
	case m[4] != "":
		return name, m[4]
	case m[3] != "":
		switch strings.ToLower(m[3]) {
		case "0x0":
			return name, "false"
		case "0xffffffff":
			return name, "true"
		}
		return name, m[3]
	}
	return name, ""
}

// parseManifest reads components, exported flags, intent filters, authorities,
// extras hints and deep links from the binary manifest via aapt2 xmltree.
func (f *Facts) parseManifest(ctx context.Context, apkPath string) error {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, "aapt2", "dump", "packagename", apkPath).Output(); err == nil {
		f.Package = strings.TrimSpace(string(out))
	}
	out, err := exec.CommandContext(cctx, "aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", apkPath).Output()
	if err != nil {
		return err
	}
	return f.parseManifestLines(string(out))
}

// parseManifestLines consumes aapt2 xmltree output (separated for testing).
func (f *Facts) parseManifestLines(dump string) error {
	lines := strings.Split(dump, "\n")
	// Stack of (element, indent).
	type frame struct {
		elem   string
		indent int
	}
	var stack []frame
	indentOf := func(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

	var cur *Component
	var curDL *DeepLink
	inApplication := false
	curAction := ""
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := reElem.FindStringSubmatch(line); m != nil {
			ind := indentOf(line)
			for len(stack) > 0 && stack[len(stack)-1].indent >= ind {
				if stack[len(stack)-1].elem == "data" && curDL != nil && curDL.Scheme != "" {
					f.upsertDeepLink(*curDL)
					curDL = nil
				}
				stack = stack[:len(stack)-1]
			}
			elem := m[1]
			stack = append(stack, frame{elem, ind})
			switch elem {
			case "application":
				inApplication = true
			case "activity", "activity-alias", "receiver", "service", "provider":
				kind := elem
				if elem == "activity-alias" {
					kind = "activity"
				}
				f.Components = append(f.Components, Component{Kind: kind})
				cur = &f.Components[len(f.Components)-1]
				curDL = nil
			case "intent-filter":
				curDL = nil
			case "data":
				if cur != nil && cur.Kind == "activity" {
					curDL = &DeepLink{Activity: cur.Name}
				}
			}
			continue
		}
		name, val := aaptAttrValue(line)
		if name == "" {
			continue
		}
		top := ""
		if len(stack) > 0 {
			top = stack[len(stack)-1].elem
		}
		switch top {
		case "application":
			if !inApplication {
				break
			}
			switch name {
			case "debuggable":
				f.Debuggable = val == "true"
			case "allowBackup":
				f.AllowBackup = val == "true"
			case "usesCleartextTraffic":
				b := val == "true"
				f.UsesCleartext = &b
			case "networkSecurityConfig":
				f.NetworkConfig = val
			}
		case "uses-sdk":
			if name == "minSdkVersion" {
				f.MinSDK = atoi(val)
			}
			if name == "targetSdkVersion" {
				f.TargetSDK = atoi(val)
			}
		case "activity", "activity-alias", "receiver", "service", "provider":
			if cur == nil {
				break
			}
			switch name {
			case "name":
				cur.Name = val
			case "exported":
				cur.Exported = val == "true"
			case "permission", "readPermission":
				cur.Permission = val
			case "authorities":
				cur.Authority = val
			}
		case "action":
			if name == "name" {
				curAction = val
				if cur != nil && !contains(cur.Actions, val) && !strings.HasPrefix(val, "android.intent.action.MAIN") {
					cur.Actions = append(cur.Actions, val)
				}
			}
		case "data":
			if curDL == nil {
				break
			}
			switch name {
			case "scheme":
				curDL.Scheme = val
			case "host":
				curDL.Host = val
			case "path", "pathPrefix", "pathPattern":
				curDL.Path = val
			}
		}
		_ = curAction
	}
	if curDL != nil && curDL.Scheme != "" {
		f.upsertDeepLink(*curDL)
	}
	return nil
}

func (f *Facts) upsertDeepLink(dl DeepLink) {
	for i := range f.DeepLinks {
		if f.DeepLinks[i].Activity == dl.Activity && f.DeepLinks[i].Scheme == dl.Scheme && f.DeepLinks[i].Host == dl.Host && f.DeepLinks[i].Path == dl.Path {
			return
		}
	}
	f.DeepLinks = append(f.DeepLinks, dl)
}

func atoi(s string) int {
	if strings.HasPrefix(s, "0x") {
		n, _ := strconv.ParseInt(strings.TrimPrefix(s, "0x"), 16, 64)
		return int(n)
	}
	n, _ := strconv.Atoi(s)
	return n
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
