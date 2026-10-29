package applications

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

func TestPackageInventoryDoesNotClaimDisuse(t *testing.T) {
	apps := parseDPKG("tool:amd64\t2.3\tii \t12\nremoved\t1\trc \t4\ninvalid\n")
	if len(apps) != 1 || apps[0].size == nil || *apps[0].size != 12288 {
		t.Fatalf("%+v", apps)
	}
	f := appFinding(apps[0], "linux")
	if f.Application.LastUsage != nil || f.Application.Running != nil || f.Recommendation != "INSPECT" || !strings.Contains(f.Application.UsageProvenance, "UNKNOWN") {
		t.Fatalf("%+v", f)
	}
	if f.Application.UninstallMethod == "" || f.Application.DependencyNotes == "" {
		t.Fatal("missing manual review guidance")
	}
}
func TestLinuxUnavailableAndFailedProbesAreNotCleanResult(t *testing.T) {
	r := findings.Result{}
	apps := linuxApps(context.Background(), &r, nil, func(string) string { return "" })
	if len(apps) != 0 || r.Support != "UNSUPPORTED" || r.Coverage.Status != "UNSUPPORTED" {
		t.Fatalf("%+v", r)
	}
	r = findings.Result{Coverage: findings.Coverage{Status: "PARTIAL"}}
	apps = linuxApps(context.Background(), &r, func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("permission denied") }, func(s string) string {
		if s == "dpkg-query" {
			return "/usr/bin/dpkg-query"
		}
		return ""
	})
	if len(apps) != 0 || len(r.Errors) != 1 || r.Coverage.Status != "PARTIAL" {
		t.Fatalf("%+v", r)
	}
}
func TestRegistryMetadataAndNoUninstallExecution(t *testing.T) {
	called := false
	r := findings.Result{}
	apps := windowsApps(context.Background(), &r, func(_ context.Context, name string, args ...string) ([]byte, error) {
		called = true
		s := strings.Join(args, " ")
		if name != "powershell" || strings.Contains(s, "Win32_Product") || strings.Contains(s, "UninstallString") || strings.Contains(s, "Remove-") {
			t.Fatalf("unsafe probe %s", s)
		}
		return []byte(`[{"DisplayName":"App","DisplayVersion":"1","InstallLocation":"C:\\Apps\\App","EstimatedSize":4}]`), nil
	})
	if !called || len(apps) != 1 || apps[0].size == nil || *apps[0].size != 4096 {
		t.Fatalf("%+v", apps)
	}
}
func TestPlistNestedKeysDoNotOverrideBundleMetadata(t *testing.T) {
	values := plistStrings([]byte(`<plist><dict><key>CFBundleShortVersionString</key><string>1.2</string><key>Nested</key><dict><key>CFBundleShortVersionString</key><string>bad</string></dict><key>CFBundleDisplayName</key><string>A &amp; B</string></dict></plist>`))
	if values["CFBundleShortVersionString"] != "1.2" || values["CFBundleDisplayName"] != "A & B" {
		t.Fatal(values)
	}
}

func TestSingleWindowsRegistryRecord(t *testing.T) {
	apps, e := parseRegistry([]byte(`{"DisplayName":"Only App","EstimatedSize":null}`))
	if e != nil || len(apps) != 1 || apps[0].size != nil {
		t.Fatalf("%+v %v", apps, e)
	}
}
