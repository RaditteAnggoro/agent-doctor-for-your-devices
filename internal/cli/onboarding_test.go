package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
)

func TestFriendlyIntroDoesNotBecomeFeatureOrApproval(t *testing.T) {
	var out bytes.Buffer
	feature := ""
	all := false
	roots := listFlag{}
	confirmed := false
	scope := testkit.Dir(t)
	// The name and symptom deliberately look like later control answers.
	input := strings.NewReader("ya\nsemua\n5\nmaybe\nya\n1\n1\n" + scope + "\n")
	if err := onboard(context.Background(), input, &out, &feature, &all, &roots, &confirmed); err != nil {
		t.Fatal(err)
	}
	if feature != "junk" || all || !confirmed || len(roots) != 1 || roots[0] != scope {
		t.Fatalf("intro changed scan choices: %s %t %v %t", feature, all, roots, confirmed)
	}
	text := out.String()
	welcome := strings.Index(text, "selamat datang")
	name := strings.Index(text, "aku panggil kamu siapa")
	device := strings.Index(text, "pakai OS apa")
	if welcome < 0 || name <= welcome || device <= name || !strings.Contains(text, "Belum aku lanjutkan") {
		t.Fatal("intro/confirmation sequence missing", text)
	}
}
func TestIntroOptionalAndCancelsAtEveryStage(t *testing.T) {
	prefixes := []string{"", "\n", "\n\n", "\n\n5\n", "\n\n5\nya\n", "\n\n5\nya\n1\n", "\n\n5\nya\n1\n1\n"}
	for _, prefix := range prefixes {
		var out bytes.Buffer
		feature := ""
		all := false
		roots := listFlag{}
		confirmed := false
		err := onboard(context.Background(), strings.NewReader(prefix+"batal\n"), &out, &feature, &all, &roots, &confirmed)
		if !errors.Is(err, context.Canceled) || len(roots) != 0 {
			t.Fatalf("cancellation at prefix %q changed scope: %v %v", prefix, roots, err)
		}
	}
	var out bytes.Buffer
	feature := ""
	all := false
	roots := listFlag{}
	confirmed := false
	if err := onboard(context.Background(), strings.NewReader("lewati\nskip\n5\nya\n3\n2\n"), &out, &feature, &all, &roots, &confirmed); err != nil {
		t.Fatal(err)
	}
	if feature != "applications" || all || len(roots) != 0 {
		t.Fatal("optional intro forced a scope")
	}
}
func TestNicknameIsBoundedAndTerminalSafe(t *testing.T) {
	var out bytes.Buffer
	feature := ""
	all := false
	roots := listFlag{}
	confirmed := false
	input := strings.Repeat("a", 41) + "\n\x1b[31mUji\u202e\n\n5\nya\n3\n1\n"
	if err := onboard(context.Background(), strings.NewReader(input), &out, &feature, &all, &roots, &confirmed); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.ContainsRune(text, '\x1b') || strings.ContainsRune(text, '\u202e') || !strings.Contains(text, `\u{001b}`) || !strings.Contains(text, "40 karakter") {
		t.Fatal("nickname was not bounded/escaped", text)
	}
}
func TestFeatureChoicesAreExplicitAndDeduplicated(t *testing.T) {
	choices, all, ok := featureChoices("1, aplikasi, 4, 1")
	if !ok || all || strings.Join(choices, ",") != "junk,applications,duplicates" {
		t.Fatal(choices, all, ok)
	}
	for _, choice := range []string{"", "maybe", "ya", "1,unknown", "5,approve-all"} {
		if _, _, ok := featureChoices(choice); ok {
			t.Fatalf("ambiguous feature accepted: %q", choice)
		}
	}
	for _, choice := range []string{"5", "all", "semua"} {
		if choices, all, ok := featureChoices(choice); !ok || !all || len(choices) != 0 {
			t.Fatal(choice, choices, all, ok)
		}
	}
}
func TestDecliningDeviceDoesNotConfirmOrChooseFeatures(t *testing.T) {
	var out bytes.Buffer
	feature := ""
	all := false
	roots := listFlag{}
	confirmed := false
	err := onboard(context.Background(), strings.NewReader("NamaUji\ncek rutin\n5\ntidak\n"), &out, &feature, &all, &roots, &confirmed)
	if !errors.Is(err, context.Canceled) || confirmed || feature != "" || len(roots) != 0 {
		t.Fatal("declined device advanced", err)
	}
	if strings.Contains(out.String(), "Mau kita cek yang mana") {
		t.Fatal("continued after declining device")
	}
}

func TestHomeShortcutCannotHideParentTraversal(t *testing.T) {
	var out bytes.Buffer
	feature := ""
	all := false
	roots := listFlag{}
	confirmed := false
	dir := testkit.Dir(t)
	input := "\n\n5\nya\n1\n1\n~/../unapproved\n" + dir + "\n"
	if err := onboard(context.Background(), strings.NewReader(input), &out, &feature, &all, &roots, &confirmed); err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0] != dir || !strings.Contains(out.String(), "tanpa ..") {
		t.Fatal("home expansion hid parent traversal", roots, out.String())
	}
}
