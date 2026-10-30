package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestInteractiveSelectionOverridesFlags(t *testing.T) {
	var out bytes.Buffer
	feature := ""
	all := true
	roots := listFlag{"old-scope"}
	confirmed := false
	input := strings.NewReader("detect\nyes\nduplicates\nreview\nchosen-scope\n")
	if err := onboard(context.Background(), input, &out, &feature, &all, &roots, &confirmed); err != nil {
		t.Fatal(err)
	}
	if all || feature != "duplicates" || len(roots) != 1 || roots[0] != "chosen-scope" || !confirmed {
		t.Fatal("interactive change failed", all, feature, roots, confirmed)
	}
}
func TestBoundedAndCancellableInput(t *testing.T) {
	if _, err := readAnswer(context.Background(), strings.NewReader(strings.Repeat("a", 9000))); err == nil {
		t.Fatal("oversized response accepted")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := readAnswer(ctx, reader); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("input ignored cancellation")
	}
}

func TestJSONOutputEscapesDirectionalControls(t *testing.T) {
	var b bytes.Buffer
	value := "synthetic\u202eapp"
	if e := jsonOut(&b, map[string]string{"target": value}); e != nil {
		t.Fatal(e)
	}
	if strings.ContainsRune(b.String(), '\u202e') || !strings.Contains(b.String(), `\u202e`) {
		t.Fatal("invisible direction control escaped display")
	}
}
