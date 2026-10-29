package platforms

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputIsBounded(t *testing.T) {
	b := &cappedBuffer{max: 5}
	if _, e := b.Write([]byte("12345")); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Write([]byte("6")); !errors.Is(e, ErrOutputLimit) || b.Len() != 5 {
		t.Fatal("unbounded output")
	}
	p := filepath.Join(t.TempDir(), "large")
	if e := os.WriteFile(p, []byte("123456"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadSmall(p, 5); !errors.Is(e, ErrOutputLimit) {
		t.Fatal("unbounded file read")
	}
}
func TestToolRejectsPaths(t *testing.T) {
	for _, name := range []string{"./ps", "/tmp/ps", `..\powershell`} {
		if Tool(name) != "" {
			t.Fatalf("accepted tool path %s", name)
		}
	}
}

func TestMetadataRootRejectsAncestorLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if e := os.MkdirAll(filepath.Join(target, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	linked := filepath.Join(dir, "linked")
	if e := os.Symlink(target, linked); e != nil {
		t.Skip("symlink creation unavailable on this OS")
	}
	if root, e := OpenMetadataDirectory(filepath.Join(linked, "nested")); e == nil {
		root.Close()
		t.Fatal("followed ancestor symlink")
	}
}
