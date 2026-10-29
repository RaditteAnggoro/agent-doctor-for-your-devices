// Package testkit creates only synthetic, canonical temporary directories.
package testkit

import (
	"os"
	"path/filepath"
	"testing"
)

func Dir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func File(t *testing.T, root, name, contents string) string {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
