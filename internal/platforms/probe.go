// Package platforms provides bounded, read-only native metadata probes.
package platforms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const MaxProbeBytes = 4 << 20

var ErrOutputLimit = errors.New("native metadata output exceeded limit")

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, ErrOutputLimit
	}
	return b.Buffer.Write(p)
}

// Tool resolves system-provided executables without consulting the current directory
// or arbitrary PATH entries. No command shell is used.
func Tool(name string) string {
	if strings.ContainsAny(name, "/\\") {
		return ""
	}
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		if name == "powershell" {
			p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
			if regular(p) {
				return p
			}
		}
		return ""
	}
	for _, d := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		p := filepath.Join(d, name)
		if regular(p) {
			return p
		}
	}
	return ""
}
func regular(p string) bool { f, e := os.Stat(p); return e == nil && f.Mode().IsRegular() }

// Run discards stderr (which may contain private details), bounds stdout and
// terminates a slow native probe. It never invokes a shell.
func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	p := Tool(name)
	if p == "" {
		return nil, exec.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out := &cappedBuffer{max: MaxProbeBytes}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func ReadSmall(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, ErrOutputLimit
	}
	return b, nil
}

// OpenMetadataDirectory rejects symbolic links in every directory component
// before opening a fixed metadata root. os.Root confines subsequent relative reads.
func OpenMetadataDirectory(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("metadata directory must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("linked or non-directory metadata path")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return os.OpenRoot(path)
}
