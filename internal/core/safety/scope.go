// Package safety enforces the shared read-only filesystem boundary.
package safety

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Protected classifies paths, not their suitability for deletion. Explicit scope
// never overrides these conservative v1 exclusions.
func Protected(path string) bool {
	p := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	for _, part := range strings.Split(p, "/") {
		switch part {
		case ".git", ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".config", "credentials", ".env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig", "keychains", "application support", "windows", "system volume information":
			return true
		}
		if strings.HasPrefix(part, ".env.") || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") || strings.HasSuffix(part, ".kdbx") || strings.HasSuffix(part, ".db") || strings.HasSuffix(part, ".sqlite") || strings.HasSuffix(part, ".sqlite3") || strings.HasSuffix(part, ".sqlite-wal") || strings.HasSuffix(part, ".sqlite-shm") {
			return true
		}
		if strings.HasSuffix(part, ".photoslibrary") || strings.HasSuffix(part, ".photolibrary") || strings.HasSuffix(part, ".app") || strings.Contains(part, "onedrive") || strings.Contains(part, "dropbox") || strings.Contains(part, "google drive") || strings.Contains(part, "googledrive") || strings.Contains(part, "icloud") || part == "mobile documents" || part == "cloudstorage" {
			return true
		}
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/sbin", "/system", "/private/var/db", "/private/var/root", "/private/var/log", "/mnt/c", "/mnt/wsl"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	for _, s := range []string{"google/chrome", "mozilla/firefox", "microsoft/edge", "/network/", "/net/"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return strings.HasPrefix(p, "//")
}

func NoSymlink(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
			return fmt.Errorf("link or irregular path rejected: %q", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
	}
	return nil
}

func Root(path string) (string, error) {
	if strings.Contains(filepath.ToSlash(path), "../") || filepath.Base(path) == ".." {
		return "", fmt.Errorf("parent traversal rejected")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if abs == filepath.VolumeName(abs)+string(os.PathSeparator) || Protected(abs) {
		return "", fmt.Errorf("protected or whole-volume scope rejected: %q", abs)
	}
	if err := NoSymlink(abs); err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("scope must be a directory")
	}
	return abs, nil
}

func Within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}
func Excluded(path string, exclusions []string) bool {
	for _, e := range exclusions {
		if Within(e, path) {
			return true
		}
	}
	return false
}
