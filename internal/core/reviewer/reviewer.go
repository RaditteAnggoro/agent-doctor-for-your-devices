// Package reviewer inspects metadata and supplies manual location guidance.
// It never opens a target's contents, starts a program, or alters a source item.
package reviewer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
)

type ItemStatus struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}
type Inspection struct {
	Finding findings.Finding `json:"finding"`
	Items   []ItemStatus     `json:"items"`
}

func Find(report findings.Report, id string) (findings.Finding, error) {
	for _, r := range report.Results {
		for _, f := range r.Findings {
			if f.ID == id {
				return f, nil
			}
		}
	}
	return findings.Finding{}, errors.New("finding is not in this scan")
}

func Inspect(report findings.Report, id string) (Inspection, error) {
	f, err := Find(report, id)
	if err != nil {
		return Inspection{}, err
	}
	result := Inspection{Finding: f, Items: []ItemStatus{}}
	expected := map[string]findings.File{}
	if f.Junk != nil {
		expected[f.Junk.File.Path] = f.Junk.File
	}
	if f.Duplicate != nil {
		for _, member := range f.Duplicate.Members {
			expected[member.Path] = member
		}
	}
	for _, path := range f.Paths {
		item := ItemStatus{Path: path, Status: "REJECTED", Reason: "path is outside the approved filesystem roots or is protected"}
		if safety.Protected(path) || safety.Excluded(path, report.Scope.Exclusions) {
			result.Items = append(result.Items, item)
			continue
		}
		var root string
		for _, candidate := range report.Scope.Roots {
			if filepath.IsAbs(path) && safety.Within(candidate, path) {
				root = candidate
				break
			}
		}
		if root == "" {
			result.Items = append(result.Items, item)
			continue
		}
		rootInfo, rootErr := os.Lstat(root)
		if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			result.Items = append(result.Items, item)
			continue
		}
		if err := safety.NoSymlink(path); err != nil {
			item.Reason = "path is inaccessible, missing, or has a link component"
			if errors.Is(err, os.ErrNotExist) {
				item.Status = "MISSING"
			}
			result.Items = append(result.Items, item)
			continue
		}
		r, err := os.OpenRoot(root)
		if err != nil {
			item.Reason = "approved root is inaccessible"
			result.Items = append(result.Items, item)
			continue
		}
		openedRoot, err := r.Stat(".")
		if err != nil || !os.SameFile(rootInfo, openedRoot) {
			r.Close()
			item.Reason = "approved root changed while opening"
			result.Items = append(result.Items, item)
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			r.Close()
			result.Items = append(result.Items, item)
			continue
		}
		info, err := r.Lstat(rel)
		r.Close()
		if err != nil {
			item.Status = "MISSING"
			item.Reason = "item no longer exists or is inaccessible"
			result.Items = append(result.Items, item)
			continue
		}
		if !info.Mode().IsRegular() {
			item.Reason = "item is not a regular file"
			result.Items = append(result.Items, item)
			continue
		}
		item.Status = "CURRENT"
		item.Reason = "metadata is readable; contents were not opened or revalidated"
		if old, ok := expected[path]; ok {
			device, identity, _, _ := safety.Identity(info)
			if info.Size() != old.Size || (!old.Modified.IsZero() && !info.ModTime().Equal(old.Modified)) || (old.Identity != "" && identity != old.Identity) || (old.Device != "" && device != old.Device) {
				item.Status = "CHANGED"
				item.Reason = "identity, size, or modification time differs from the scan; rescan before drawing conclusions"
			}
		} else {
			item.Status = "UNVERIFIED"
			item.Reason = "scan has no file identity to compare; metadata only"
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}

// Reveal returns containing-folder strings only. The CLI displays these as data;
// no file-manager command or target file is executed on any platform.
func Reveal(report findings.Report, id string) ([]string, error) {
	inspection, err := Inspect(report, id)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	seen := map[string]bool{}
	for _, item := range inspection.Items {
		if item.Status != "CURRENT" {
			continue
		}
		parent := filepath.Dir(item.Path)
		if !seen[parent] {
			paths = append(paths, parent)
			seen[parent] = true
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no current approved file location available; inspect the stored finding for manual guidance")
	}
	return paths, nil
}
