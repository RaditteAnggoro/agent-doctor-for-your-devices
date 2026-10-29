package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
)

type Entry struct {
	File findings.File
	Info os.FileInfo
	Root *os.Root
	Rel  string
}
type Inventory struct {
	Entries  []Entry
	Coverage findings.Coverage
	Warnings []string
	roots    []*os.Root
}

func (i *Inventory) Close() {
	for _, r := range i.roots {
		_ = r.Close()
	}
}
func (i *Inventory) incomplete(msg string) {
	i.Coverage.Status = "PARTIAL"
	i.Warnings = append(i.Warnings, msg)
}
func Walk(ctx context.Context, scope findings.Scope) *Inventory {
	inv := &Inventory{Coverage: findings.Coverage{Status: "COMPLETED"}, Entries: []Entry{}, Warnings: []string{}}
	seen := map[string]bool{}
	for _, path := range scope.Roots {
		if ctx.Err() != nil {
			inv.Coverage.Status = "CANCELLED"
			break
		}
		abs, err := safety.Root(path)
		if err != nil {
			inv.incomplete(err.Error())
			inv.Coverage.Inaccessible++
			continue
		}
		root, err := os.OpenRoot(abs)
		if err != nil {
			inv.incomplete(fmt.Sprintf("root inaccessible: %q", abs))
			inv.Coverage.Inaccessible++
			continue
		}
		inv.roots = append(inv.roots, root)
		rootInfo, err := root.Stat(".")
		if err != nil {
			inv.incomplete("root metadata unavailable")
			continue
		}
		dev, _, _, _ := safety.Identity(rootInfo)
		var walk func(string, int)
		walk = func(rel string, depth int) {
			if ctx.Err() != nil {
				inv.Coverage.Status = "CANCELLED"
				return
			}
			if inv.Coverage.Visited >= scope.MaxFiles {
				inv.incomplete("entry budget reached")
				return
			}
			before, err := root.Lstat(rel)
			if err != nil || before.Mode()&os.ModeSymlink != 0 {
				inv.Coverage.Skipped++
				inv.incomplete("directory changed or became a link")
				return
			}
			dir, err := root.Open(rel)
			if err != nil {
				inv.Coverage.Inaccessible++
				inv.incomplete(fmt.Sprintf("directory inaccessible: %q", filepath.Join(abs, rel)))
				return
			}
			defer dir.Close()
			current, err := dir.Stat()
			if err != nil || !os.SameFile(before, current) {
				inv.Coverage.Skipped++
				inv.incomplete("directory identity changed")
				return
			}
			for {
				if ctx.Err() != nil {
					inv.Coverage.Status = "CANCELLED"
					return
				}
				entries, err := dir.ReadDir(128)
				for _, e := range entries {
					if ctx.Err() != nil {
						inv.Coverage.Status = "CANCELLED"
						return
					}
					if inv.Coverage.Visited >= scope.MaxFiles {
						inv.incomplete("entry budget reached")
						return
					}
					inv.Coverage.Visited++
					sub := filepath.Join(rel, e.Name())
					full := filepath.Join(abs, sub)
					if seen[full] {
						continue
					}
					seen[full] = true
					if safety.Protected(full) || safety.Excluded(full, scope.Exclusions) || e.Type()&os.ModeSymlink != 0 || e.Type()&os.ModeIrregular != 0 {
						inv.Coverage.Skipped++
						continue
					}
					info, err := root.Lstat(sub)
					if err != nil {
						inv.Coverage.Inaccessible++
						inv.incomplete(fmt.Sprintf("metadata inaccessible: %q", full))
						continue
					}
					if !safety.Owned(info) {
						inv.Coverage.Skipped++
						continue
					}
					if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
						inv.Coverage.Skipped++
						continue
					}
					d, id, hard, sparse := safety.Identity(info)
					var hardlink *bool
					if id != "" {
						hardlink = &hard
					}
					if dev != "" && d != dev {
						inv.Coverage.Skipped++
						inv.incomplete("mount boundary skipped")
						continue
					}
					if info.IsDir() {
						if depth >= scope.MaxDepth {
							inv.Coverage.Skipped++
							inv.incomplete("depth limit reached")
							continue
						}
						walk(sub, depth+1)
					} else if info.Mode().IsRegular() {
						inv.Entries = append(inv.Entries, Entry{findings.File{Path: full, Size: info.Size(), Modified: info.ModTime(), Device: d, Identity: id, Hardlink: hardlink, Sparse: sparse}, info, root, sub})
					} else {
						inv.Coverage.Skipped++
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					inv.Coverage.Inaccessible++
					inv.incomplete("directory read failed")
					break
				}
			}
		}
		walk(".", 0)
	}
	sort.Slice(inv.Entries, func(a, b int) bool { return inv.Entries[a].File.Path < inv.Entries[b].File.Path })
	if inv.Coverage.Status == "PARTIAL" && len(inv.Entries) == 0 && inv.Coverage.Inaccessible > 0 {
		inv.Coverage.Status = "PERMISSION_DENIED"
	}
	// Coalesce repeated budget diagnostics without hiding inaccessible counts.
	uniq := []string{}
	for _, w := range inv.Warnings {
		found := false
		for _, u := range uniq {
			if w == u {
				found = true
				break
			}
		}
		if !found {
			uniq = append(uniq, w)
		}
	}
	inv.Warnings = uniq
	return inv
}

// Open revalidates both pathname and opened descriptor inside an OS rooted handle.
func (e Entry) Open() (*os.File, error) {
	if safety.Protected(e.File.Path) {
		return nil, errors.New("protected path")
	}
	components := strings.Split(e.Rel, string(os.PathSeparator))
	p := "."
	for _, c := range components {
		p = filepath.Join(p, c)
		st, err := e.Root.Lstat(p)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeIrregular != 0 {
			return nil, errors.New("path changed to link")
		}
	}
	f, err := e.Root.Open(e.Rel)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !os.SameFile(e.Info, st) || !st.Mode().IsRegular() || st.Size() != e.Info.Size() || !st.ModTime().Equal(e.Info.ModTime()) {
		_ = f.Close()
		return nil, errors.New("file changed since discovery")
	}
	return f, nil
}
