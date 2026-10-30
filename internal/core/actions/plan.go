// Package actions implements opt-in, single-target Trash plans. Scanning never
// calls an executor. A plan is evidence for approval, not approval itself.
package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/reviewer"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
)

type Fingerprint struct {
	Path         string    `json:"path"`
	Device       string    `json:"device"`
	Identity     string    `json:"identity"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified"`
	SHA256       string    `json:"sha256,omitempty"`
	LogicalBytes int64     `json:"logical_bytes"`
	Directory    bool      `json:"directory"`
}
type Plan struct {
	SchemaVersion  string       `json:"schema_version"`
	ID             string       `json:"id"`
	ScanID         string       `json:"scan_id"`
	FindingID      string       `json:"finding_id"`
	Action         string       `json:"action"`
	OS             string       `json:"os"`
	Created        time.Time    `json:"created"`
	Expires        time.Time    `json:"expires"`
	Target         Fingerprint  `json:"target"`
	Retain         *Fingerprint `json:"retain,omitempty"`
	ApprovedRoot   string       `json:"approved_root"`
	MaxReadBytes   int64        `json:"max_read_bytes"`
	BackupReviewed bool         `json:"backup_reviewed"`
	BundleOnly     bool         `json:"bundle_only"`
	Consequences   []string     `json:"consequences"`
	Recovery       string       `json:"recovery"`
	ApprovalHash   string       `json:"approval_hash"`
}
type Options struct {
	Target, Retain, Action     string
	BackupReviewed, BundleOnly bool
	MaxReadBytes               int64
}

func Hash(p Plan) (string, error) {
	p.ApprovalHash = ""
	b, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func Validate(p Plan, now time.Time) error {
	if p.SchemaVersion != "1.0" || !strings.HasPrefix(p.ID, "plan-") || len(p.ID) != 29 || p.ScanID == "" || p.FindingID == "" {
		return errors.New("invalid action plan identity")
	}
	if _, e := hex.DecodeString(strings.TrimPrefix(p.ID, "plan-")); e != nil {
		return errors.New("invalid plan identifier")
	}
	if p.OS != runtime.GOOS || (p.Action != "TRASH_FILE" && p.Action != "UNINSTALL_APP_BUNDLE") {
		return errors.New("plan action or operating system mismatch")
	}
	if p.Created.IsZero() || p.Expires.Sub(p.Created) != 15*time.Minute || now.Before(p.Created) || !now.Before(p.Expires) {
		return errors.New("plan expired or clock is inconsistent; create and review a fresh plan")
	}
	if !p.BackupReviewed || p.MaxReadBytes < 1 || p.MaxReadBytes > 64<<30 {
		return errors.New("backup review or read budget missing")
	}
	if p.Target.Directory != (p.Action == "UNINSTALL_APP_BUNDLE") || p.Target.Identity == "" || p.Target.Device == "" {
		return errors.New("target type or file identity is missing")
	}
	if p.Action == "UNINSTALL_APP_BUNDLE" && !p.BundleOnly {
		return errors.New("bundle-only uninstall acknowledgement is missing")
	}
	h, e := Hash(p)
	if e != nil || h != p.ApprovalHash {
		return errors.New("action plan content changed; approval hash does not match")
	}
	if p.Target.Path == p.ApprovedRoot || !filepath.IsAbs(p.Target.Path) || !safety.Within(p.ApprovedRoot, p.Target.Path) {
		return errors.New("target outside approved action root")
	}
	return nil
}

func Build(ctx context.Context, r findings.Report, id string, o Options, now time.Time) (Plan, error) {
	var p Plan
	if !o.BackupReviewed {
		return p, errors.New("review backup/retention needs, then explicitly pass --backup-reviewed")
	}
	if o.MaxReadBytes < 1 || o.MaxReadBytes > 64<<30 {
		return p, errors.New("action read budget must be 1 byte..64GiB")
	}
	if r.Timestamp.IsZero() || now.Before(r.Timestamp) || now.Sub(r.Timestamp) > 24*time.Hour {
		return p, errors.New("scan is older than 24 hours or clock differs; rescan before planning actions")
	}
	if r.Environment.OS != runtime.GOOS || r.Environment.Type != "native" || r.Environment.Remote {
		return p, errors.New("execution requires a confirmed native local environment; subsystem/remote actions are unavailable")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return p, errors.New("UNSUPPORTED: safe native Trash execution is not available on this platform")
	}
	f, e := reviewer.Find(r, id)
	if e != nil {
		return p, e
	}
	target, e := filepath.Abs(o.Target)
	if e != nil || o.Target == "" {
		return p, errors.New("an exact --target path is required")
	}
	target = filepath.Clean(target)
	p = Plan{SchemaVersion: "1.0", ScanID: r.ScanID, FindingID: id, OS: runtime.GOOS, Created: now.UTC(), Expires: now.UTC().Add(15 * time.Minute), MaxReadBytes: o.MaxReadBytes, BackupReviewed: true, BundleOnly: o.BundleOnly, Recovery: "Restore the item manually from OS Trash to the original target path. Do not empty Trash; subscriptions and external app data are retained. No permanent deletion fallback exists."}
	switch o.Action {
	case "trash":
		p.Action = "TRASH_FILE"
		if f.Junk == nil && f.Duplicate == nil {
			return Plan{}, errors.New("Trash plans require a junk file or an exact duplicate member")
		}
		var expected *findings.File
		if f.Junk != nil && f.Junk.File.Path == target {
			x := f.Junk.File
			expected = &x
		}
		if f.Duplicate != nil {
			if f.Duplicate.MatchType != "EXACT_CONTENT" || f.Duplicate.HashAlgorithm != "SHA-256" || len(f.Duplicate.Digest) != 64 {
				return Plan{}, errors.New("duplicate member lacks exact content verification")
			}
			for _, m := range f.Duplicate.Members {
				if m.Path == target {
					x := m
					expected = &x
				}
			}
		}
		if expected == nil {
			return Plan{}, errors.New("target is not a file recorded in this finding")
		}
		for _, root := range r.Scope.Roots {
			if safety.Within(root, target) && root != target {
				p.ApprovedRoot = root
				break
			}
		}
		if p.ApprovedRoot == "" || safety.Excluded(target, r.Scope.Exclusions) {
			return Plan{}, errors.New("target is outside scope or excluded")
		}
		if e := filePolicy(target); e != nil {
			return Plan{}, e
		}
		snap, e := fingerprint(ctx, target, p.ApprovedRoot, false, o.MaxReadBytes)
		if e != nil {
			return Plan{}, e
		}
		if !matchesScan(snap, *expected) {
			return Plan{}, errors.New("target changed since scan; rescan")
		}
		p.Target = snap
		if f.Duplicate != nil {
			keep, e := filepath.Abs(o.Retain)
			if e != nil || o.Retain == "" || keep == target {
				return Plan{}, errors.New("duplicate action requires a different exact --keep member path")
			}
			var retained *findings.File
			for _, m := range f.Duplicate.Members {
				if m.Path == keep {
					x := m
					retained = &x
				}
			}
			if retained == nil || safety.Excluded(keep, r.Scope.Exclusions) {
				return Plan{}, errors.New("retained member is not approved in this group")
			}
			var keepRoot string
			for _, root := range r.Scope.Roots {
				if safety.Within(root, keep) {
					keepRoot = root
					break
				}
			}
			if keepRoot == "" {
				return Plan{}, errors.New("retained member outside approved roots")
			}
			if e := filePolicy(keep); e != nil {
				return Plan{}, e
			}
			other, e := fingerprint(ctx, keep, keepRoot, false, o.MaxReadBytes)
			if e != nil {
				return Plan{}, e
			}
			if !matchesScan(other, *retained) || other.SHA256 != snap.SHA256 || snap.SHA256 != f.Duplicate.Digest || other.Identity == snap.Identity {
				return Plan{}, errors.New("retained/selected content or identity changed; rescan")
			}
			p.Retain = &other
		}
		p.Consequences = []string{f.PossibleConsequences, "Only this exact regular file is moved to OS Trash; other files remain. Physical space is not promised while Trash retains it.", "Backup retention was acknowledged by the user; the tool did not create a backup."}
	case "uninstall":
		if runtime.GOOS != "darwin" {
			return Plan{}, errors.New("UNSUPPORTED: application uninstall execution currently supports eligible macOS bundles only; use the package manager/vendor UI elsewhere")
		}
		a := f.Application
		if a == nil || a.Location == nil || *a.Location != target {
			return Plan{}, errors.New("target must equal the application's recorded installation location")
		}
		if a.AppRole != "MAIN" || a.SystemApp == nil || *a.SystemApp || a.Running == nil || *a.Running || len(a.RelatedApps) > 0 {
			return Plan{}, errors.New("system/helper/running/related or unknown app requires vendor/manual review; no bundle action")
		}
		if !o.BundleOnly {
			return Plan{}, errors.New("review vendor instructions, confirm no dedicated uninstaller is needed, and explicitly pass --bundle-only")
		}
		parent := filepath.Dir(target)
		home, _ := os.UserHomeDir()
		if parent != "/Applications" && parent != filepath.Join(home, "Applications") {
			return Plan{}, errors.New("only immediate user Application bundles are eligible")
		}
		p.ApprovedRoot = parent
		if e := appPolicy(target); e != nil {
			return Plan{}, e
		}
		snap, e := fingerprint(ctx, target, parent, true, o.MaxReadBytes)
		if e != nil {
			return Plan{}, e
		}
		if a.BundleModifiedAt == nil || !snap.Modified.Equal(*a.BundleModifiedAt) {
			return Plan{}, errors.New("bundle metadata changed or lacks recorded modification time; rescan")
		}
		p.Target = snap
		p.Consequences = []string{"This is a bundle-only uninstall: the selected .app moves to Trash. External documents, preferences, caches, login items and subscriptions are retained.", "A dedicated vendor uninstaller may be required for integrations; use it manually instead of this action if applicable.", "Restore the app from Trash if needed; no process is stopped and no administrator access is requested."}
	default:
		return Plan{}, errors.New("action must be trash or uninstall")
	}
	var random [12]byte
	if _, e := rand.Read(random[:]); e != nil {
		return Plan{}, e
	}
	p.ID = "plan-" + hex.EncodeToString(random[:])
	p.ApprovalHash, _ = Hash(p)
	return p, Validate(p, now)
}

func matchesScan(f Fingerprint, s findings.File) bool {
	return s.Identity != "" && f.Identity == s.Identity && f.Device == s.Device && f.Size == s.Size && f.Modified.Equal(s.Modified) && !s.Symlink && !s.Cloud && s.Hardlink != nil && !*s.Hardlink
}
func filePolicy(path string) error {
	if safety.Protected(path) {
		return errors.New("protected or cloud path cannot be trashed")
	}
	p := "/" + strings.ToLower(filepath.ToSlash(path)) + "/"
	for _, hint := range []string{"/uploads/", "/src/", "/node_modules/", "/backup/", "/backups/"} {
		if strings.Contains(p, hint) {
			return errors.New("project, managed upload or backup path requires manual owner-aware cleanup")
		}
	}
	// An enclosing repository establishes live project context even if .git was
	// excluded from the scan itself. Do not traverse its contents.
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, e := os.Lstat(filepath.Join(dir, ".git")); e == nil {
			return errors.New("working repository requires manual project-aware cleanup")
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return nil
}
func appPolicy(path string) error {
	if !strings.HasSuffix(strings.ToLower(path), ".app") || safety.Protected(filepath.Dir(path)) {
		return errors.New("protected or non-application target")
	}
	if e := safety.NoSymlink(path); e != nil {
		return e
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, rel := range []string{"Contents/Library/SystemExtensions", "Contents/Library/LaunchServices", "Contents/Library/LoginItems", "Contents/Library/LaunchDaemons", "Contents/Library/LaunchAgents"} {
		if _, e := r.Lstat(filepath.FromSlash(rel)); e == nil {
			return errors.New("application has integration components; use vendor uninstall flow")
		} else if !os.IsNotExist(e) {
			return errors.New("application integration checks were inaccessible")
		}
	}
	// Common security/VPN clients require vendor handling. This is a conservative
	// deny hint, not a classification of whether the product is harmful.
	n := strings.ToLower(filepath.Base(path))
	for _, hint := range []string{"mcafee", "antivirus", "security", "vpn", "tunnelblick", "orbstack", "uninstall", "helper", "systemextension"} {
		if strings.Contains(n, hint) {
			return errors.New("integration/security/helper app requires official vendor uninstall flow")
		}
	}
	return nil
}

// fingerprint validates path, ownership, mount identity and a secure parent,
// then reads a single regular file through an OS-rooted handle to hash it.
func fingerprint(ctx context.Context, path, root string, directory bool, max int64) (Fingerprint, error) {
	var out Fingerprint
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if !filepath.IsAbs(root) || !safety.Within(root, path) || root == path {
		return out, errors.New("invalid action root")
	}
	if e := safety.NoSymlink(path); e != nil {
		return out, e
	}
	parent := filepath.Dir(path)
	ps, e := os.Stat(parent)
	if e != nil {
		return out, e
	}
	if !safety.Owned(ps) || ps.Mode().Perm()&0022 != 0 {
		if !(directory && parent == "/Applications" && safety.TrustedSystemParent(ps)) {
			return out, errors.New("action parent must be user-owned and not group/world writable, or the trusted system Applications directory")
		}
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return out, e
	}
	defer r.Close()
	rel, e := filepath.Rel(root, path)
	if e != nil {
		return out, e
	}
	st, e := r.Lstat(rel)
	if e != nil {
		return out, e
	}
	if st.IsDir() != directory || (!directory && !st.Mode().IsRegular()) || !safety.Owned(st) {
		return out, errors.New("unexpected target type or ownership")
	}
	device, id, hard, _ := safety.Identity(st)
	rs, e := r.Stat(".")
	if e != nil {
		return out, e
	}
	rd, _, _, _ := safety.Identity(rs)
	if id == "" || device == "" || device != rd || hard && !directory {
		return out, errors.New("unknown identity, mount boundary or shared hardlink rejected")
	}
	out = Fingerprint{Path: path, Device: device, Identity: id, Size: st.Size(), Modified: st.ModTime(), Directory: directory}
	if directory {
		digest, logical, e := bundleDigest(ctx, r, rel, device, max)
		if e != nil {
			return out, e
		}
		out.SHA256 = digest
		out.LogicalBytes = logical
		return out, nil
	}
	if st.Size() > max {
		return out, errors.New("target exceeds action hash budget; increase --max-bytes deliberately or use manual review")
	}
	f, e := r.Open(rel)
	if e != nil {
		return out, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return out, errors.New("target changed while opening")
	}
	h := sha256.New()
	buf := make([]byte, 64*1024)
	var n int64
	for {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		count, e := f.Read(buf)
		if count > 0 {
			n += int64(count)
			if n > max {
				return out, errors.New("action hash budget exceeded")
			}
			_, _ = h.Write(buf[:count])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, e
		}
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(st, after) || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) || n != st.Size() {
		return out, errors.New("target changed during fingerprinting")
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	out.LogicalBytes = n
	return out, nil
}

// bundleDigest hashes bounded regular-file content and directory metadata,
// including symlink identities without following them. Known content changes
// invalidate the plan; unrelated concurrent writers remain an external race.
func bundleDigest(ctx context.Context, r *os.Root, rel, device string, maxRead int64) (string, int64, error) {
	remaining := maxRead
	buffer := make([]byte, 64*1024)
	h := sha256.New()
	entries := 0
	var logical int64
	seen := map[string]bool{}
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if depth > 48 {
			return errors.New("bundle action depth limit reached")
		}
		st, e := r.Lstat(path)
		if e != nil {
			return e
		}
		dev, id, _, _ := safety.Identity(st)
		if id == "" || dev != device {
			return errors.New("bundle identity or mount boundary unsupported")
		}
		entries++
		if entries > 10000 {
			return errors.New("bundle action entry limit reached; use vendor/manual uninstall")
		}
		fmt.Fprintf(h, "%q:%s:%d:%d:%d\n", path, id, st.Mode(), st.Size(), st.ModTime().UnixNano())
		if st.Mode().IsRegular() && !seen[id] {
			if st.Size() < 0 || st.Size() > int64(^uint64(0)>>1)-logical {
				return errors.New("bundle logical size overflow")
			}
			if st.Size() > remaining {
				return errors.New("bundle exceeds action read budget; increase --max-bytes deliberately or use vendor/manual uninstall")
			}
			file, err := r.Open(path)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(st, opened) {
				file.Close()
				return errors.New("bundle file changed while opening")
			}
			var read int64
			for {
				if err := ctx.Err(); err != nil {
					file.Close()
					return err
				}
				n, err := file.Read(buffer)
				if int64(n) > remaining {
					file.Close()
					return errors.New("bundle action read budget exceeded")
				}
				if n > 0 {
					remaining -= int64(n)
					read += int64(n)
					_, _ = h.Write(buffer[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					file.Close()
					return err
				}
			}
			after, err := file.Stat()
			file.Close()
			if err != nil || !os.SameFile(st, after) || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) || read != st.Size() {
				return errors.New("bundle file changed during fingerprinting")
			}
			logical += st.Size()
			seen[id] = true
		}
		if st.IsDir() {
			f, e := r.Open(path)
			if e != nil {
				return e
			}
			defer f.Close()
			opened, e := f.Stat()
			if e != nil || !os.SameFile(st, opened) {
				return errors.New("bundle changed during directory open")
			}
			var children []os.DirEntry
			for {
				batch, err := f.ReadDir(128)
				children = append(children, batch...)
				if len(children) > 10000-entries {
					return errors.New("bundle action entry limit reached")
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
			}
			sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
			for _, child := range children {
				if e := walk(filepath.Join(path, child.Name()), depth+1); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := walk(rel, 0); e != nil {
		return "", 0, e
	}
	return hex.EncodeToString(h.Sum(nil)), logical, nil
}
