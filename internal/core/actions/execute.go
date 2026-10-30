package actions

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

type Backend interface {
	Available() error
	Trash(context.Context, Fingerprint) (string, error)
}
type Outcome struct {
	PlanID             string    `json:"plan_id"`
	ApprovalHash       string    `json:"approval_hash"`
	Status             string    `json:"status"`
	Action             string    `json:"action"`
	Target             string    `json:"target"`
	TrashLocation      string    `json:"trash_location,omitempty"`
	Started            time.Time `json:"started"`
	Finished           time.Time `json:"finished"`
	FilesTrashed       int       `json:"files_trashed"`
	AppBundlesTrashed  int       `json:"app_bundles_trashed"`
	PermanentDeletions int       `json:"permanent_deletions"`
	Message            string    `json:"message"`
}

// Execute re-builds the selection from its immutable scan, validates current
// fingerprints, then asks the caller to durably journal STARTED before dispatch.
// Any ambiguous native result is UNKNOWN and must never be auto-retried.
func Execute(ctx context.Context, p Plan, r findings.Report, approval string, b Backend, before func(Outcome) error) (Outcome, error) {
	var out Outcome
	now := time.Now().UTC()
	if e := Validate(p, now); e != nil {
		return out, e
	}
	if subtle.ConstantTimeCompare([]byte(p.ApprovalHash), []byte(approval)) != 1 {
		return out, errors.New("explicit approval hash does not match the displayed plan")
	}
	if before == nil || b == nil {
		return out, errors.New("durable journal and native Trash backend are required")
	}
	if e := b.Available(); e != nil {
		return out, e
	}
	action := "trash"
	if p.Action == "UNINSTALL_APP_BUNDLE" {
		action = "uninstall"
	}
	keep := ""
	if p.Retain != nil {
		keep = p.Retain.Path
	}
	fresh, e := Build(ctx, r, p.FindingID, Options{Target: p.Target.Path, Retain: keep, Action: action, BackupReviewed: p.BackupReviewed, BundleOnly: p.BundleOnly, MaxReadBytes: p.MaxReadBytes}, now)
	if e != nil {
		return out, e
	}
	if p.ScanID != r.ScanID || p.Action != fresh.Action || p.ApprovedRoot != fresh.ApprovedRoot || !sameFingerprint(p.Target, fresh.Target) || !sameRetain(p.Retain, fresh.Retain) {
		return out, errors.New("selection or target fingerprint changed; create a fresh plan")
	}
	if p.Action == "UNINSTALL_APP_BUNDLE" {
		// Collect a fresh visible comm-only process snapshot before any app move.
		data, e := platforms.Run(ctx, "ps", "-axo", "comm=")
		if e != nil {
			return out, errors.New("cannot establish current running state; uninstall blocked")
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), p.Target.Path+string(os.PathSeparator)) {
				return out, errors.New("application is running; save work and close it manually before creating a fresh plan")
			}
		}
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := Validate(p, time.Now().UTC()); e != nil {
		return out, e
	}
	now = time.Now().UTC()
	out = Outcome{PlanID: p.ID, ApprovalHash: p.ApprovalHash, Status: "STARTED", Action: p.Action, Target: p.Target.Path, Started: now, Message: "Native Trash operation started; an interrupted result must be inspected before any retry."}
	if e := before(out); e != nil {
		return Outcome{}, fmt.Errorf("cannot persist start journal; no native action dispatched: %w", e)
	}
	if e := Validate(p, time.Now().UTC()); e != nil {
		out.Status = "NOT_DISPATCHED"
		out.Finished = time.Now().UTC()
		out.Message = e.Error()
		return out, nil
	}
	if e := ctx.Err(); e != nil {
		out.Status = "NOT_DISPATCHED"
		out.Finished = time.Now().UTC()
		out.Message = "Cancelled before native dispatch"
		return out, nil
	}
	destination, e := b.Trash(ctx, p.Target)
	out.Finished = time.Now().UTC()
	out.TrashLocation = destination
	if e != nil {
		out.Status = "UNKNOWN"
		out.Message = "Native operation returned an error; no permanent-deletion fallback or automatic retry. Inspect original path and Trash. " + e.Error()
		return out, nil
	}
	if _, e := os.Lstat(p.Target.Path); !os.IsNotExist(e) {
		out.Status = "UNKNOWN"
		out.Message = "Native call returned but original path is still present or inaccessible; inspect both locations. No retry was attempted."
		return out, nil
	}
	out.Status = "COMPLETED"
	out.Message = "Selected item moved to native OS Trash. Restore manually from Trash to the recorded original path if needed; do not empty Trash."
	if p.Action == "UNINSTALL_APP_BUNDLE" {
		out.AppBundlesTrashed = 1
		out.Message += " Bundle-only uninstall; external app data, integrations and subscriptions were not removed."
	} else {
		out.FilesTrashed = 1
	}
	return out, nil
}

func sameFingerprint(a, b Fingerprint) bool {
	return a.Path == b.Path && a.Device == b.Device && a.Identity == b.Identity && a.Size == b.Size && a.Modified.Equal(b.Modified) && a.SHA256 == b.SHA256 && a.LogicalBytes == b.LogicalBytes && a.Directory == b.Directory
}
func sameRetain(a, b *Fingerprint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sameFingerprint(*a, *b)
}
