package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/actions"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/discovery"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/session"
)

type actionFlags struct {
	Enabled, BackupReviewed, BundleOnly                               bool
	ScanID, FindingID, Action, Target, Keep, PlanID, Approval, Format string
	MaxBytes                                                          int64
	Timeout                                                           time.Duration
}

func runAction(ctx context.Context, command string, st *session.Store, o actionFlags, out, stderr io.Writer) int {
	if command == "action-status" {
		if o.PlanID == "" {
			return errCode(stderr, 64, errors.New("--plan is required"))
		}
		var result actions.Outcome
		if err := st.LoadActionOutcome(o.PlanID, &result); err != nil {
			return errCode(stderr, 1, err)
		}
		if err := jsonOut(out, result); err != nil {
			return errCode(stderr, 1, err)
		}
		return 0
	}
	if !o.Enabled {
		return errCode(stderr, 64, errors.New("experimental actions require --enable-actions; scans remain read-only"))
	}
	current := discovery.Detect()
	if current.Type != "native" || current.Remote {
		return errCode(stderr, 64, errors.New("actions require current native local execution; SSH/subsystem/container execution is unavailable"))
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if command == "plan" {
		if o.ScanID == "" || o.FindingID == "" {
			return errCode(stderr, 64, errors.New("plan requires --scan and --finding"))
		}
		r, err := st.Load(o.ScanID)
		if err != nil {
			return errCode(stderr, 1, err)
		}
		state, err := st.State(o.ScanID)
		if err != nil {
			return errCode(stderr, 1, err)
		}
		if state.Status == "CANCELLED" {
			return errCode(stderr, 64, errors.New("cancelled review session cannot create action plans"))
		}
		p, err := actions.Build(ctx, r, o.FindingID, actions.Options{Target: o.Target, Retain: o.Keep, Action: o.Action, BackupReviewed: o.BackupReviewed, BundleOnly: o.BundleOnly, MaxReadBytes: o.MaxBytes}, time.Now().UTC())
		if err != nil {
			return errCode(stderr, 64, err)
		}
		if err := actions.Native().Available(); err != nil {
			return errCode(stderr, 3, err)
		}
		if err := st.SaveActionPlan(p.ID, p); err != nil {
			return errCode(stderr, 1, err)
		}
		if o.Format == "json" {
			if err := jsonOut(out, p); err != nil {
				return errCode(stderr, 1, err)
			}
		} else {
			fmt.Fprintf(out, "Experimental action plan %s\nAction: %s\nExact target: %s\nSource finding: %s / %s\nLogical bytes: %d (physical recovery unknown)\nExpires: %s\n", p.ID, p.Action, terminal(p.Target.Path), p.ScanID, p.FindingID, p.Target.LogicalBytes, p.Expires.Format(time.RFC3339))
			if p.Retain != nil {
				fmt.Fprintln(out, "Retain:", terminal(p.Retain.Path))
			}
			for _, c := range p.Consequences {
				fmt.Fprintln(out, "-", terminal(c))
			}
			fmt.Fprintln(out, "Recovery:", terminal(p.Recovery))
			fmt.Fprintln(out, "No target changed. Review the entire plan, then explicitly approve its hash using:")
			fmt.Fprintf(out, "agent-doctor apply --enable-actions --plan %s --approve %s\n", p.ID, p.ApprovalHash)
			fmt.Fprintln(out, "Use the same --data-dir as this plan when overriding the default storage.")
		}
		return 0
	}
	if command != "apply" {
		return errCode(stderr, 64, errors.New("unknown action command"))
	}
	if o.PlanID == "" || o.Approval == "" {
		return errCode(stderr, 64, errors.New("apply requires the reviewed --plan ID and its exact --approve SHA-256 hash"))
	}
	var p actions.Plan
	if err := st.LoadActionPlan(o.PlanID, &p); err != nil {
		return errCode(stderr, 1, err)
	}
	h, err := actions.Hash(p)
	if err != nil || subtle.ConstantTimeCompare([]byte(h), []byte(o.Approval)) != 1 || h != p.ApprovalHash {
		return errCode(stderr, 64, errors.New("approval or saved plan hash mismatch"))
	}
	unlock, err := st.AcquireActionLock()
	if err != nil {
		return errCode(stderr, 1, err)
	}
	defer unlock()
	var prior actions.Outcome
	if err := st.LoadActionOutcome(p.ID, &prior); err == nil {
		if prior.PlanID != p.ID || prior.ApprovalHash != p.ApprovalHash {
			return errCode(stderr, 1, errors.New("action journal does not match this plan"))
		}
		if err := jsonOut(out, prior); err != nil {
			return errCode(stderr, 1, err)
		}
		if prior.Status == "COMPLETED" {
			fmt.Fprintln(stderr, "Previously recorded completed outcome; no new native action dispatched.")
			return 0
		}
		return errCode(stderr, 2, errors.New("prior attempt is incomplete or uncertain; no automatic retry"))
	} else if !os.IsNotExist(err) {
		return errCode(stderr, 1, err)
	}
	scanUnlock, err := st.AcquireScanLock(p.ScanID)
	if err != nil {
		return errCode(stderr, 1, err)
	}
	defer scanUnlock()
	source, err := st.Load(p.ScanID)
	if err != nil {
		return errCode(stderr, 1, err)
	}
	state, err := st.State(p.ScanID)
	if err != nil {
		return errCode(stderr, 1, err)
	}
	if state.Status == "CANCELLED" {
		return errCode(stderr, 64, errors.New("review session cancelled; action rejected"))
	}
	result, err := actions.Execute(ctx, p, source, o.Approval, actions.Native(), func(start actions.Outcome) error {
		if err := st.ClaimAction(p.ID, p.ApprovalHash); err != nil {
			return err
		}
		return st.SaveActionOutcome(p.ID, start)
	})
	if err != nil {
		return errCode(stderr, 64, err)
	}
	if err := st.SaveActionOutcome(p.ID, result); err != nil {
		return errCode(stderr, 1, fmt.Errorf("native operation may have occurred but final journal could not be saved; inspect original and Trash, no retry: %w", err))
	}
	if err := jsonOut(out, result); err != nil {
		return errCode(stderr, 1, err)
	}
	if result.Status != "COMPLETED" {
		return 2
	}
	return 0
}
