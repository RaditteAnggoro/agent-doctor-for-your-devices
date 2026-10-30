// Package session persists explicitly requested local reports and review notes.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

const maxStoredBytes = 128 << 20

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)

type Store struct{ dir string }
type Decision struct {
	Decision  string    `json:"decision"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ReviewState struct {
	SchemaVersion string              `json:"schema_version"`
	ScanID        string              `json:"scan_id"`
	Status        string              `json:"status"`
	Decisions     map[string]Decision `json:"decisions"`
}

func NewStore(dir string) *Store { return &Store{dir: dir} }
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "agent-doctor", "sessions"), nil
}
func checkID(id string) error {
	if !validID.MatchString(id) {
		return errors.New("invalid scan or finding ID")
	}
	return nil
}

// open walks directory handles, rejecting symlinks/reparse-point aliases and
// binding each child to the metadata just checked. Writes remain inside Root.
func (s *Store) open(create bool) (*os.Root, error) {
	abs, err := filepath.Abs(s.dir)
	if err != nil {
		return nil, err
	}
	if abs == filepath.VolumeName(abs)+string(filepath.Separator) {
		return nil, errors.New("session directory cannot be a volume root")
	}
	volume := filepath.VolumeName(abs)
	r, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(abs, volume+string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		info, err := r.Lstat(part)
		if errors.Is(err, fs.ErrNotExist) && create {
			if err = r.Mkdir(part, 0700); err == nil {
				if err = syncDirectory(r); err == nil {
					info, err = r.Lstat(part)
				}
			}
		}
		if err != nil {
			r.Close()
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
			r.Close()
			return nil, errors.New("session directory contains a link or non-directory")
		}
		next, err := r.OpenRoot(part)
		r.Close()
		if err != nil {
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			return nil, errors.New("session directory changed while opening")
		}
		if i == len(parts)-1 && runtime.GOOS != "windows" && opened.Mode().Perm()&0077 != 0 {
			next.Close()
			return nil, errors.New("session directory must be private (mode 0700)")
		}
		r = next
	}
	return r, nil
}

func (s *Store) Save(report findings.Report) error {
	if err := checkID(report.ScanID); err != nil {
		return err
	}
	r, err := s.open(true)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lock(r, report.ScanID)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := r.Lstat(report.ScanID + ".json"); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("scan ID already exists")
	}
	return atomicWrite(r, report.ScanID+".json", report)
}

func (s *Store) Load(id string) (findings.Report, error) {
	var result findings.Report
	if err := checkID(id); err != nil {
		return result, err
	}
	r, err := s.open(false)
	if err != nil {
		return result, err
	}
	defer r.Close()
	if err := readJSON(r, id+".json", &result); err != nil {
		return result, err
	}
	if result.ScanID != id || result.SchemaVersion != "1.0" {
		return findings.Report{}, errors.New("stored scan ID or schema version is invalid")
	}
	return result, nil
}

func (s *Store) List() ([]string, error) {
	r, err := s.open(false)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	dir, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".review.json") && entry.Type().IsRegular() {
			id := strings.TrimSuffix(name, ".json")
			if checkID(id) == nil {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *Store) State(id string) (ReviewState, error) {
	state := ReviewState{SchemaVersion: "1.0", ScanID: id, Status: "ACTIVE", Decisions: map[string]Decision{}}
	if _, err := s.Load(id); err != nil {
		return state, err
	}
	r, err := s.open(false)
	if err != nil {
		return state, err
	}
	defer r.Close()
	err = readJSON(r, id+".review.json", &state)
	if errors.Is(err, fs.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return ReviewState{}, err
	}
	if state.ScanID != id || state.SchemaVersion != "1.0" || (state.Status != "ACTIVE" && state.Status != "CANCELLED") {
		return ReviewState{}, errors.New("invalid review state")
	}
	if state.Decisions == nil {
		state.Decisions = map[string]Decision{}
	}
	for id, decision := range state.Decisions {
		if checkID(id) != nil || !validDecision(decision.Decision) || len(decision.Note) > 8192 {
			return ReviewState{}, errors.New("invalid stored review decision")
		}
	}
	return state, nil
}

func (s *Store) Review(scanID, findingID, decision, note string) error {
	if err := checkID(findingID); err != nil {
		return err
	}
	if !validDecision(decision) {
		return errors.New("decision must be keep, review-later, skip, or mark-reviewed")
	}
	if len(note) > 8192 {
		return errors.New("review note exceeds 8192 bytes")
	}
	if err := checkID(scanID); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lock(r, scanID)
	if err != nil {
		return err
	}
	defer unlock()
	report, err := s.Load(scanID)
	if err != nil {
		return err
	}
	found := false
	for _, r := range report.Results {
		for _, f := range r.Findings {
			if f.ID == findingID {
				found = true
			}
		}
	}
	if !found {
		return errors.New("finding is not in this scan")
	}
	state, err := s.State(scanID)
	if err != nil {
		return err
	}
	if state.Status == "CANCELLED" {
		return errors.New("session is cancelled; findings remain available for inspection and export")
	}
	state.Decisions[findingID] = Decision{Decision: decision, Note: note, UpdatedAt: time.Now().UTC()}
	return atomicWrite(r, scanID+".review.json", state)
}

func validDecision(s string) bool {
	return s == "keep" || s == "review-later" || s == "skip" || s == "mark-reviewed"
}

func (s *Store) Cancel(id string) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lock(r, id)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := s.State(id)
	if err != nil {
		return err
	}
	state.Status = "CANCELLED"
	return atomicWrite(r, id+".review.json", state)
}

func lock(r *os.Root, id string) (func(), error) {
	name := ".lock-" + id
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("session is busy or has a stale lock (check other running instances): %w", err)
	}
	if err := f.Close(); err != nil {
		r.Remove(name)
		return nil, err
	}
	return func() { _ = r.Remove(name) }, nil
}

func readJSON(r *os.Root, name string, v any) error {
	info, err := r.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxStoredBytes {
		return errors.New("session must be a bounded regular file")
	}
	f, err := r.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return errors.New("session file changed while opening")
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0077 != 0 {
		return errors.New("session file must be private (mode 0600)")
	}
	d := json.NewDecoder(io.LimitReader(f, maxStoredBytes+1))
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("session has trailing data")
	}
	return nil
}

func atomicWrite(r *os.Root, name string, v any) error {
	if info, err := r.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing to replace linked or special session file")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmp := ".tmp-" + hex.EncodeToString(random[:])
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := r.Rename(tmp, name); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return syncDirectory(r)
}

// Sync both file content and directory entry before actions may be dispatched.
// Windows scan/report storage uses its normal filesystem semantics; action
// execution there remains unsupported rather than claiming this Unix guarantee.
func syncDirectory(r *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
