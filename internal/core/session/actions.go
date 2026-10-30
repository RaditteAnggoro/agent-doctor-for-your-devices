package session

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

// SaveActionPlan writes a new private, immutable plan selected by the plan command.
func (s *Store) SaveActionPlan(id string, v any) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(true)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lock(r, id)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := r.Lstat(id + ".plan.json"); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("action plan already exists or cannot be inspected")
	}
	return atomicWrite(r, id+".plan.json", v)
}
func (s *Store) LoadActionPlan(id string, v any) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	return readJSON(r, id+".plan.json", v)
}
func (s *Store) LoadActionOutcome(id string, v any) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	return readJSON(r, id+".outcome.json", v)
}
func (s *Store) SaveActionOutcome(id string, v any) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	return atomicWrite(r, id+".outcome.json", v)
}

// ClaimAction syncs a non-retry marker before native dispatch. Interrupted
// attempts require journal inspection; storage corruption still needs recovery.
func (s *Store) ClaimAction(id, hash string) error {
	if err := checkID(id); err != nil {
		return err
	}
	r, err := s.open(false)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := r.OpenFile(".attempt-"+id, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("plan already attempted; inspect the action journal and original/Trash locations before creating a new plan")
	}
	err = json.NewEncoder(f).Encode(map[string]string{"plan_id": id, "approval_hash": hash})
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDirectory(r)
}

// AcquireActionLock serializes actions sharing this store, including retained
// duplicate checks. Never share independent data directories for one cleanup run.
func (s *Store) AcquireActionLock() (func(), error) {
	r, err := s.open(false)
	if err != nil {
		return nil, err
	}
	unlock, err := lock(r, "action-execution")
	if err != nil {
		r.Close()
		return nil, err
	}
	return func() { unlock(); r.Close() }, nil
}

func (s *Store) AcquireScanLock(id string) (func(), error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	r, err := s.open(false)
	if err != nil {
		return nil, err
	}
	unlock, err := lock(r, id)
	if err != nil {
		r.Close()
		return nil, err
	}
	return func() { unlock(); r.Close() }, nil
}
