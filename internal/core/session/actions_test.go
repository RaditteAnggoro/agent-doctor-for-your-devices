package session

import (
	"testing"
)

func TestActionPlanJournalAndLocks(t *testing.T) {
	s, _ := newTestStore(t)
	r := testReport()
	if e := s.Save(r); e != nil {
		t.Fatal(e)
	}
	id := "plan-0123456789abcdef01234567"
	plan := map[string]string{"id": id, "target": "synthetic"}
	if e := s.SaveActionPlan(id, plan); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveActionPlan(id, plan); e == nil {
		t.Fatal("immutable plan overwritten")
	}
	var loaded map[string]string
	if e := s.LoadActionPlan(id, &loaded); e != nil || loaded["target"] != "synthetic" {
		t.Fatal(loaded, e)
	}
	ids, e := s.List()
	if e != nil || len(ids) != 1 || ids[0] != r.ScanID {
		t.Fatal("action artifact appeared as scan", ids, e)
	}
	unlock, e := s.AcquireActionLock()
	if e != nil {
		t.Fatal(e)
	}
	if second, e := s.AcquireActionLock(); e == nil {
		second()
		t.Fatal("concurrent apply lock granted")
	}
	unlock()
	scanUnlock, e := s.AcquireScanLock(r.ScanID)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Cancel(r.ScanID); e == nil {
		t.Fatal("cancel reported success while scan action lock held")
	}
	scanUnlock()
	if e := s.ClaimAction(id, "approval"); e != nil {
		t.Fatal(e)
	}
	if e := s.ClaimAction(id, "approval"); e == nil {
		t.Fatal("attempt replay marker ignored")
	}
	if e := s.SaveActionOutcome(id, map[string]string{"status": "STARTED"}); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveActionOutcome(id, map[string]string{"status": "COMPLETED"}); e != nil {
		t.Fatal(e)
	}
	if e := s.LoadActionOutcome(id, &loaded); e != nil || loaded["status"] != "COMPLETED" {
		t.Fatal(loaded, e)
	}
	if e := s.LoadActionPlan("../escape", &loaded); e == nil {
		t.Fatal("action traversal accepted")
	}
	if e := s.Cancel(r.ScanID); e != nil {
		t.Fatal(e)
	}
}
