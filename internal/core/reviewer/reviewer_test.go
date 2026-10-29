package reviewer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
)

func TestInspectRevalidatesAndRevealNeverExecutes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "; rm -rf ~; =formula.command")
	contents := []byte("#!/bin/sh\ntouch SHOULD_NEVER_BE_CREATED\n")
	if err := os.WriteFile(path, contents, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	device, identity, hard, sparse := safety.Identity(info)
	file := findings.File{Path: path, Size: info.Size(), Modified: info.ModTime(), Device: device, Identity: identity, Hardlink: &hard, Sparse: sparse}
	r := findings.Report{Scope: findings.Scope{Roots: []string{root}}, Results: []findings.Result{{Feature: "junk", Findings: []findings.Finding{{ID: "J-000001", Feature: "junk", Paths: []string{path}, Junk: &findings.Junk{File: file}}}}}}
	i, err := Inspect(r, "J-000001")
	if err != nil || len(i.Items) != 1 || i.Items[0].Status != "CURRENT" {
		t.Fatal(i, err)
	}
	paths, err := Reveal(r, "J-000001")
	if err != nil || len(paths) != 1 || paths[0] != root {
		t.Fatal(paths, err)
	}
	if _, err := os.Stat(filepath.Join(root, "SHOULD_NEVER_BE_CREATED")); !os.IsNotExist(err) {
		t.Fatal("target was executed")
	}
	if err := os.Chtimes(path, time.Now(), info.ModTime().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	i, err = Inspect(r, "J-000001")
	if err != nil || i.Items[0].Status != "CHANGED" {
		t.Fatal(i, err)
	}
	if _, err := Reveal(r, "J-000001"); err == nil {
		t.Fatal("stale item revealed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	i, err = Inspect(r, "J-000001")
	if err != nil || i.Items[0].Status != "MISSING" {
		t.Fatal(i, err)
	}
	if _, err := Find(r, "J-unknown"); err == nil {
		t.Fatal("unknown ID found")
	}
}

func TestInspectRejectsOutsideRootAndExclusions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "excluded.tmp")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	r := findings.Report{Scope: findings.Scope{Roots: []string{root}, Exclusions: []string{path}}, Results: []findings.Result{{Findings: []findings.Finding{{ID: "J-000001", Paths: []string{path, filepath.Join(filepath.Dir(root), "outside")}}}}}}
	i, err := Inspect(r, "J-000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range i.Items {
		if item.Status != "REJECTED" {
			t.Fatal(item)
		}
	}
}
