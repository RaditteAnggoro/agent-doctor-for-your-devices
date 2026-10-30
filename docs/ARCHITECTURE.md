# Architecture

The agent skill is an instruction layer. The Go CLI performs deterministic local
read-only collection and safety checks without network access. Opt-in actions use a separate exact-target plan and native Trash boundary.

```text
agent conversation / terminal
        |
  internal/cli  -> discovery + capability checks
        |
  approved scope -> safety -> bounded scanner inventory
        |                         |
        +-> junk / duplicates <---+
        +-> performance / applications -> fixed native metadata probes
        |
  structured feature results -> reports -> stdout or explicit export
        |
  optional session storage -> inspector / reviewer -> review decisions
  explicit action selection -> immutable plan -> separate hash approval -> native Trash + journal
```

`internal/core/findings` contains the versioned shared structures and feature-specific
evidence. `core/safety` rejects protected scopes, links and root escapes;
`core/scanner` walks via rooted filesystem handles and enforces limits. Duplicate
analysis streams candidate contents rather than loading entire files into memory.

`internal/platforms` bounds native metadata probes, uses trusted system executable
locations and fixed argument arrays, and exposes available disk facts. Feature
collectors keep support, coverage, findings, warnings, errors, observations and method
separate. One unsupported collector need not discard another collector's evidence.

`core/reports` produces escaped Markdown, JSON and feature-specific CSV; `core/session`
persists opt-in reports/review state. `core/reviewer` checks a finding and supplies
metadata or containing-folder paths. Review decisions do not mutate source items.

Policies under `policies/` document conservative reference rules; they are not a
user-editable bypass or dynamically executable action configuration. Runtime safety
checks in Go are authoritative. Schemas document the data boundary; an action-plan
schema cannot enable cleanup. The original build specification in `.agents/artifacts/`
is a requirements record, not evidence that every optional feature is implemented.

## Version 0.2 decision evidence and actions

Scans remain read-only and now include decision-oriented evidence. Experimental
phase2 is a separate opt-in path; see [ACTIONS.md](ACTIONS.md) for supported native
macOS Trash/bundle-only uninstall, exact approval, persistence, recovery and residual
races. Read legacy v1 restrictions above as scan behavior; they do not describe the
new separately approved action boundary. Windows/Linux action execution remains
unsupported. Never use personal reports or real app data as development fixtures.
