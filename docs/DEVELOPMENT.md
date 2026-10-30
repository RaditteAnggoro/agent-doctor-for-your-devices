# Development

Use Go 1.26 or newer and Git. There are no third-party Go modules. Build and test
without an AI client:

```sh
go fmt ./...
go vet ./...
go test -race ./...
go build -trimpath -buildvcs=false -o bin/agent-doctor ./cmd/agent-doctor
```

The same Go commands work in PowerShell; use `bin/agent-doctor.exe` as its output.
`make check` is a Unix convenience, not a Windows prerequisite. Tests use temporary
synthetic data. No test requires root, user data, package uninstall or network access.

The repository includes the owner's development skills under `.agents/skills/`.
Follow [AGENTS.md](../AGENTS.md); choose only the applicable workflow. The product
skill at `.agents/skills/agent-doctor-for-your-devices/` is a separate user-facing
workflow. Its metadata follows the [Agent Skills specification](https://agentskills.io/specification).

CI runs format, vet and tests on macOS, Windows and Linux, then cross-builds six
OS/architecture targets. Those jobs prove only the revision they actually execute.
They do not prove ChromeOS host access or cover every OS version.

The manual release workflow first reruns checks, then produces versioned archives
and SHA-256 checksums as workflow artifacts. It does not publish a tag or release.
After reviewing passing jobs, maintainers may create a release and attach those
artifacts. Include MIT and toolchain notices. Binaries are unsigned unless a future
release explicitly documents signature verification.

## Version 0.2 decision evidence and actions

Scans remain read-only and now include decision-oriented evidence. Experimental
phase2 is a separate opt-in path; see [ACTIONS.md](ACTIONS.md) for supported native
macOS Trash/bundle-only uninstall, exact approval, persistence, recovery and residual
races. Read legacy v1 restrictions above as scan behavior; they do not describe the
new separately approved action boundary. Windows/Linux action execution remains
unsupported. Never use personal reports or real app data as development fixtures.

Native macOS integration is opt-in and uses only generated synthetic artifacts;
each native Trash move is immediately restored. Run it separately from normal CI:

```sh
AGENT_DOCTOR_NATIVE_TRASH_TEST=1 go test -run '^TestNativeTrashAndRestoreSynthetic$' -v ./internal/core/actions
```
