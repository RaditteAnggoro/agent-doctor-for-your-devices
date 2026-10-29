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
