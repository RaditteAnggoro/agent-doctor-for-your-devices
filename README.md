# Agent Doctor For Your Devices

**Scan first. Understand everything. Decide yourself.**

A local Go CLI plus an agent skill for investigating device maintenance. It finds
explainable junk candidates, samples performance, inventories applications and groups
exact duplicates. Findings include evidence, uncertainty and manual inspection steps.

**v1 is read-only toward device data. There is no automated deletion, uninstall or
process termination.** Reports and review state are written only when you choose
local storage or an export destination. You can keep every item and finish with a
useful report. No telemetry, account or network connection is required by the CLI.

## Build from source

Install Go 1.26 or newer from [go.dev](https://go.dev/dl/) and Git. No third-party
Go modules, Python, Node or paid API are needed to run the CLI.

macOS / Linux / Crostini terminal:

```sh
git clone https://github.com/RaditteAnggoro/agent-doctor-for-your-devices.git
cd agent-doctor-for-your-devices
go build -trimpath -buildvcs=false -o bin/agent-doctor ./cmd/agent-doctor
./bin/agent-doctor --help
./bin/agent-doctor doctor
```

Windows PowerShell:

```powershell
git clone https://github.com/RaditteAnggoro/agent-doctor-for-your-devices.git
Set-Location agent-doctor-for-your-devices
go build -trimpath -buildvcs=false -o bin/agent-doctor.exe ./cmd/agent-doctor
.\bin\agent-doctor.exe --help
.\bin\agent-doctor.exe doctor
```

The commands below assume `bin` is on your PATH; otherwise use `./bin/agent-doctor`
or `.\bin\agent-doctor.exe`. No published package or prebuilt release is assumed.
The manual release workflow prepares archives only after its test matrix passes.

## Start a review

```sh
agent-doctor scan --interactive
agent-doctor scan --feature duplicates --scope ./my-test-folder --store
agent-doctor scan --all --read-only --scope ./my-test-folder --exclude ./my-test-folder/private --store
agent-doctor scan --feature performance
agent-doctor scan --feature applications
```

Interactive mode asks for OS first and confirms the detected execution environment.
Noninteractive filesystem scans require explicit roots. `--all` never grants whole-disk
permission. Inspect `doctor` output first; WSL, Crostini, remote and container scans
require `--confirm-environment` to acknowledge their restricted scope. A Linux binary
inside WSL does not measure Windows host health.

Without `--store`, the report goes to stdout and no session is saved. Add `--store`
for later review, optionally with `--data-dir <private-folder>`. Saved reports contain
exact paths. Resource defaults are 30 seconds, 10,000 entries, 12 directory levels
and 1 GiB of content reads; configure `--timeout`, `--max-files`, `--max-depth` and
`--max-bytes` for a deliberate deeper scan. Exclusions, protected paths and link/mount
boundaries still apply. Reading files may update access times.

Use the scan ID printed by a saved scan:

```sh
agent-doctor report --scan <scan-id> --summary
agent-doctor inspect D-000001 --scan <scan-id>
agent-doctor explain D-000001 --scan <scan-id>
agent-doctor reveal D-000001 --scan <scan-id>
agent-doctor review D-000001 --scan <scan-id> --decision keep
agent-doctor session list
agent-doctor session resume <scan-id>
agent-doctor export --scan <scan-id> --format markdown --output review.md
agent-doctor export --scan <scan-id> --feature duplicates --format csv --output duplicates.csv
agent-doctor export --scan <scan-id> --format json --share-safe --output shared.json
```

`reveal` prints a containing-folder path for manual navigation and never launches a
file. Review decisions affect session state only. Exports refuse existing destinations.
CSV selects one feature so its fields remain meaningful. `--share-safe` replaces
data-derived strings; inspect remaining counts and sizes before sharing. See
[reporting](docs/REPORTING.md) for formats, review state and exit codes. Synthetic
output examples are in [`examples/`](examples/); their measurements are not device
findings.

## What is implemented

| Feature | Evidence | Deliberate limits |
| --- | --- | --- |
| Junk | File metadata and old temporary/log/installer files and recognized cache paths | Age/size never proves disuse; sensitive/cloud/managed paths excluded |
| Performance | Two cumulative CPU samples, visible RSS/working set, available system capacity, user startup references | Short observations; metrics vary by OS; no tuning or stopping |
| Applications | Native app/package metadata with source/version where available | Last-use and dependency state usually unknown; no uninstall |
| Duplicates | Size shortlist, streaming SHA-256, full-content verification and per-member metadata | Exact matches only; no similar-photo matcher or promised physical recovery |

| Platform | Implemented scope | Verification limit |
| --- | --- | --- |
| macOS | Approved filesystem roots, `/Applications`, `/System/Applications` and user app metadata, process samples/capacity, user LaunchAgents filenames | Local macOS checks and CI must be read for the tested revision; all versions/architectures are not certified |
| Windows 10/11 | Approved local roots, registry uninstall metadata, process samples and available memory | Native runtime verification depends on Windows CI; Store/portable apps and startup inventory omitted |
| Linux | Approved roots, available dpkg/rpm/pacman/Flatpak metadata, process samples, `/proc` memory, user startup filenames | Runtime verification depends on Linux CI; distro/package-manager variations remain partial |
| ChromeOS / Crostini | Accessible Linux container and explicitly shared folders only | No ChromeOS hardware verification; host/Android apps, startup and performance unsupported |

Performance and application inventories are **PARTIAL** even when useful: coverage
is intentionally narrower than a full OS inventory. Unknown metrics are null with
reasons. Missing/denied collectors are never reported as a clean bill of health.
[Platform details and manual test plan](docs/PLATFORM_SUPPORT.md).

## Use with an agent

The canonical skill is
[`.agents/skills/agent-doctor-for-your-devices/SKILL.md`](.agents/skills/agent-doctor-for-your-devices/SKILL.md).
Keep its `references/` directory with it. This follows the
[Agent Skills format](https://agentskills.io/specification). Project skill discovery
varies by client/version; read that file explicitly if automatic discovery is absent.
For Codex, a user-local copy can be placed under `~/.codex/skills/`; for Claude Code,
copy the same canonical folder to `.claude/skills/` when supported by the installed
version. Do not maintain divergent copies.

Example prompt: “Use agent-doctor-for-your-devices. I'm on macOS; review duplicates
in this folder, keep everything and explain the results.” The skill confirms the OS,
execution environment and scope before collecting. It handles questions, ambiguity,
postpone and cancel without treating them as permission. Agent clients may have their
own costs and privacy policies. The CLI works independently of any agent client.

## Privacy, limitations and contributing

The CLI makes no network calls and collects no serial numbers or raw process arguments.
Local reports contain private metadata. Do not commit them or attach them to public
issues. Read [privacy](docs/PRIVACY.md), [threat model](docs/THREAT_MODEL.md),
[security reporting](SECURITY.md) and [contributing](CONTRIBUTING.md).

There is no antivirus, registry cleaner, background optimizer or security-audit claim.
Filesystem races, false positives, permissions and short observation windows limit
conclusions. Similar-image detection and automated cleanup are outside v1.

Run `go vet ./...`, `go test -race ./...` and `go build ./cmd/agent-doctor` for local
checks. CI additionally checks formatting and cross-compiles planned architectures.
See [development](docs/DEVELOPMENT.md) and [architecture](docs/ARCHITECTURE.md).

## Inspiration & credits

Created by **RA** as an independent original project. Feature ideas were
inspired by [CleanMyMac](https://macpaw.com/cleanmymac), terminal maintenance workflows
in [Mole](https://github.com/tw93/Mole), duplicate analysis in
[Czkawka](https://github.com/qarmin/czkawka), application review in
[Pearcleaner](https://github.com/hghpublic/alienator88-Pearcleaner), and categorization
in [mac-cleanup-py](https://github.com/mac-cleanup/mac-cleanup-py). There is no affiliation
or endorsement and no upstream implementation code is incorporated.

Original code: [MIT](LICENSE), copyright 2026 RA. Upstream licenses differ;
see [inspiration](docs/INSPIRATION.md), [notices](THIRD_PARTY_NOTICES.md) and [NOTICE.md](NOTICE.md).
