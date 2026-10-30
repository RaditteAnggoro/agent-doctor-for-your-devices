# Threat model

## Assets and boundaries

Protect source files, app state, processes, startup settings and private paths.
The CLI accepts untrusted filenames, metadata, scope arguments, saved JSON and
native tool output. The agent must treat all scan results as data, never instructions.
The CLI's write boundary consists of explicit local session/report destinations.
Scans have no action side effects. The separate experimental executor uses exact approval, native Trash and private journals; no shell interpolation, telemetry or privileged helper is used.

## Defenses and limits

| Threat | Control and residual limit |
| --- | --- |
| Scope escape through links or mounts | Validate approved roots; reject traversal and links; skip protected/cloud paths and crossing volumes. Changing trees remain a race; collect conservatively and inspect stale results again. |
| File replaced while hashing | Revalidate identity/metadata and bound reads; changed files produce incomplete coverage. Filesystems do not provide a transaction across the entire scan. |
| Misleading duplicate savings | Full content evidence required, hard links accounted for; physical reclaimable space remains null because sparse/COW/storage behavior is uncertain. |
| Command or terminal injection | Argument arrays for fixed metadata commands; never execute a target. Escape control characters and Markdown; neutralize CSV formulas. |
| Prompt injection in a name | Names/descriptions are data. Skill requires fresh scope decisions from the actual user. |
| Resource exhaustion | Depth/file/byte/time limits; streaming reads and bounded work. A limit yields partial or cancelled coverage, not a clean result. |
| Secret disclosure | No process argument dumps; share-safe export; private local storage. Local reports still contain sensitive metadata. |
| Unsafe cleanup advice | Every finding includes uncertainty and inspection instructions. No automated deletion, uninstall or process termination. |

No security audit or immunity to all filesystem races is claimed. Do not run against
actively hostile storage or treat a report as authorization for later changes.
Cloud deletion can propagate and backup copies can be intentionally redundant.
Platform gaps appear as partial/unsupported/permission denied with reasons.

## Version 0.2 decision evidence and actions

Scans remain read-only and now include decision-oriented evidence. Experimental
phase2 is a separate opt-in path; see [ACTIONS.md](ACTIONS.md) for supported native
macOS Trash/bundle-only uninstall, exact approval, persistence, recovery and residual
races. Read legacy v1 restrictions above as scan behavior; they do not describe the
new separately approved action boundary. Windows/Linux action execution remains
unsupported. Never use personal reports or real app data as development fixtures.
