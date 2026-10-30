# Reports and review state

A scan report records product/schema version, scan ID, UTC timestamp and display
timezone, environment, requested scope, exclusions, feature coverage, warnings,
collection method, elapsed time and actual changes. Missing measurements are null
with a reason. Empty findings are meaningful only alongside completed coverage.

A new interactive session greets the user in informal Bahasa Indonesia, offers an
optional nickname and current issue, then continues to device, feature and scope
selection. Enter or `skip`/`lewati` passes either intro question. Numbered choices
and supported text aliases are accepted, and `ya`/`yes` can confirm a pending
read-only choice. `batal`/`stop` ends onboarding. Intro answers do not supply any
scope, storage consent or plan approval.

The preferred name and issue are not part of the report schema, JSON/CSV exports,
saved scan/review state or a user profile. Reports still distinguish measurements,
sources, limitations and decision blockers. An ongoing agent chat can retain its
conversational context without repeating the greeting on a feature change or resume.
Separate experimental actions still require their exact reviewed plan hash.

Findings use `J-`, `P-`, `A-` and `D-` identifiers. Junk explains category, age and
consequences. Performance records observed metrics and sampling semantics.
Applications record inventory provenance and unknown usage. Duplicates record a
group, SHA-256 evidence, every member and logical redundant bytes; physical recovery
is unknown. Risk, confidence and recommendations are independent judgments.

Use `scan ... --store` for later review. All subsequent commands accept
`--data-dir <private-directory>` when using a custom location:

```sh
agent-doctor report --scan <scan-id> --summary
agent-doctor report --scan <scan-id> --feature duplicates
agent-doctor inspect D-000001 --scan <scan-id>
agent-doctor explain D-000001 --scan <scan-id>
agent-doctor reveal D-000001 --scan <scan-id>
agent-doctor review D-000001 --decision keep --scan <scan-id>
agent-doctor session resume <scan-id>
```

`reveal` prints a containing-folder path for manual use; it never executes the file.
Review decisions (`keep`, `review-later`, `skip`, `mark-reviewed`) affect saved review
state only. `session cancel` marks a saved session cancelled; it does not signal an
unrelated process. A cancelled saved session remains viewable but rejects new review
decisions. Interrupt an active scan with Ctrl+C.

JSON and Markdown export the complete selected inventory. CSV requires a selected
feature, producing one feature-specific table; duplicate rows retain group/member
linkage. Quote escaping and formula neutralization are applied. Exact local paths
are private; use share-safe export before sharing:

```sh
agent-doctor export --scan <scan-id> --format markdown --output report.md
agent-doctor export --scan <scan-id> --feature junk --format csv --output junk.csv
agent-doctor export --scan <scan-id> --format json --share-safe --output share.json
```

Session writes use a per-scan lock. An interrupted write can leave `.lock-<scan-id>`
in the private session folder. Verify that no process is still using that scan
before manually removing its stale lock; never remove an active writer's lock.

Exports do not overwrite an existing file. The JSON schemas in `schemas/` describe
persisted reports/review state. No executable action plan is supported in v1.

Exit codes: `0` success, `1` internal/storage error, `2` partial, `3` unsupported,
`4` permission denied, `64` invalid arguments, `130` interrupted. Shell scripts
should retain useful reports even when a collector returns partial coverage.

`session resume --format json` emits one object containing `report` and `review_state`. Share-safe resume also redacts review notes and review timestamps. Resume supports Markdown or JSON; use `report` for CSV. Interactive terminal Markdown previews at most 20 findings per feature; exports and redirected scan output retain the complete inventory.

## Version 0.2 decision evidence and actions

Scans remain read-only and now include decision-oriented evidence. Experimental
phase2 is a separate opt-in path; see [ACTIONS.md](ACTIONS.md) for supported native
macOS Trash/bundle-only uninstall, exact approval, persistence, recovery and residual
races. Read legacy v1 restrictions above as scan behavior; they do not describe the
new separately approved action boundary. Windows/Linux action execution remains
unsupported. Never use personal reports or real app data as development fixtures.
