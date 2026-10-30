# Experimental phase 2: Trash and bundle-only uninstall

Scan results provide evidence, not action approval. A user explicitly chooses one
finding and exact path, reviews backup/retention needs, prepares an immutable plan,
then separately approves its SHA-256 hash. `plan` writes private plan metadata but
never changes the selected target. No permanent deletion or privilege escalation
fallback exists. Scans remain read-only regardless of action availability.

## Capability

| Operation | Current execution scope |
| --- | --- |
| Trash one selected regular file from junk/exact duplicates | Native macOS, current-user-owned item, stable file ID and secure parent |
| Bundle-only app uninstall | Eligible native macOS user-owned .app directly in /Applications or ~/Applications |
| System/helper/security/VPN/integrated/related-product apps | Blocked; review official vendor uninstall method manually |
| Windows/Linux/WSL/Crostini/remote execution | Unsupported for actions; read-only feature collectors retain their existing scope |

macOS uses Foundation's
[`trashItemAtURL:resultingItemURL:error:`](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))
with a file-reference URL and expected filesystem identity. The target is passed as
an argument, never concatenated into executable script. This method moves an item
to Trash; failure has no permanent-delete fallback. The actual returned Trash path
is recorded. Linux's path-only native dispatch is deliberately unavailable until
an identity-preserving backend is verified.

An app action is a **bundle-only uninstall**. Review the
[official Apple process](https://support.apple.com/102610) and the vendor instructions
first. If a dedicated uninstaller or an in-app uninstall process is required, use
that official flow manually. Do not select the uninstaller/helper as an independent
removal target. Moving a bundle retains external documents, preferences, caches,
shared services and subscriptions; it does not claim a complete product removal.

## File workflow

First scan and save a report in private local storage:

```sh
agent-doctor scan --feature junk --scope /path/to/approved-folder --store
agent-doctor report --scan SCAN_ID
agent-doctor plan --enable-actions --scan SCAN_ID --finding J-000001 \
  --action trash --target '/path/to/approved-folder/selected-file.tmp' --backup-reviewed
```

Only the path recorded in that exact finding can be selected. For a duplicate,
also pass `--keep '/exact/retained/member'`; both files must still match the recorded
SHA-256 and identities. Protected/cloud/linked/hardlinked/managed-upload/backup and
working-repository targets are rejected. A plan hashes the selected file again.
The default read budget is1GiB per selected file or bundle; deliberately adjust
`--max-bytes` for a larger target. A bundle measurement includes bounded complete
regular-file contents and metadata, without following symlinks.

Review the complete plan: source scan/finding, exact selected and retained paths,
logical size, consequences, expiry and recovery route. The displayed hash approves
that plan's complete contents. Then, only after deciding to proceed:

```sh
agent-doctor apply --enable-actions --plan PLAN_ID --approve EXACT_PLAN_SHA256
agent-doctor action-status --plan PLAN_ID
```

Use the same `--data-dir` on scan, plan, apply and status when overriding the default.
`--share-safe` is not supported by plans/journals because they require exact private
targets; share a redacted scan report instead. Never post plans or journals publicly.

## Application workflow

Scan applications with the enriched evidence, then review the selected app and its
vendor uninstall instructions. Save open work and close it manually. A running or
unknown-running app, missing role/system metadata, related-product hint, detected
integration, helper or root-owned bundle cannot use this action.

```sh
agent-doctor scan --feature applications --store
agent-doctor plan --enable-actions --scan SCAN_ID --finding A-000001 \
  --action uninstall --target '/Applications/Selected App.app' \
  --backup-reviewed --bundle-only
```

`--bundle-only` acknowledges the limited removal scope and vendor review. It does
not override a blocked app. Apply still requires the exact plan hash separately.
The process list is checked again immediately before dispatch; no app is killed.

## Journals, interruption and recovery

Plans expire15minutes after creation; source scans must be at most24hours old.
Apply revalidates current environment, scope, ownership, file ID, content, retained
copy and app state. File and directory syncs precede native dispatch. One attempted
plan cannot automatically run again. Completed repeats return its saved outcome.
STARTED or UNKNOWN means inspect the original path and OS Trash; do not blindly retry.
Create a fresh scan and plan only after resolving what actually happened.

The action store serializes applies and holds the source scan's lock through final
dispatch. A concurrent `session cancel` returns busy; Ctrl+C interrupts the actual
apply process. After native dispatch, interruption may leave an UNKNOWN outcome.
Crash-created locks require checking that no writer is active before manual recovery.

Restore the exact item manually from the recorded Trash location to its original
path, and keep Trash intact until satisfied. No space recovery is promised while
Trash retains data. No automatic restore or Empty Trash operation is implemented.

External processes can change files or retained copies after validation, visible
process snapshots can miss helpers, and separate data directories do not share
locks. Use one action store per device/session and stop when evidence is uncertain.
These are residual limits, not a transactional snapshot or a security-audit claim.
