# Privacy

The CLI makes no network requests, performs no auto-update checks and sends no
telemetry. It does not collect serial numbers, device fingerprints or raw process
arguments. Agent clients are separate software and can have their own data policies
and usage costs. Do not paste a private report into an agent without considering
that client's handling of it.

Filesystem scans read approved metadata. Exact duplicate analysis reads file
contents only to calculate streaming hashes and verify matches. It does not retain
or print those contents. OS metadata collectors read only supported local sources.
Reading can update filesystem access times or hydrate files on unusual filesystems;
cloud paths are conservatively excluded and physical storage savings are unknown.

Interactive onboarding offers an optional preferred nickname and current issue.
The CLI uses those answers for this process only. It does not copy intro text into
report fields, exports, persisted scan/review state or a personal profile, including
when `--store` is selected. Enter, `skip` and `lewati` let users pass either question;
a new CLI process asks afresh. Existing chat context may supply the preferred name
or issue, so an agent should not repeat a known answer.

Names and issues are conversational data, not feature/root selection, saving consent
or approval for an action plan. Terminal and agent clients may retain input,
scrollback or conversation under their own policies; skipping both questions is
available without changing scan capabilities.

A scan prints its result; `--store` explicitly opts into local report/session storage.
Use `--data-dir` to choose a private storage folder. Persisted reports contain exact
paths and may identify apps or processes. Exports write only to the path you select.
Do not save them inside a scanned tree or a public repository. On Unix, the final session directory must have mode 0700 and report/review files
use mode 0600. Windows access follows the parent directory's ACL; Go file modes do
not establish private NTFS ACLs, so choose a user-private directory.

`export --share-safe` replaces data-derived strings for safer sharing. Review the
output yourself: feature counts, byte sizes and timing can still be sensitive.
No redaction can guarantee anonymity. Delete saved report/session files manually
when no longer needed; the CLI has no hidden retention or upload service.

## Version 0.2 decision evidence and actions

Scans remain read-only and now include decision-oriented evidence. Experimental
phase2 is a separate opt-in path; see [ACTIONS.md](ACTIONS.md) for supported native
macOS Trash/bundle-only uninstall, exact approval, persistence, recovery and residual
races. Read legacy v1 restrictions above as scan behavior; they do not describe the
new separately approved action boundary. Windows/Linux action execution remains
unsupported. Never use personal reports or real app data as development fixtures.
