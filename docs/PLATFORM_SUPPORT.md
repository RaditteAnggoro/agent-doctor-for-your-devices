# Platform support and verification

Support describes collector capability. Coverage describes a particular scan.
PARTIAL, UNSUPPORTED, PERMISSION_DENIED, NOT_TESTED and SKIPPED communicate real
limits; `COMPLETED` describes finished collection within the chosen scope only.
No report certifies an entire device as healthy.

| Environment | Filesystem analysis | Applications | Performance | Verification |
| --- | --- | --- | --- | --- |
| macOS Intel / Apple Silicon | Approved readable roots; links/protected/cloud/nested mounts skipped | `/Applications`, `/System/Applications` and `~/Applications` metadata; version when readable | Visible process CPU/RSS; total memory; current-filesystem capacity; user LaunchAgents filenames | Local synthetic tests on the development Mac; matrix CI should be checked separately; all OS versions unverified |
| Native Windows 10/11 | Approved local roots, conservative link/reparse handling | Standard HKCU/HKLM uninstall metadata; Store/portable apps omitted | Visible process CPU/working set and available OS memory; startup collection absent | CI configured; native behavior is unverified until its job actually passes |
| Native Linux | Approved local roots | Available dpkg-query, rpm, pacman, Flatpak; Snap/AppImage/manual installs omitted | Visible process CPU/RSS, `/proc/meminfo`, current-filesystem capacity, user autostart/systemd filenames | CI configured; distribution variations require local verification |
| WSL | Linux scope only; no automatic `/mnt/c` traversal | Linux packages only | Accessible Linux namespace only | Host Windows is a different target |
| Crostini | Linux container and explicitly shared accessible roots | Container packages only | Container-visible metrics; some values may reflect host limits incorrectly | No ChromeOS hardware test; manual test below required |
| Docker / SSH / remote | Reachable environment only | Available local metadata | Reachable namespace; remote environment explicitly acknowledged | Does not establish physical host coverage |

Application usage dates, dependencies, related-service state, executable paths,
pressure and some capacity metrics remain unknown where not reliably collected.
Startup entries are presence-only filenames, not enablement or impact analysis.
Performance reports include at most 25 visible processes by resident/working-set
memory and at most 100 user startup references. Package metadata is capped.

Filesystem physical reclamation is unknown: hard links, sparse files, clones and
copy-on-write filesystems differ. Cloud names are conservatively excluded, but a
custom sync root may not be recognizable. Use local folders and explicit exclusions.
No permission bypass or root/admin scan is required.

## ChromeOS / Crostini manual test plan

1. Use a Chromebook with Linux enabled and record ChromeOS/Crostini versions without device IDs.
2. Share a disposable synthetic folder with Linux containing exact duplicates, a different same-size file and a protected subfolder.
3. Build the Linux binary inside Crostini or use a verified Linux archive. Run `doctor`; confirm host/execution distinctions, or report an unknown host honestly.
4. Scan only the shared synthetic root with `--confirm-environment`. Verify complete duplicate members, protected exclusions and unchanged contents.
5. Inspect/export/review using a private Linux directory. Confirm no ChromeOS host or Android app claims and no automatic cross-scope traversal.
6. Cancel a bounded deep scan, then check cancelled/partial coverage. Keep all files. Record the command/revision and limitations before calling this environment tested.

Cross-compilation and generic Linux CI do not replace this manual device test.

On Windows the portable collector cannot measure external hardlink counts or file identities from metadata; link-count, sparse and clone flags remain null when unknown. Discovered hardlinks are deduplicated with OS file-identity comparisons, bounded to 1024 identity-unknown files per size bucket. Additional files are skipped with PARTIAL coverage.
