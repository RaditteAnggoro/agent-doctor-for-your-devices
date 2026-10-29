# Platform support during a conversation

`doctor` is authoritative for available collectors in the running environment.
The README/platform matrix records implementation and test limits. Never treat a
cross-compiled binary as proof that a collector ran on that device.

- **macOS:** use only user-approved readable folders. Respect TCC/SIP. Do not ask to disable protections. A denied folder yields limited coverage.
- **Windows:** use the native executable for Windows metadata. User folders and supported metadata sources require no administrator account. Avoid NTFS links/junctions and protected OS directories.
- **Linux:** check available native tools; package managers, desktop startup and `/proc` visibility differ. Container metrics describe the accessible namespace.
- **WSL:** host Windows and Linux execution differ. Do not cross `/mnt/c` automatically or claim Linux metrics cover Windows.
- **ChromeOS/Crostini:** ask about Linux enablement and shared folders. Linux process/package findings do not describe ChromeOS host/Android apps or startup.
- **SSH/remote/container:** confirm the execution environment is the intended target. Do not infer access to the physical host.

Missing fields remain null with reasons. Use PARTIAL, UNSUPPORTED, PERMISSION_DENIED,
NOT_TESTED or SKIPPED where applicable. Manual reporting remains useful when a
collector is limited. No ChromeOS hardware test has been established by this skill.
