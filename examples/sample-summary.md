# Agent Doctor For Your Devices — Review report

Scan: synthetic-scan-001 · Mode: READ-ONLY

Use these measurements, their sources and the questions below to decide what to inspect or keep. No finding approves uninstall or deletion. All items are retained; unknown values remain unknown.

## junk

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

| ID | Exact path | Logical size | Modified / age | Category | Risk / review state |
| --- | --- | --- | --- | --- | --- |
| J-000001 | /synthetic/資料/file.tmp | 5 bytes | 2026-01-01T00:00:00Z (0 days before scan) | temporary\_file | MODERATE / NEEDS\_REVIEW |

Modification age is not last use. Confirm offline reuse, active work and backup needs before any future removal review.

Collection method: synthetic metadata

| Evidence field | Recorded value |
| --- | --- |
| bytes read | 0 |
| inaccessible | 0 |
| skipped | 0 |
| status | COMPLETED |
| visited | 0 |

### J-000001 — Synthetic temporary file for manual review

Risk: MODERATE · Confidence: MEDIUM · Guidance: INSPECT

**Why review:** Synthetic category and age

**Possible consequences:** Loss of wanted data

**Manual inspection:** Review exact path manually

**Exact locations**

- /synthetic/資料/file.tmp

**Evidence**

- Synthetic metadata

**Limitations**

- Synthetic fixture only

**Decision preparation:** NEEDS\_REVIEW · Suggested choice: INSPECT · Review type: MANUAL\_FILE\_REVIEW

**Reasons for this choice**

- Category temporary\_file; logical size 5 bytes; modification time 2026-01-01T00:00:00Z.
- 0 days since modification; modification age is not last use.

**Missing evidence**

- Reliable last use and owning app activity are unknown.
- Backup/sync role and physical storage recovery are not established.
- Hardlink count is unknown; logical copies do not establish physical recovery.

**Before any later action**

- This read-only review is not execution approval. A later action requires exact targets, current identity checks, consequences and explicit user confirmation.

**Questions for your decision**

- Is the file still needed for work, troubleshooting, restoration or offline use?
- Is this the only copy you need, and is a usable backup available?

**Next review steps**

- Inspect the exact path and its purpose, then record keep or review-later if uncertain.
- If later selected for file cleanup, review backup/sync propagation and an OS Trash recovery route before approving exact targets.

Potential logical bytes under review: 5 bytes. This is not a physical recovery estimate or action approval.

| Evidence field | Recorded value |
| --- | --- |
| active use hints | UNKNOWN (not collected in this scan) |
| backup | false |
| basename | file.tmp |
| category | temporary\_file |
| file / clone | UNKNOWN (not collected in this scan) |
| file / cloud | false |
| file / device | synthetic-device |
| file / hardlink | UNKNOWN (not collected in this scan) |
| file / identity | synthetic-id |
| file / modified | 2026-01-01T00:00:00Z |
| file / path | /synthetic/資料/file.tmp |
| file / size | 5 |
| file / sparse | UNKNOWN (not collected in this scan) |
| file / symlink | false |
| kind | file |
| last accessed | UNKNOWN (not collected in this scan) |
| owning app | UNKNOWN (not collected in this scan) |
| reclaimable bytes | UNKNOWN (not collected in this scan) |
| review status | REVIEW\_WITH\_CAUTION |

Candidate logical bytes: 5. Physical reclaimable space: UNKNOWN.

## performance

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

| ID | Process / observation | CPU % (100% = one logical core) | RSS / working set | Window seconds | Risk / review state |
| --- | --- | --- | --- | --- | --- |
| P-000001 | Synthetic observation | UNKNOWN (not collected in this scan) | UNKNOWN (not collected in this scan) | 3 | MODERATE / OBSERVE |

Rows are limited by collector coverage and are not a complete CPU ranking. RSS can include shared pages. Compare the actual observation window with the workload before diagnosing persistent slowness.

Collection method: synthetic metadata

| Evidence field | Recorded value |
| --- | --- |
| bytes read | 0 |
| inaccessible | 0 |
| skipped | 0 |
| status | COMPLETED |
| visited | 0 |

### P-000001 — Synthetic observation

Risk: MODERATE · Confidence: MEDIUM · Guidance: INSPECT

**Why review:** Synthetic category and age

**Possible consequences:** Loss of wanted data

**Manual inspection:** Review exact path manually

**Exact locations**

- /synthetic/資料/file.tmp

**Evidence**

- Synthetic metadata

**Limitations**

- Synthetic fixture only

**Decision preparation:** OBSERVE · Suggested choice: OBSERVE\_LONGER · Review type: INVESTIGATE\_PROCESS

**Reasons for this choice**

- Resource measurements are observations, not proof of a persistent fault or a reason to uninstall an app.

**Missing evidence**

- Memory pressure unknown: SYNTHETIC pressure source unavailable
- Available memory is unknown; free pages and total RAM alone do not establish memory pressure.
- Swap usage was not measured.

**Before any later action**

- This read-only review is not execution approval. A later action requires exact targets, current identity checks, consequences and explicit user confirmation.

**Questions for your decision**

- What slowdown or resource symptom are you observing, and during which workload?

**Next review steps**

- Compare resource observations over a longer representative workload in the OS system monitor.
- Review dependencies and active work before choosing any manual action; this report stops no processes and changes no startup entries.

Potential logical bytes under review: UNKNOWN (not collected in this scan). This is not a physical recovery estimate or action approval.

| Evidence field | Recorded value |
| --- | --- |
| cpu percent | UNKNOWN (not collected in this scan) |
| cpu semantics | Unavailable |
| dependency notes | UNKNOWN (not collected in this scan) |
| disk available bytes | UNKNOWN (not collected in this scan) |
| disk total bytes | UNKNOWN (not collected in this scan) |
| executable path | UNKNOWN (not collected in this scan) |
| logical cpus | 4 |
| memory available bytes | UNKNOWN (not collected in this scan) |
| memory pressure reason | SYNTHETIC pressure source unavailable |
| memory total bytes | UNKNOWN (not collected in this scan) |
| observation seconds | 3 |
| observed impact | Unknown |
| owner | UNKNOWN (not collected in this scan) |
| pid | UNKNOWN (not collected in this scan) |
| process name | UNKNOWN (not collected in this scan) |
| rss bytes | UNKNOWN (not collected in this scan) |
| running | UNKNOWN (not collected in this scan) |
| startup source | UNKNOWN (not collected in this scan) |
| swap used bytes | UNKNOWN (not collected in this scan) |

## applications

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

| ID | Application | Version | Logical app size / measurement | Last-used signal | Running | System / role | Risk / review state |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-000001 | Synthetic App | UNKNOWN | 734.00 MB (734003200 bytes) / COMPLETED | 2026-09-14 | No | No / MAIN | MODERATE / NEEDS\_REVIEW |

Last-used metadata is a source-specific opening/launch signal, not complete activity history; its provenance and missing-data reasons are recorded in each application card. Missing data never proves that an application is unused. A PARTIAL size is a measured lower bound; package estimates and logical size do not promise physical storage recovery.

Collection method: synthetic metadata

| Evidence field | Recorded value |
| --- | --- |
| bytes read | 0 |
| inaccessible | 0 |
| skipped | 0 |
| status | COMPLETED |
| visited | 0 |

### A-000001 — Synthetic application

Risk: MODERATE · Confidence: MEDIUM · Guidance: INSPECT

**Why review:** Synthetic category and age

**Possible consequences:** Loss of wanted data

**Manual inspection:** Review exact path manually

**Exact locations**

- /synthetic/資料/file.tmp

**Evidence**

- Synthetic metadata

**Limitations**

- Synthetic fixture only

**Decision preparation:** NEEDS\_REVIEW · Suggested choice: INSPECT · Review type: MANUAL\_UNINSTALL\_REVIEW

**Reasons for this choice**

- An installed application record is available; installation is not evidence of disuse.
- Bundle/package logical size: 734003200 bytes; method: SYNTHETIC bounded logical bundle measurement; excludes external app data; status: COMPLETED.
- No matching process was observed in the snapshot; this does not prove the application is unused.

**Missing evidence**

- Last-use timestamp cannot be compared reliably to this observation.
- Private app data, licenses, reliable installation time and actual dependency graph are not measured by the bundle inventory.

**Before any later action**

- This read-only review is not execution approval. A later action requires exact targets, current identity checks, consequences and explicit user confirmation.

**Questions for your decision**

- Do you still use this app, including occasional or offline work?
- Does another tool, browser extension, VPN or security workflow depend on it?
- Which documents, settings and licenses need backup or retention?

**Next review steps**

- Review the exact installation location, measured size and usage source.
- Check the vendor's official uninstall instructions; identify a dedicated uninstaller if required.
- Record keep, review-later, skip or mark-reviewed; choose exact app/data scope separately for a future phase.
- Use the OS interface

Potential logical bytes under review: 734.00 MB (734003200 bytes). This is not a physical recovery estimate or action approval.

| Evidence field | Recorded value |
| --- | --- |
| app role | MAIN |
| bundle id | com.example.synthetic |
| bundle modified at | 2026-09-01T10:00:00Z |
| dependency notes | UNKNOWN (not collected in this scan) |
| install size bytes | 734003200 |
| installed at | UNKNOWN (not collected in this scan) |
| last usage | 2026-09-14T10:00:00Z |
| location | UNKNOWN (not collected in this scan) |
| name | Synthetic App |
| related services | UNKNOWN (not collected in this scan) |
| running | false |
| running reason | SYNTHETIC comm-only snapshot: no matching visible process |
| size entries | 120 |
| size limitations | SYNTHETIC evidence only; no device data was collected |
| size method | SYNTHETIC bounded logical bundle measurement; excludes external app data |
| size status | COMPLETED |
| source | synthetic |
| system app | false |
| uninstall method | Use the OS interface |
| updated at | UNKNOWN (not collected in this scan) |
| usage provenance | SYNTHETIC Spotlight LaunchServices open signal |
| usage reason | Illustrative open metadata, not complete activity history |
| usage status | AVAILABLE |
| version | UNKNOWN (not collected in this scan) |

## duplicates

Support: SUPPORTED · Coverage: COMPLETED · Findings: 1

| Group ID | Match | Members | Logical redundant size | Physical recovery | Risk / review state |
| --- | --- | --- | --- | --- | --- |
| D-000001 | EXACT\_CONTENT | 2 | 5 bytes | UNKNOWN (not collected in this scan) | MODERATE / NEEDS\_REVIEW |

Review every member and its role. Matching content can be intentional backup or project/application data; none of these files is selected for deletion.

Collection method: synthetic metadata

| Evidence field | Recorded value |
| --- | --- |
| bytes read | 0 |
| inaccessible | 0 |
| skipped | 0 |
| status | COMPLETED |
| visited | 0 |

### D-000001 — Exact synthetic match

Risk: MODERATE · Confidence: MEDIUM · Guidance: INSPECT

**Why review:** Synthetic category and age

**Possible consequences:** Loss of wanted data

**Manual inspection:** Review exact path manually

**Exact locations**

- /synthetic/資料/file.tmp

**Evidence**

- Synthetic metadata

**Limitations**

- Synthetic fixture only

**Decision preparation:** NEEDS\_REVIEW · Suggested choice: COMPARE\_COPIES · Review type: COMPARE\_DUPLICATES

**Reasons for this choice**

- 2 members; EXACT\_CONTENT / SHA-256 verification; logical redundant bytes 5.

**Missing evidence**

- The purpose, external references and backup role of each copy are unknown.
- Physical storage recovery, clones and snapshot sharing are unknown.
- Hardlink count is unknown; logical copies do not establish physical recovery.

**Before any later action**

- This read-only review is not execution approval. A later action requires exact targets, current identity checks, consequences and explicit user confirmation.

**Questions for your decision**

- Which exact path should remain available, and which applications or projects reference each copy?
- Are these intentional backups, exports or app-managed uploads?
- Has each proposed removal target been revalidated since this scan?

**Next review steps**

- Compare every member path, modification date, size and link flags.
- Choose a retained path explicitly; the displayed suggestion is only a neutral review starting point.
- Keep all app-managed or referenced copies until their owners and recovery requirements are established.

Potential logical bytes under review: 5 bytes. This is not a physical recovery estimate or action approval.

| Member exact path | Logical size | Modified / age | Link / allocation observations | Device / file identity |
| --- | --- | --- | --- | --- |
| /synthetic/資料/file.tmp | 5 bytes | 2026-01-01T00:00:00Z (0 days before scan) | hardlink=UNKNOWN; symlink=No; sparse=UNKNOWN; clone=UNKNOWN; cloud=No | synthetic-device / synthetic-id |
| /synthetic/copy.tmp | 5 bytes | 2026-01-01T00:00:00Z (0 days before scan) | hardlink=UNKNOWN; symlink=No; sparse=UNKNOWN; clone=UNKNOWN; cloud=No | synthetic-device / second-id |

| Evidence field | Recorded value |
| --- | --- |
| backup warning | Unknown |
| digest | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
| hash algorithm | SHA-256 |
| logical redundant bytes | 5 |
| match type | EXACT\_CONTENT |
| physical reclaimable bytes | UNKNOWN (not collected in this scan) |
| retain reason | Neutral path ordering |
| suggested retain | /synthetic/資料/file.tmp |

Logical redundant bytes: 5. Physical reclaimable space: UNKNOWN.

## Scan provenance and scope

| Evidence field | Recorded value |
| --- | --- |
| accuracy notes | SYNTHETIC: not actual observations |
| actual changes / apps uninstalled | 0 |
| actual changes / files removed | 0 |
| actual changes / processes stopped | 0 |
| display timezone | UTC |
| elapsed seconds | 0 |
| environment / architecture | synthetic |
| environment / host os | synthetic |
| environment / limitations | UNKNOWN (not collected in this scan) |
| environment / os | synthetic |
| environment / os version | UNKNOWN (not collected in this scan) |
| environment / remote | false |
| environment / tools | UNKNOWN (not collected in this scan) |
| environment / type | fixture |
| method | synthetic |
| permissions | No actual device access |
| product | Agent Doctor For Your Devices |
| scan id | synthetic-scan-001 |
| schema version | 1.0 |
| scope / exclusions | UNKNOWN (not collected in this scan) |
| scope / max bytes | 10000 |
| scope / max depth | 5 |
| scope / max files | 100 |
| scope / roots | /synthetic |
| selected features | junk; performance; applications; duplicates |
| timestamp | 2026-01-01T00:00:00Z |
| version | 0.2.0 |

Changes: 0 files removed / 0 apps uninstalled / 0 processes stopped.
