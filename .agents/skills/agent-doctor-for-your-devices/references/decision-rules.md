# Feature-specific decisions

Risk describes consequences; confidence describes evidence. Neither is deletion
permission. Prefer INSPECT/KEEP/REVIEW_LATER; protected material is DO_NOT_TOUCH.

**Junk:** classify explainable old temporary/log/installer files and recognized cache-path candidates, not large
files alone. Show age/category and active-use uncertainty. Credentials, browser
profiles, repositories, app databases, cloud data and system paths are protected.
Unknown access times are null. Cache regeneration can cost time and bandwidth.

**Performance:** distinguish measured CPU sampling semantics from instantaneous RSS
or capacity. State the observation window and scope. A busy process is not a broken
process. Missing pressure/swap/startup data is unknown. Do not print raw command-line
arguments. Ask whether work is expected before suggesting manual investigation in
the OS monitor. Never stop a process or disable startup entries.

**Applications:** inventory is evidence of installation, not disuse. Unknown last-use
and running state remain unknown. Source, version and dependency notes qualify review.
Uninstall guidance is informational and uses the official OS/package workflow;
recursive folder deletion is not an uninstall method.

**Duplicates:** size grouping is only a shortlist. Exact groups need full streaming
SHA-256 and content verification, with every member listed. Account for hard links;
physical recovery stays null for uncertain sparse/COW/cloned storage. Preserve
backups and every copy. A suggested retain path is a review convenience with a stated
reason, not a decision to remove the others. Similar images are not exact duplicates.
