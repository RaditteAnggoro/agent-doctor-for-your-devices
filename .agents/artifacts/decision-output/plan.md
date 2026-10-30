# Decision-oriented evidence and reports

Requested outcome: scan output must give users enough evidence to review uninstall/delete candidates later. This increment enriches read-only evidence and review preparation, not an execution engine. Preserve existing scopes, no telemetry and no fabricated activity or recovery estimates.

Acceptance:
- Applications show measured logical bundle size + completeness/method, last-used source and unknown reason, running evidence, system/helper role, consequences and questions before uninstall review.
- All four features produce visible decision guidance, missing evidence, blockers, exact paths and practical next steps. Duplicate members show dates and individual locations, not just group totals.
- Human reports and agent chat tables use these fields; JSON/CSV retain complete evidence. Redaction, old stored-report compatibility and escaping remain intact.
- Performance uses a useful bounded configurable sample and more native metadata when available. Unknown data remains explicitly unknown.
- Synthetic tests cover measurements, metadata absence, partial limits, protected items, decision rules and output. Run race tests, vet, formatting and six target builds, then publish and inspect CI.

Work split: application collector; performance collector; report/skill/docs; root shared contracts, decision rules, schemas, CLI, integration and publication. No real device scan during development/testing and no personal screenshots or scan outputs committed.

## User expansion, 2026-10-30

The user explicitly requested implementing delete and uninstall processes too.
Experimental phase2 now adds private immutable single-target plans with15-minute
expiry, scan age<=24h, full file/bundle fingerprints, exact approval hash, retained
duplicate validation, native macOS Foundation Trash, current native/local environment
checks and journal/replay locks. Bundle-only app uninstall keeps external user data.
No real user files/apps are selected for action by this development task. Linux and
Windows execution remains unsupported until identity-preserving native backends are
verified; read-only collection still supports its documented environments.
