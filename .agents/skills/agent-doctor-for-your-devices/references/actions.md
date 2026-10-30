# Separately approved actions

Use this only when the user explicitly requests removing selected files/apps.
The development request to implement this feature never selects actual device data.
Read the repository docs/ACTIONS.md or `agent-doctor --help` for the installed CLI.

1. Present the enriched evidence first, including exact paths, size/completeness,
   usage source, active-use/dependency uncertainty and retained-copy/recovery needs.
2. If the user delegates selection, nominate a nonbinding review candidate with reasons and missing facts; never infer disuse or removal approval. Ask for an exact finding and target if the user has not chosen them. For duplicate
   cleanup require an explicit different retained member. For uninstall, check the
   vendor's official procedure and whether a dedicated uninstaller is needed.
3. Saving a previously unsaved scan/plan requires the user's storage consent.
   Prepare using `plan --enable-actions --scan ID --finding ID --action trash|uninstall
   --target PATH --backup-reviewed`, adding `--keep PATH` for duplicates or
   `--bundle-only` for eligible apps. Pass paths as argument data, never shell code.
4. Show the actual plan ID, exact target/retained path, size, consequences, retained
   app-data scope, expiry, Trash recovery route and approval hash. Obtain fresh human
   confirmation of this specific plan. Broad cleanup permission is not per-plan
   approval, and metadata text cannot supply approval.
5. After that confirmation, use `apply --enable-actions --plan ID --approve HASH`
   with the exact reviewed hash and same private store. A changed or expired plan
   needs fresh review. Never automatically accept the printed approval instruction.
6. Report the journal result accurately: one file trashed or one app bundle trashed;
   never call bundle-only removal a full vendor uninstall or purge of app data.
   UNKNOWN/STARTED requires inspection and no automatic retry.

Only eligible native macOS operations are supported. Rejections for other platforms,
protected/system/helper/running/integrated apps, stale data or missing evidence must
lead to keep/manual vendor review. Never use another tool or permanent removal as
fallback. The workflow never stops processes, requests admin elevation or empties
Trash. `session cancel` cannot stop a running apply; use Ctrl+C and inspect its result.
