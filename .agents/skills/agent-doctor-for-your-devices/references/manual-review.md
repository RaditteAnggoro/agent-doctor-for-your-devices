# Manual review

Always present findings before asking what to do. Use the stored scan ID when available:

```text
agent-doctor inspect J-000001 --scan <scan-id>
agent-doctor explain J-000001 --scan <scan-id>
agent-doctor reveal J-000001 --scan <scan-id>
agent-doctor review J-000001 --decision keep --scan <scan-id>
agent-doctor review J-000001 --decision review-later --scan <scan-id>
agent-doctor review J-000001 --decision skip --scan <scan-id>
agent-doctor review J-000001 --decision mark-reviewed --scan <scan-id>
```

Confirm flags with the installed CLI's help if using a different version. The reveal
fallback prints containing-folder paths for manual navigation, never opens targets.
Inspection of a stale or changed file cannot prove it is still the original finding.

Review state changes only the local session, never the item. If the original scan
was not saved, work from the current report or ask before creating local storage.
Export requires an explicit destination; refuse accidental overwrites. `session list`
and `session resume <scan-id>` restore saved reports and decisions. `session cancel`
marks saved state; Ctrl+C interrupts an active CLI process.

When users request cleanup, explain the reviewed risks and official vendor/UI steps.
For eligible native macOS items, follow actions.md to prepare and obtain fresh
per-plan approval. Do not generate bulk destructive commands, silently escalate,
or use another tool to bypass a rejected action. Finishing while keeping all
items is a complete session.
