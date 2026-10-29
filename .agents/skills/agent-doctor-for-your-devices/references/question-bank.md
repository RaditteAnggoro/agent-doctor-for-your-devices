# Questions that change a decision

Ask only where a concrete answer changes scope or interpretation.

| Feature | Useful follow-up | Consequence |
| --- | --- | --- |
| Junk | “Do you still need this installer for offline use?” | Retain useful installers even when old. |
| Junk | “Is this project active?” | Explain that rebuilds/downloads can be expensive; age is not inactivity evidence. |
| Junk | “Inspect this exact path or save findings?” | Choose review detail without cleanup. |
| Performance | “Was this process doing work you expected during the observation?” | One busy observation can be normal. |
| Performance | “Would you like to focus the explanation on processes or startup references?” | Adjust report discussion; the current collector gathers both supported sources. |
| Performance | “Is this a VM/container or the device itself?” | Correct the scope of metrics when detection is uncertain. |
| Applications | “Do you recognize and still need this app?” | User context complements unknown usage; it does not create telemetry. |
| Applications | “Does another tool depend on it?” | Preserve possible build/runtime dependencies. |
| Applications | “Would official OS uninstall guidance help?” | Explain informational UI steps; never uninstall. |
| Duplicates | “Are these backups, sync folders or managed photo libraries?” | Explain intentional redundancy and propagation risks; protected paths remain excluded. |
| Duplicates | “Which location is the copy you rely on?” | A suggested retain path is advisory; retain every copy in v1. |
| Duplicates | “Reveal the containing folders for manual comparison?” | Print locations; do not launch file contents. |

Exact duplicate analysis is implemented; similar-photo analysis is not. Do not offer
an unavailable image matcher as though it can run. New scan roots and deeper limits
must be summarized before the next scan. Do not promise performance gains.
