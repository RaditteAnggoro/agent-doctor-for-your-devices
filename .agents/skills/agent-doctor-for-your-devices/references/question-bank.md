# Questions that change a decision

Ask only where a concrete answer changes scope or interpretation. These Indonesian
examples illustrate the question's purpose; adapt the wording to the user's
conversation language without changing the consequence or approval boundary.

| Feature | Useful follow-up | Consequence |
| --- | --- | --- |
| Junk | “Installer ini masih kamu butuhkan buat instal ulang atau pakai offline?” | Retain useful installers even when old. |
| Junk | “Proyek ini masih kamu pakai?” | Explain that rebuilds/downloads can be expensive; age is not inactivity evidence. |
| Junk | “Mau lihat detail file ini atau simpan hasilnya dulu?” | Choose review detail without cleanup. |
| Performance | “Pas dicek tadi, proses ini memang lagi kamu pakai buat kerja?” | One busy observation can be normal. |
| Performance | “Mau kita bahas proses yang berjalan atau referensi startup dulu?” | Adjust report discussion; the current collector gathers both supported sources. |
| Performance | “Ini perangkatnya langsung, atau kamu pakai VM/container?” | Correct the scope of metrics when detection is uncertain. |
| Applications | “Kamu masih pakai aplikasi ini?” | User context complements unknown usage; it does not create telemetry. |
| Applications | “Ada tool atau pekerjaan lain yang masih butuh aplikasi ini?” | Preserve possible build/runtime dependencies. |
| Applications | “Mau aku bantu cek cara uninstall resminya?” | Check the official method; eligible actions still require a separately reviewed exact-target plan. |
| Duplicates | “File ini bagian dari backup, folder sync, atau library foto aplikasi?” | Explain intentional redundancy and propagation risks; protected paths remain excluded. |
| Duplicates | “Salinan di folder mana yang biasanya kamu pakai?” | A suggested retain path is advisory; a later approved action must preserve an explicitly chosen verified member. |
| Duplicates | “Mau lihat lokasi foldernya supaya bisa kamu bandingkan?” | Print locations; do not launch file contents. |

Exact duplicate analysis is implemented; similar-photo analysis is not. Do not offer
an unavailable image matcher as though it can run. New scan roots and deeper limits
must be summarized before the next scan. Do not promise performance gains.
