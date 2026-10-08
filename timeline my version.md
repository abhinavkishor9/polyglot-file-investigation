# Investigation Timeline

| Date / Time | Phase | Activity | Evidence | Assessment |
|---|---|---|---|---|
| 08-10-2026 07:24 | Setup | Evidence directory created | `C:\PolyglotFileLab\Evidence` | Investigation workspace established |
| 08-10-2026 07:28:27 | Baseline Artifact | `invoice.txt` created | 40 bytes | Controlled reference file |
| 08-10-2026 07:29:58 | Archive Creation | `EmbeddedData.zip` created | 173 bytes | Controlled ZIP archive |
| 08-10-2026 | Artifact Construction | ZIP bytes appended to copied text file | `invoice-polyglot.txt` | Controlled polyglot-like artifact created |
| 08-10-2026 07:31:20 | Artifact Metadata | File creation time recorded | `invoice-polyglot.txt` | Artifact metadata captured |
| 08-10-2026 07:31:33 | Artifact Metadata | Last write time recorded | `invoice-polyglot.txt` | Artifact modification completed |
| 08-10-2026 | Hash Analysis | SHA256 calculated | `B73368FD011D7B1D2DB527B6BF7AAABAF4DB72F8CEBBDA4D957DCC01431F5A67` | Artifact identity established |
| 08-10-2026 | Size Analysis | Reference and polyglot sizes compared | 40 vs 213 bytes | Additional data confirmed |
| 08-10-2026 | Byte Analysis | ZIP signature searched | `50 4B 03 04` at offset 40 | Secondary format signature confirmed |
| 08-10-2026 | String Analysis | ASCII content extracted | `ArchiveContent.txt`, `PK` | Consistent with embedded ZIP data |
| 08-10-2026 | Sysmon Review | Event ID 1 searched | No matching result displayed | Execution not confirmed |
| 08-10-2026 | Sysmon Review | Event ID 11 searched | No direct PowerShell result displayed | Direct attribution not established |
| 08-10-2026 | Wazuh Review | Sysmon Event ID 11 observed | Endpoint `DESKTOP-9MMM37V` | File-creation telemetry available |
| 08-10-2026 | Correlation | Artifact and telemetry compared | Endpoint-scoped evidence | No execution established |

