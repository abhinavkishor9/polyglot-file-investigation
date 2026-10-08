# Investigation Timeline

## Timeline

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

## Key Evidence

### Reference File

```text
C:\PolyglotFileLab\invoice.txt
```

```text
Size: 40 bytes
SHA256: 0A7C3F48B8138D6E706C1D57426D8A2FD7FECEDCBC5BAA9CD71CDB1D6E33FBD1
```

### Polyglot Artifact

```text
C:\PolyglotFileLab\invoice-polyglot.txt
```

```text
Extension: .txt
Size: 213 bytes
SHA256: B73368FD011D7B1D2DB527B6BF7AAABAF4DB72F8CEBBDA4D957DCC01431F5A67
```

### Secondary Signature

```text
ZIP signature: 50 4B 03 04
Offset: 40
```

### Wazuh

```text
Computer: DESKTOP-9MMM37V
Channel: Microsoft-Windows-Sysmon/Operational
Event ID: 11
Event Record ID: 1130809
```

## Timeline Interpretation

The timeline shows a controlled progression from a normal 40-byte text file to a 213-byte artifact containing appended ZIP-format data.

The most significant forensic finding is the ZIP signature at byte offset 40, which corresponds directly with the original size of the reference file. This provides strong evidence that the ZIP content was appended after the original text content.

## Events Excluded From the Investigation

Task Scheduler Event ID 100 activity was observed for:

```text
\Microsoft\Windows\Flighting\OneSettings\RefreshCache
```

The observed event occurred on:

```text
28-07-2026
```

Because this predates the 08-10-2026 investigation, it is not included as evidence of polyglot-file activity.

## Final Timeline Assessment

The timeline supports:

```text
Controlled polyglot characteristic: CONFIRMED
Appended ZIP data: CONFIRMED
Artifact SHA256: CONFIRMED
Wazuh Sysmon EID 11 telemetry: OBSERVED
Artifact execution: NOT CONFIRMED
Malicious activity: NOT ESTABLISHED
```

The investigation demonstrates that file-format analysis must extend beyond the filename and extension. The artifact's internal byte structure provided the strongest evidence of its multi-format characteristics, while endpoint telemetry was used as supporting evidence rather than as a substitute for direct artifact analysis.
