# Polyglot File Investigation

A controlled DFIR investigation into a file containing multiple recognizable file-format characteristics. The investigation examines how a file that appears to be a normal text file can contain additional embedded or appended data that is not obvious from its filename or extension.

The lab follows an evidence-driven approach using Windows file metadata, SHA256 hashing, byte-level inspection, ASCII string analysis, Sysmon telemetry, and Wazuh endpoint correlation.

## Investigation Overview

| Category | Details |
|---|---|
| Investigation Type | DFIR / File Analysis / Threat Hunting |
| Primary Technique | Polyglot / Multi-Format File Analysis |
| Host | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| PowerShell | 7.6.6 |
| Sysmon | System Monitor v15.21 |
| Wazuh Agent | `001` |
| Evidence Path | `C:\PolyglotFileLab\Evidence` |
| Primary Artifact | `C:\PolyglotFileLab\invoice-polyglot.txt` |
| File Extension | `.txt` |
| Polyglot File Size | 213 bytes |
| SHA256 | `B73368FD011D7B1D2DB527B6BF7AAABAF4DB72F8CEBBDA4D957DCC01431F5A67` |

## Scenario

A controlled file investigation is performed to determine whether a file's filename and extension accurately represent its underlying content. A normal text file is created first, followed by a small ZIP archive containing controlled content. The ZIP data is then appended to a copy of the text file, creating a controlled artifact with multiple recognizable file-format characteristics.

The resulting artifact is named `invoice-polyglot.txt`. Although its extension remains `.txt`, byte-level analysis identifies a ZIP signature at a later offset in the file. The investigation therefore examines the artifact's metadata, hash, byte structure, strings, and endpoint telemetry to determine what can be confirmed from the available evidence.

## Objectives

- Establish a documented Windows investigation baseline.
- Create a controlled reference text file.
- Create a controlled ZIP archive.
- Construct a controlled polyglot-like artifact by appending ZIP data.
- Record file metadata and timestamps.
- Calculate SHA256 hashes for the reference and modified artifacts.
- Compare the original and modified file sizes.
- Inspect the artifact at the byte level.
- Identify additional file-format signatures.
- Extract and examine ASCII-readable content.
- Search Sysmon for file creation telemetry.
- Search Sysmon for process execution telemetry.
- Correlate the artifact with Wazuh endpoint telemetry.
- Distinguish confirmed file-format characteristics from assumptions about maliciousness.
- Document telemetry limitations and unrelated events.

## Controlled Artifacts

### Reference File

```text
C:\PolyglotFileLab\invoice.txt
```

Size:

```text
40 bytes
```

SHA256:

```text
0A7C3F48B8138D6E706C1D57426D8A2FD7FECEDCBC5BAA9CD71CDB1D6E33FBD1
```

### Embedded Archive

```text
C:\PolyglotFileLab\EmbeddedData.zip
```

Size:

```text
173 bytes
```

### Investigation Artifact

```text
C:\PolyglotFileLab\invoice-polyglot.txt
```

Extension:

```text
.txt
```

Size:

```text
213 bytes
```

SHA256:

```text
B73368FD011D7B1D2DB527B6BF7AAABAF4DB72F8CEBBDA4D957DCC01431F5A67
```

## File Analysis

The original text file was 40 bytes. The resulting `invoice-polyglot.txt` was 213 bytes, representing the original content plus the appended ZIP data.

The file retained the `.txt` extension:

```text
invoice-polyglot.txt
```

However, byte-level analysis identified the ZIP signature:

```text
50 4B 03 04
```

at:

```text
Byte offset: 40
```

This is consistent with the controlled construction: the first 40 bytes contain the original text content and the ZIP data begins afterward.

## ASCII String Analysis

The extracted ASCII representation contained:

```text
Controlled Polyglot File Investigation
ArchiveContent.txt
PK
```

The appearance of `ArchiveContent.txt` and ZIP-related `PK` data is consistent with the controlled ZIP content appended to the artifact.

## Sysmon Findings

A Sysmon Event ID 11 record associated with the endpoint was observed in Wazuh:

```text
Channel: Microsoft-Windows-Sysmon/Operational
Computer: DESKTOP-9MMM37V
Event ID: 11
Event Record ID: 1130809
```

This provides endpoint telemetry indicating that Sysmon Event ID 11 data was being collected and ingested by Wazuh.

A direct PowerShell query for Sysmon Event ID 11 using the filename did not return a displayed result. Therefore, the Wazuh record is treated as supporting telemetry, while the exact relationship between that record and the artifact should not be overstated without the complete event message.

A direct Sysmon Event ID 1 query for `invoice-polyglot.txt` also returned no result.

## Wazuh Findings

Wazuh contained endpoint-specific Sysmon telemetry for:

```text
Computer: DESKTOP-9MMM37V
Event ID: 11
```

The endpoint should be scoped using:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

No confirmed Sysmon Event ID 1 execution event for `invoice-polyglot.txt` was observed in the provided evidence.

## Unrelated Telemetry

Task Scheduler Event ID 100 activity was also observed on the endpoint, including the Microsoft task:

```text
\Microsoft\Windows\Flighting\OneSettings\RefreshCache
```

The observed Task Scheduler activity occurred on 28-07-2026 and is not correlated with the 08-10-2026 polyglot investigation. It is therefore excluded from the investigation assessment.

## Assessment

| Finding | Assessment |
|---|---|
| File extension | `.txt` |
| Original file size | 40 bytes |
| Polyglot file size | 213 bytes |
| ZIP signature | Confirmed |
| ZIP signature offset | Byte 40 |
| Embedded archive content | Confirmed as controlled test data |
| SHA256 | Confirmed |
| Sysmon EID 11 telemetry | Observed through Wazuh |
| Sysmon EID 1 for artifact | No matching result observed |
| Artifact execution | Not confirmed |
| Malicious payload | Not identified |
| Malicious execution | Not confirmed |
| Polyglot characteristic | Confirmed in controlled artifact |

## Final Assessment

The investigation confirms that `invoice-polyglot.txt` contains the original 40-byte text content followed by recognizable ZIP-format data beginning at byte offset 40. The artifact therefore demonstrates a controlled multi-format/polyglot characteristic despite retaining a `.txt` extension.

The evidence does not establish that the file is malicious or that it was executed. The observed Wazuh Sysmon Event ID 11 telemetry confirms that relevant file-creation telemetry is being collected on the endpoint, but the provided evidence does not establish a complete one-to-one relationship between that event and the artifact. No matching Sysmon Event ID 1 execution event was observed.

The investigation therefore concludes that the **polyglot characteristic is confirmed, while maliciousness and execution remain unconfirmed**.

## Key Lesson

A file extension should never be treated as sufficient evidence of file type. File metadata, hashes, signatures, internal structure, strings, and endpoint telemetry should be evaluated together.

> Follow the evidence, not the assumption.
