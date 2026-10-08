# polyglot-file-investigation
A polyglot file is an artifact that can satisfy the structural requirements of more than one file format, or a file that contains content associated with another format without necessarily being obvious from its filename or extension.

For a SOC/DFIR analyst, the important point is that file extension alone is not reliable evidence of file type.

For example, a file named:

invoice.jpg

may have a JPEG extension while containing additional data that is inconsistent with a normal JPEG. Conversely, some legitimate files can contain appended metadata or additional structures, so unusual bytes do not automatically mean malicious activity.

The investigation should therefore compare several independent characteristics:

Filename → Extension → File signature → MIME/type → Size → Hash → Internal structure → Strings → Endpoint telemetry

The investigation should distinguish between:

Confirmed polyglot characteristics
Suspicious file-format manipulation
Benign additional data
Insufficient evidence

Most importantly, finding a second file signature does not by itself prove malware. The analyst must determine where the signature occurs, whether the primary format remains valid, what the additional content represents, and whether endpoint activity supports malicious use.

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
A controlled Windows endpoint investigation is conducted to determine whether a file's name and extension accurately represent its underlying content. The investigation focuses on a deliberately constructed artifact that begins as a normal text file and is later combined with controlled ZIP-format data. This provides a safe way to examine how multiple file-format characteristics can exist within a single artifact.

The investigation begins with a known reference file so that its original size, metadata, and hash can be compared against the modified artifact. A benign ZIP archive is then created and its binary content is appended to a copy of the reference file. The resulting `invoice-polyglot.txt` retains a `.txt` extension but contains recognizable ZIP-format data beyond the original text content.

The investigation examines the artifact from several perspectives:
- File metadata, timestamps, size, and SHA256 hash.
- File extension compared with the underlying byte structure.
- Hexadecimal data and recognizable file signatures.
- The location of the secondary ZIP signature within the file.
- ASCII-readable strings and embedded filenames.
- Sysmon file-creation and process-creation telemetry.
- Wazuh endpoint telemetry associated with the Windows host.

A key investigative question is whether the additional file-format structure represents a genuine polyglot characteristic and whether there is any independent evidence of malicious activity. The presence of multiple signatures is treated as an artifact characteristic, not automatically as proof of malware.

The investigation also considers telemetry limitations. A missing Sysmon or Wazuh result is recorded as **no matching telemetry observed**, rather than being interpreted as proof that an event never occurred. Unrelated endpoint activity is excluded when its timestamp or context does not support a relationship with the controlled artifact.

The final assessment should distinguish between **confirmed file-format characteristics, observed endpoint telemetry, execution evidence, and unresolved questions**. The objective is to demonstrate how a DFIR analyst can move beyond file extensions and use multiple independent sources of evidence to understand a suspicious or unusual file.


## Lab Objectives

- Establish a documented baseline of the Windows endpoint, user context, PowerShell environment, and investigation workspace.
- Create a controlled reference text file to establish the expected size, content, metadata, and SHA256 hash of a normal artifact.
- Create a controlled ZIP archive containing benign test data.
- Construct a controlled polyglot artifact by appending ZIP-format data to the reference file.
- Preserve the original and modified artifacts for comparative analysis.
- Compare the filenames and extensions of the reference and modified files.
- Record file size, creation time, modification time, access time, and full file paths.
- Calculate SHA256 hashes for the reference and polyglot artifacts.
- Inspect the binary structure of the polyglot artifact at the byte level.
- Identify recognizable file-format signatures within the artifact.
- Determine the exact byte offset at which the secondary ZIP signature appears.
- Compare the secondary signature location with the original reference file size.
- Extract ASCII-readable content from the artifact.
- Identify embedded filenames or format-related strings within the binary data.
- Determine whether the artifact contains additional data beyond its expected primary content.
- Examine Sysmon Event ID 11 for file creation telemetry associated with the controlled artifact.
- Examine Sysmon Event ID 1 for evidence that the artifact was executed or referenced by a process.
- Correlate available Sysmon telemetry with the artifact name, path, and investigation timeline.
- Use Wazuh endpoint telemetry to determine whether relevant Sysmon events were ingested from `DESKTOP-9MMM37V`.
- Distinguish direct artifact evidence from endpoint telemetry that cannot be conclusively attributed to the artifact.
- Review unrelated endpoint events and exclude activity that falls outside the investigation timeline.
- Determine whether the observed characteristics support a confirmed polyglot or multi-format file structure.
- Avoid interpreting the presence of multiple file signatures as automatic evidence of malware.
- Determine whether any evidence supports file execution or malicious behavior.
- Document telemetry gaps and distinguish “no matching telemetry observed” from “activity did not occur.”
- Preserve the investigation results in a reproducible evidence trail.
- Produce a final assessment that separates confirmed file characteristics, endpoint observations, and unresolved questions.

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

