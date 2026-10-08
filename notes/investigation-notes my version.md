# Investigation Notes

## 1. Investigation Setup

A dedicated investigation workspace was created:

```text
C:\PolyglotFileLab\Evidence
```

The directory was successfully created and verified.

Baseline information was collected for the investigation time, Windows host, user context, and PowerShell environment.

Host:

```text
DESKTOP-9MMM37V
```

The investigation was performed on Windows using PowerShell 7.6.6.

## 2. Reference File Creation

A controlled text file was created:

```text
C:\PolyglotFileLab\invoice.txt
```

Content:

```text
Controlled Polyglot File Investigation
```

File metadata:

| Property | Value |
|---|---|
| Name | `invoice.txt` |
| Size | 40 bytes |
| Creation Time | 08-10-2026 07:28:27 |
| Last Write Time | 08-10-2026 07:28:27 |

The reference file was intentionally simple so that changes introduced during construction of the test artifact could be measured.

## 3. Controlled ZIP Creation

A second controlled file was created:

```text
C:\PolyglotFileLab\ArchiveContent.txt
```

The file was compressed into:

```text
C:\PolyglotFileLab\EmbeddedData.zip
```

Archive metadata:

| Property | Value |
|---|---|
| Name | `EmbeddedData.zip` |
| Size | 173 bytes |
| Creation Time | 08-10-2026 07:29:58 |
| Last Write Time | 08-10-2026 07:29:58 |

The archive contained controlled content and was not a malicious sample.

## 4. Polyglot Artifact Construction

A copy of the reference text file was created:

```text
C:\PolyglotFileLab\invoice-polyglot.txt
```

The ZIP bytes were then appended to the file.

The resulting artifact retained the `.txt` extension while containing additional ZIP-format data.

This was a controlled demonstration of multi-format file characteristics.

## 5. File Size Comparison

The reference file was:

```text
40 bytes
```

The resulting artifact was:

```text
213 bytes
```

The difference is consistent with the ZIP data appended to the original file.

This provides a controlled explanation for the larger file size.

## 6. Hash Analysis

The reference file SHA256 was:

```text
0A7C3F48B8138D6E706C1D57426D8A2FD7FECEDCBC5BAA9CD71CDB1D6E33FBD1
```

The polyglot artifact SHA256 was:

```text
B73368FD011D7B1D2DB527B6BF7AAABAF4DB72F8CEBBDA4D957DCC01431F5A67
```

The different hashes confirm that the modified artifact is a different byte sequence from the original reference file.

## 7. Artifact Metadata

The resulting file was identified as:

```text
Name: invoice-polyglot.txt
Extension: .txt
Length: 213 bytes
Path: C:\PolyglotFileLab\invoice-polyglot.txt
```

Recorded timestamps:

```text
CreationTime: 08-10-2026 07:31:20
LastWriteTime: 08-10-2026 07:31:33
```

The `.txt` extension does not reveal the additional ZIP data.

## 8. Byte-Level Analysis

The complete artifact was loaded as a byte array and searched for the ZIP local file header signature:

```text
50 4B 03 04
```

The signature was identified at:

```text
Byte offset: 40
```

This is significant because the original text file was exactly 40 bytes.

The evidence therefore supports the following structure:

```text
Bytes 0–39
└── Original controlled text content

Byte 40 onward
└── Appended ZIP-format data
```

This is direct evidence of the controlled multi-format structure.

## 9. ASCII String Analysis

The artifact was converted into an ASCII representation.

Relevant strings included:

```text
Controlled Polyglot File Investigation
ArchiveContent.txt
PK
```

`ArchiveContent.txt` and the ZIP-related `PK` content are consistent with the controlled archive that was appended to the artifact.

Because the ZIP data is compressed, the entire archive content is not expected to appear as readable ASCII.

## 10. Sysmon Process Creation Analysis

A Sysmon Event ID 1 query searched for:

```text
invoice-polyglot
```

No matching result was displayed.

Therefore:

```text
Artifact execution was not confirmed.
```

This does not prove that the file was never executed. It only means that the supplied Sysmon query did not produce a matching Event ID 1 result.

## 11. Sysmon File Creation Analysis

A Sysmon Event ID 11 query searched for:

```text
invoice-polyglot
```

No result was displayed directly in the PowerShell output.

However, Wazuh contained Sysmon telemetry showing:

```text
Channel: Microsoft-Windows-Sysmon/Operational
Computer: DESKTOP-9MMM37V
Event ID: 11
Event Record ID: 1130809
```

This confirms that Sysmon Event ID 11 telemetry is being collected and ingested by Wazuh.

The exact event-to-artifact relationship should not be claimed beyond the available fields because the complete Wazuh event message was not provided.

## 12. Wazuh Correlation

Endpoint-specific Wazuh searches should use:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

The investigation should prioritize:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND "invoice-polyglot.txt"
```

and:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"11" AND "invoice-polyglot.txt"
```

and:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"1" AND "invoice-polyglot.txt"
```

The provided evidence confirms Event ID 11 telemetry in Wazuh but does not confirm execution of the artifact.

## 13. Unrelated Event Review

Task Scheduler Event ID 100 events were also observed.

One event referenced:

```text
\Microsoft\Windows\Flighting\OneSettings\RefreshCache
```

The event timestamp was:

```text
28-07-2026 07:20:06
```

The polyglot investigation occurred on:

```text
08-10-2026
```

The Task Scheduler activity is therefore outside the investigation window and is not considered evidence related to the polyglot artifact.

