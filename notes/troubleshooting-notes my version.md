# Troubleshooting Notes

## 1. Sysmon Event ID 1 Returned No Result

### Observation

The following query was used:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "invoice-polyglot"
} |
Select-Object TimeCreated, Id, Message |
Format-List
```

No matching result was displayed.

### Interpretation

This does not prove that the artifact was never executed.

The query only establishes that no matching Sysmon Event ID 1 record containing the searched filename was returned.

Possible explanations include:

- The file was not executed.
- The filename was not present in the process command line.
- The artifact was accessed by another application without appearing in the query.
- Relevant telemetry was outside the selected event range.
- The process creation event did not contain the filename.

### Investigation Impact

Execution remains:

```text
NOT CONFIRMED
```

The result should not be converted into:

```text
File was never executed.
```

## 2. Sysmon Event ID 11 PowerShell Query Returned No Result

### Observation

The investigation searched Sysmon Event ID 11 for:

```text
invoice-polyglot
```

No result was displayed directly in PowerShell.

### Additional Evidence

Wazuh contained Sysmon telemetry with:

```text
Channel: Microsoft-Windows-Sysmon/Operational
Computer: DESKTOP-9MMM37V
Event ID: 11
Event Record ID: 1130809
```

### Interpretation

Sysmon Event ID 11 telemetry is available through Wazuh, but the provided evidence does not contain enough event fields to definitively establish that Event Record ID `1130809` corresponds to `invoice-polyglot.txt`.

### Investigation Impact

The correct conclusion is:

```text
Sysmon Event ID 11 telemetry was observed through Wazuh, but direct artifact attribution was not fully established from the available event fields.
```

## 3. File Extension Did Not Reveal the Complete Structure

### Observation

The investigated file was:

```text
invoice-polyglot.txt
```

Its extension was:

```text
.txt
```

However, byte-level inspection found:

```text
50 4B 03 04
```

at:

```text
byte offset 40
```

### Interpretation

The extension describes how the file is named, not everything contained within the file.

The additional ZIP signature demonstrates why file-format investigations should include byte-level analysis.

## 4. File Size Difference

### Observation

Reference file:

```text
40 bytes
```

Polyglot artifact:

```text
213 bytes
```

### Explanation

The ZIP archive was intentionally appended to the 40-byte reference file.

Therefore, the size increase is expected and does not independently indicate malicious manipulation.

## 5. ASCII Output Contained Garbled Characters

### Observation

The ASCII extraction produced readable text mixed with non-readable characters:

```text
Controlled Polyglot File Investigation
P?;H]?C?5'%ArchiveContent.txt...
```

### Explanation

The ZIP archive contains compressed binary data. Interpreting binary data directly as ASCII naturally produces non-readable characters.

### Investigation Impact

The presence of garbled characters is not itself suspicious.

The useful evidence was the presence of recognizable strings such as:

```text
ArchiveContent.txt
PK
```

combined with the independently confirmed ZIP signature.

## 6. Task Scheduler Events Appeared During Review

### Observation

Task Scheduler Event ID 100 events were present, including:

```text
\Microsoft\Windows\Flighting\OneSettings\RefreshCache
```

### Interpretation

The event occurred on:

```text
28-07-2026
```

while the polyglot investigation occurred on:

```text
08-10-2026
```

### Resolution

The Task Scheduler activity was excluded from the investigation because it falls outside the relevant timeline.

This is an important DFIR practice: not every event returned by a host query belongs to the investigation.

## 7. Avoiding Overclassification

### Potential Mistake

A file containing two recognizable format signatures could be immediately labeled:

```text
Malware
```

### Correct Approach

The evidence only establishes:

```text
Multiple file-format characteristics
```

Additional evidence would be required to establish maliciousness, such as:

- malicious executable content
- security-product detection
- suspicious execution
- process injection
- persistence
- network communication
- malicious script content
- other independent indicators of compromise

The controlled artifact intentionally contains ZIP data, so maliciousness is not supported by the current evidence.

## 8. Recommended Wazuh Troubleshooting Query

Start broad:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND "invoice-polyglot.txt"
```

Then narrow to Sysmon Event ID 11:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"11" AND "invoice-polyglot.txt"
```

Then check process creation:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"1" AND "invoice-polyglot.txt"
```

Finally, search the complete investigation directory:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND "C:\\PolyglotFileLab"
```

