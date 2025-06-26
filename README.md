# Windows Process Memory Scanner

A powerful C++ tool for scanning process memory of critical Windows services and processes to detect executable files, verify their signatures, and export findings for forensic analysis.

## Features

- Scans memory of critical Windows services and processes
- Detects executable file paths in memory (both standard and device paths)
- Verifies digital signatures (Authenticode and Catalog)
- Identifies deleted/missing executables
- Converts device paths (e.g., `\Device\HarddiskVolumeX`) to drive letters
- Generates comprehensive CSV reports
- Supports analysis with Timeline Explorer
- Requires and verifies Administrator privileges

## Scanned Targets

### Windows Services:
- Program Compatibility Assistant (PcaSvc)
- Connected User Experiences and Telemetry (DiagTrack)
- Windows Search (WSearch)
- Windows Defender (WinDefend)
- Windows Update (wuauserv)
- Event Log (EventLog)
- Task Scheduler (Schedule)

### Critical Processes:
- explorer.exe
- svchost.exe (with service name identification)
- dllhost.exe
- lsass.exe
- csrss.exe
- winlogon.exe
- services.exe
- spoolsv.exe

## Detection Capabilities

- Finds paths to executable files in process memory:
  - .exe, .dll, .sys
  - .cmd, .bat, .ps1
  - .msi, .com
- Handles both regular paths (`C:\path\to\file.exe`) and device paths (`\Device\HarddiskVolumeX\path\to\file.exe`)

## Signature Verification

Each found executable is checked for:
- Authenticode signatures (standard PE signatures)
- Catalog signatures (Windows Defender signatures)
- File existence (marks as "DELETED" if missing)
- Invalid signatures (failed verification)
