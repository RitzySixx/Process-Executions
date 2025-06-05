# ProcessMemoryScanner - File Path Analyzer

A Windows forensic tool that scans process memory to discover file paths and detect potentially deleted files. Useful for incident response, malware analysis, and digital forensics investigations.

## 🔍 Overview

ProcessMemoryScanner analyzes the memory of running processes and Windows services to extract file paths, then checks if those files still exist on disk. This helps identify recently deleted files, temporary artifacts, and potential evidence of malicious activity.

## ✨ Features

- **Memory Scanning** - Extracts file paths from process memory spaces
- **Service Analysis** - Scans critical Windows services for file references
- **File Existence Check** - Verifies if discovered files are present or deleted
- **Duplicate Filtering** - Shows unique paths per process to avoid redundancy
- **Color-Coded Output** - Visual indicators for present/deleted files
- **Export Functionality** - Save results to timestamped text files
- **Service Name Resolution** - Identifies specific services running under svchost.exe

## 🎯 Target Processes & Services

### Windows Services
- **PcaSvc** - Program Compatibility Assistant
- **DiagTrack** - Connected User Experiences and Telemetry  
- **WSearch** - Windows Search
- **WinDefend** - Windows Defender
- **wuauserv** - Windows Update
- **EventLog** - Windows Event Log
- **Schedule** - Task Scheduler

### Critical Processes
- `explorer.exe`, `svchost.exe`, `dllhost.exe`
- `lsass.exe`, `csrss.exe`, `winlogon.exe`
- `services.exe`, `spoolsv.exe`

## 🚀 Usage

```bash
ProcessMemoryScanner.exe
```

**Requirements**: Run as Administrator for full memory access privileges.

## 📊 Output Format

```
========== WinDefend (PID: 1234) ==========
[PRESENT] (12/15/2023 14:30) C:\Windows\System32\MpSvc.dll
[DELETED]                    C:\Temp\suspicious_file.exe
[PRESENT] (12/14/2023 09:15) C:\Program Files\Windows Defender\MsMpEng.exe
```

## 🔧 File Type Detection

Scans for executable and script files:
- **Executables**: `.exe`, `.dll`, `.sys`, `.com`
- **Scripts**: `.cmd`, `.bat`, `.ps1`
- **Installers**: `.msi`

## 📈 Use Cases

- **Malware Analysis** - Discover deleted malware components
- **Incident Response** - Find traces of attacker tools
- **Digital Forensics** - Recover evidence of file execution
- **System Monitoring** - Track file system changes
- **Compliance Auditing** - Verify software installations

## 📋 Requirements

- Windows 7/Server 2008 or later
- Administrator privileges (required)
- Visual C++ Runtime
- Minimum 4GB RAM (recommended for large memory scans)

## 🔧 Compilation

```bash
cl /EHsc ProcessMemoryScanner.cpp -o ProcessMemoryScanner.exe
```

## 📄 Output Files

- **Console**: Real-time colored output with file status
- **Export**: `ProcessMemoryScan_[timestamp].txt` - Complete results
- **Summary**: File counts and analysis statistics

## ⚠️ Security Notice

This tool performs deep memory analysis and requires elevated privileges. Use only for legitimate forensic, security, and administrative purposes. Ensure proper authorization before deployment.

## 🛡️ Privacy Considerations

Memory scanning may reveal sensitive file paths and system information. Handle results appropriately and follow your organization's data protection policies.

## 📝 License

Designed for professional forensic and security analysis. Use in compliance with applicable laws and organizational policies.
