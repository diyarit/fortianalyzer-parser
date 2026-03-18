# FortiAnalyzer Log Parser

Parse FortiAnalyzer traffic logs into deduplicated, ready-to-implement FortiGate firewall policies. Available as a command-line script and a WPF desktop GUI.

---

## Scripts

| File | Description |
|---|---|
| `FortiAnalyzer-Parser.ps1` | CLI — scriptable, pipeable, automation-friendly |
| `FortiAnalyzer-Parser-GUI.ps1` | WPF GUI — drag-and-drop, live log, no CLI required |

Both scripts share the same parsing engine, filter logic, and export formats.

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- No third-party modules required

---

## Setup

```powershell
git clone https://github.com/diyarit/fortianalyzer-parser.git
cd fortianalyzer-parser

# Unblock downloaded files
Unblock-File -Path .\FortiAnalyzer-Parser.ps1
Unblock-File -Path .\FortiAnalyzer-Parser-GUI.ps1

# Allow script execution (one-time, current user)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or run directly without changing policy:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\FortiAnalyzer-Parser.ps1 -LogFilePath traffic.log
```

---

## CLI Usage

```powershell
# Basic — outputs NetworkTraffic.csv
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log

# HTML report with progress
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -OutputFormat HTML -OutputFile report.html -ShowProgress

# Filter: accepted HTTPS traffic from a specific host
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -FilterSrcIP "10.1.10.2" -FilterService "443" -FilterAction "accept"

# Time range + custom subnet grouping
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -StartTime "2026-03-17 08:00:00" -EndTime "2026-03-17 18:00:00" -SubnetMask 16

# Parallel processing for large files
.\FortiAnalyzer-Parser.ps1 -LogFilePath huge.log -UseParallel -MaxThreads 8 -ShowProgress
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-LogFilePath` | *(required)* | Path to the FortiAnalyzer log file |
| `-OutputFile` | `NetworkTraffic.csv` | Output file path |
| `-OutputFormat` | `CSV` | `CSV`, `JSON`, `HTML`, or `TEXT` |
| `-SubnetMask` | `24` | CIDR prefix for IP grouping (8-32) |
| `-FilterSrcIP` | | Partial match on source IP (e.g. `10.1.10`) |
| `-FilterDstIP` | | Partial match on destination IP |
| `-FilterService` | | Port number (e.g. `443`) or partial service name (e.g. `HTTP`) |
| `-FilterAction` | | `accept` or `deny` |
| `-StartTime` | | Exclude lines before this datetime |
| `-EndTime` | | Exclude lines after this datetime |
| `-ConfigFile` | | JSON file to override built-in port mappings |
| `-UseParallel` | `false` | Enable RunspacePool parallel processing |
| `-MaxThreads` | `4` | Thread count when using `-UseParallel` (1-32) |
| `-ShowProgress` | `false` | Display live progress bar |
| `-DebugMode` | `false` | Verbose field-level debug output |

---

## GUI Usage

```powershell
PowerShell -ExecutionPolicy Bypass -File .\FortiAnalyzer-Parser-GUI.ps1
```

- **Drag and drop** a log file onto the input box to auto-populate paths and start immediately
- **Filters panel** — source IP, destination IP, service (port or name), and action; a badge shows how many filters are active
- **Cancel** — stops processing mid-file cleanly
- **Open Output Folder** — appears in the status bar after a successful run
- All processing runs in a background runspace; the UI stays responsive throughout

---

## Filtering

All filters combine with **AND** logic and are applied during parsing — excluded rows never enter memory.

**Service filter** accepts a port number or a partial service name:

| Input | Behaviour |
|---|---|
| `443` | Exact match on destination port |
| `HTTP` | Partial match on service name — matches HTTP, HTTPS, HTTP-ALT, HTTP-8080 |

**IP filters** use partial prefix matching — `192.168.1` matches any IP starting with `192.168.1`.

Active filters are printed at the start of every run and included in all report formats.

---

## Output Formats

| Format | Best for |
|---|---|
| **CSV** | Spreadsheet analysis, further data processing |
| **JSON** | API integration, scripting |
| **HTML** | Self-contained report with summary cards, colour-coded badges, XSS-safe |
| **TEXT** | Documentation, email, plain-text records |

---

## Policy Naming

```
{ACTION}_{SOURCE_INTERFACE}_TO_{DESTINATION_INTERFACE}_{SERVICE}
```

Examples: `ALLOW_INTERNAL_TO_WAN1_HTTPS` · `DENY_WAN1_TO_INTERNAL_RDP`

Names exceeding FortiGate's 35-character limit are truncated with a 5-character SHA-1 hash of the service name appended, ensuring uniqueness is preserved.

---

## Service Mappings

100+ built-in port-to-service mappings covering core internet, Microsoft, databases, virtualisation, containers, and observability tools. Unknown ports render as `TCP/PORT` or `UDP/PORT`.

Custom mappings can be added via `-ConfigFile` without modifying the script:

```json
{
  "serviceMappings": {
    "8443": "CUSTOM-PORTAL",
    "9999": "INTERNAL-APP"
  }
}
```

---

## Contributing

1. Fork, branch, commit, pull request
2. When reporting a bug, include a sanitised sample log line, the exact command used, and the full error output

