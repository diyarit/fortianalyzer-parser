# FortiAnalyzer Log Parser

Parse FortiAnalyzer traffic logs into deduplicated, ready-to-implement FortiGate firewall policies. Available as a CLI script and a WPF desktop GUI.

---

## What's New in v4.1

| Feature | Description |
|---|---|
| **Shared Module** | All logic extracted to `FortiAnalyzerParser.psm1` — single source of truth, no duplication |
| **Shadow Rule Detection** | Identifies redundant policies that can never be hit (FortiGate has NO native support for this) |
| **Compliance Checking** | Flags overly broad rules, high-risk services (RDP, Telnet), missing deny-all |
| **Interactive HTML Reports** | Client-side sorting, search/filter, expandable row details, charts |
| **FortiGate CLI Export** | Paste-ready `config firewall policy` snippets for direct deployment |
| **FortiManager XML Export** | Importable XML for FortiManager's "Import Policy" feature |
| **Rule Diff/Comparison** | Compare before/after policy sets — shows added, removed, modified rules |
| **Parallel Mode Filters** | All filters (IP, service, action) now work correctly in `-UseParallel` mode |
| **Performance Optimizations** | Early-exit regex, combined pattern, SHA1 reuse, removed manual GC |

---

## Architecture

```
FortiAnalyzerParser/
  FortiAnalyzerParser.psd1    Module manifest
  FortiAnalyzerParser.psm1    Shared parsing engine (all logic)
  FortiAnalyzer-Parser.ps1    CLI thin wrapper
  FortiAnalyzer-Parser-GUI.ps1  WPF GUI thin wrapper
  Tests/                      Pester unit tests (32 tests)
```

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- No third-party modules required

---

## Setup

```powershell
git clone https://github.com/diyarit/fortianalyzer-parser.git
cd fortianalyzer-parser

Unblock-File -Path .\FortiAnalyzer-Parser.ps1
Unblock-File -Path .\FortiAnalyzer-Parser-GUI.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or run directly:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\FortiAnalyzer-Parser.ps1 -LogFilePath traffic.log
```

---

## CLI Usage

```powershell
# Basic - outputs NetworkTraffic.csv
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log

# HTML report with interactive charts, sorting, and search
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -OutputFormat HTML -OutputFile report.html

# Filter: accepted HTTPS traffic from a specific host
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -FilterSrcIP "10.1.10.2" -FilterService "443" -FilterAction "accept"

# Time range + custom subnet grouping
.\FortiAnalyzer-Parser.ps1 -LogFilePath fw.log -StartTime "2026-03-17 08:00:00" -EndTime "2026-03-17 18:00:00" -SubnetMask 16

# Parallel processing for large files (all filters supported)
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

- **Drag and drop** a log file onto the input box to auto-populate and start
- **Filters panel** - source IP, destination IP, service, action; badge shows active filter count
- **Cancel** - stops processing mid-file cleanly
- **Open Output Folder** - appears in the status bar after a successful run
- All processing runs in a background runspace; UI stays responsive

---

## Filtering

All filters combine with **AND** logic and are applied during parsing - excluded rows never enter memory.

**Service filter** accepts a port number or a partial service name:

| Input | Behaviour |
|---|---|
| `443` | Exact match on destination port |
| `HTTP` | Partial match - matches HTTP, HTTPS, HTTP-ALT, HTTP-8080 |

**IP filters** use partial prefix matching - `192.168.1` matches any IP starting with `192.168.1`.

---

## Output Formats

| Format | Best for |
|---|---|
| **CSV** | Spreadsheet analysis, further data processing |
| **JSON** | API integration, scripting |
| **HTML** | Interactive report with charts, sorting, search, expandable details, print-friendly |
| **TEXT** | Documentation, email, plain-text records |

### HTML Report Features

- **Interactive sorting** - click any column header to sort ascending/descending
- **Search/filter** - type in the search box to filter rows in real-time
- **Expandable details** - click the arrow on any row to see full IPs, ports, timestamps
- **Charts** - top 10 services bar chart, action breakdown donut chart
- **Print-friendly** - clean layout with `@media print` CSS rules
- **XSS-safe** - all dynamic values are HTML-encoded

---

## Analysis Tools

### Shadow Rule Detection

Identifies redundant policies where a later rule is fully subsumed by an earlier rule:

```powershell
Import-Module .\FortiAnalyzerParser.psm1
$results = Get-FAExportList -UniqueConnections $parsedData
$shadows = @(Find-FAShadowRules -Policies $results)
$shadows | Format-Table ShadowedBy, ShadowedRule, Service
```

### Compliance Checking

Flags security issues in your policy set:

```powershell
$findings = @(Test-FACompliance -Policies $results)
$findings | Where-Object Severity -eq 'Critical' | Format-Table Type, Policy, Message
```

Checks include:
- Overly broad source/destination (0.0.0.0/0 or "any")
- High-risk services exposed (RDP, Telnet, FTP, SMB, Docker)
- RDP from non-RFC1918 sources
- Missing explicit deny-all rule
- Low-traffic deny rules (possible stale rules)

### FortiGate CLI Export

Generate paste-ready firewall policy commands:

```powershell
$cli = Export-FAFortiGateCLI -Policies $results
$cli | Set-Content -Path "policies.cli"
```

### FortiManager XML Export

Generate XML for direct import into FortiManager:

```powershell
$xml = Export-FAFortiManagerXML -Policies $results -PackageName "MyPolicyPackage"
$xml | Set-Content -Path "policies.xml"
```

### Rule Diff/Comparison

Compare two policy sets (before vs. after changes):

```powershell
$old = Get-FAExportList -UniqueConnections $oldParsedData
$new = Get-FAExportList -UniqueConnections $newParsedData
$diff = Compare-FARules -Baseline $old -Current $new
Write-Host $diff.Summary
$diff.Added   | Format-Table Policy, Source, Service
$diff.Removed | Format-Table Policy, Source, Service
```

---

## Policy Naming

```
{ACTION}_{SOURCE_INTERFACE}_TO_{DESTINATION_INTERFACE}_{SERVICE}
```

Examples: `ALLOW_INTERNAL_TO_WAN1_HTTPS` / `DENY_WAN1_TO_INTERNAL_RDP`

Names exceeding FortiGate's 35-character limit are truncated with a 5-character SHA-1 hash suffix, ensuring uniqueness.

---

## Service Mappings

100+ built-in port-to-service mappings covering core internet, Microsoft, databases, virtualisation, containers, and observability tools. Unknown ports render as `TCP/PORT` or `UDP/PORT`.

Custom mappings via `-ConfigFile`:

```json
{
  "serviceMappings": {
    "8443": "CUSTOM-PORTAL",
    "9999": "INTERNAL-APP"
  }
}
```

---

## Testing

```powershell
# Run all 32 Pester tests
Invoke-Pester -Path ./Tests

# Import module manually for interactive use
Import-Module ./FortiAnalyzerParser.psm1 -Force
Get-Command -Module FortiAnalyzerParser
```

---

## Project Structure

| File | Description |
|---|---|
| `FortiAnalyzerParser.psm1` | Shared parsing engine (all logic) |
| `FortiAnalyzerParser.psd1` | Module manifest |
| `FortiAnalyzer-Parser.ps1` | CLI thin wrapper |
| `FortiAnalyzer-Parser-GUI.ps1` | WPF GUI thin wrapper |
| `Tests/` | Pester unit tests |
| `.gitignore` | Git ignore rules |
| `AGENTS.md` | Contributor guide |

---

## Contributing

1. Fork, branch, commit, pull request
2. Run `Invoke-Pester -Path ./Tests` before committing
3. Add tests for new functions
4. All public functions must use `FA` prefix (e.g. `Get-FAServiceName`)
5. Never duplicate logic between CLI and GUI - add to the shared module
