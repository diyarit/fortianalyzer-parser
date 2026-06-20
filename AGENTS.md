# FortiAnalyzer Parser - Contributor Guide

## Build & Test
```powershell
# Run Pester tests
Invoke-Pester -Path ./Tests -Output Detailed

# Import module manually
Import-Module ./FortiAnalyzerParser.psm1 -Force

# Run CLI
./FortiAnalyzer-Parser.ps1 -LogFilePath sample.log -OutputFormat HTML
```

## Architecture
- `FortiAnalyzerParser.psm1` — shared parsing engine (all logic lives here)
- `FortiAnalyzerParser.psd1` — module manifest
- `FortiAnalyzer-Parser.ps1` — CLI thin wrapper
- `FortiAnalyzer-Parser-GUI.ps1` — WPF GUI thin wrapper
- `Tests/` — Pester unit tests

## Conventions
- All public functions use `FA` prefix (e.g. `Get-FAServiceName`)
- Version is defined once in `$script:FAVersion` inside the `.psm1`
- Never duplicate logic between CLI and GUI — add to the shared module
- Run `Invoke-Pester` before committing
