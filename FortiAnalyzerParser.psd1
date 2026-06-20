@{
    RootModule        = 'FortiAnalyzerParser.psm1'
    ModuleVersion     = '4.1.0'
    GUID              = 'a3b8c9d0-e1f2-3456-7890-abcdef123456'
    Author            = 'Diyar Abbas'
    CompanyName       = 'FortiAnalyzer Parser Project'
    Copyright         = '(c) 2026 Diyar Abbas. All rights reserved.'
    Description       = 'Shared parsing engine for FortiAnalyzer log files. Extracts network traffic patterns and generates FortiGate firewall policies.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-FAServiceName'
        'Convert-FASubnet'
        'Get-FAPolicyName'
        'Get-FALogTimestamp'
        'ConvertTo-FAHtmlSafe'
        'Test-FAServiceAction'
        'Select-FAByIPFilter'
        'Import-FAConfig'
        'Test-FAPrerequisites'
        'Write-FALog'
        'Invoke-FAParseLine'
        'Build-FATextReport'
        'Build-FAHtmlReport'
        'Get-FAExportList'
        'Get-FACombinedPattern'
        'Get-FAServicePatterns'
        'Get-FAServiceMappings'
        'Initialize-FAMetrics'
        'Find-FAShadowRules'
        'Test-FACompliance'
        'Export-FAFortiGateCLI'
        'Export-FAFortiManagerXML'
        'Compare-FARules'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @(
        '$FAServiceMappings'
        '$FAVersion'
    )

    PrivateData = @{
        PSData = @{
            Tags       = @('FortiAnalyzer', 'FortiGate', 'Firewall', 'LogParser', 'NetworkSecurity')
            LicenseUri = 'https://github.com/diyarit/fortianalyzer-parser/blob/main/LICENSE'
            ProjectUri = 'https://github.com/diyarit/fortianalyzer-parser'
        }
    }
}
