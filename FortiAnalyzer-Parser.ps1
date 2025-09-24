<#
.SYNOPSIS
    FortiAnalyzer Log Parser
.DESCRIPTION
    Parses FortiAnalyzer logs and extracts network traffic patterns for analysis.
    Exports connection data to CSV format for further review and analysis.
.AUTHOR
    Diyar Abbas
.VERSION
    2.0
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true)]
    [string]$LogFilePath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "NetworkTraffic.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress
)

# Regex patterns for parsing FortiAnalyzer logs
$patterns = @{
    srcip = 'srcip=(\d+\.\d+\.\d+\.\d+)'
    dstip = 'dstip=(\d+\.\d+\.\d+\.\d+)'
    srcport = 'srcport=(\d+)'
    dstport = 'dstport=(\d+)'
    service = 'service="([^"]+)"'
    srcintf = 'srcintf="([^"]+)"'
    dstintf = 'dstintf="([^"]+)"'
    action = 'action="([^"]+)"'
    proto = 'proto=(\d+)'
}

# Service name mappings for common ports
$serviceMappings = @{
    '53' = 'DNS'
    '80' = 'HTTP'
    '443' = 'HTTPS'
    '135' = 'DCE-RPC'
    '3389' = 'RDP'
    '9100' = 'TCP-9100'
    '7680' = 'tcp/7680'
    '9396' = 'VeeamConsole'
}

# Initialize collections
$connections = [System.Collections.ArrayList]::new()
$uniqueConnections = @{}

function Convert-ToSubnet {
    param([string]$ipAddress)
    
    $octets = $ipAddress -split '\.'
    if ($octets.Count -eq 4) {
        return "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
    }
    return $ipAddress
}

function Get-ServiceName {
    param([string]$port, [string]$protocol)
    
    if ($serviceMappings.ContainsKey($port)) {
        return $serviceMappings[$port]
    }
    return "tcp/$port"
}

function Parse-LogFile {
    param([string]$filePath)
    
    if ($ShowProgress) { Write-Host "Parsing log file: $filePath" -ForegroundColor Green }
    
    $lineCount = 0
    $totalLines = 0
    
    # Get total lines efficiently
    if ($ShowProgress) {
        $totalLines = (Get-Content $filePath -ReadCount 1000 | Measure-Object).Count
    }
    
    Get-Content $filePath -ReadCount 1000 | ForEach-Object {
        foreach ($line in $_) {
            $lineCount++
            
            if ($ShowProgress -and $lineCount % 1000 -eq 0) {
                $percent = if ($totalLines -gt 0) { [Math]::Min(($lineCount/$totalLines*100), 100) } else { 0 }
                Write-Progress -Activity "Parsing logs" -Status "Progress: $lineCount/$totalLines" -PercentComplete $percent
            }
        
            # Extract fields using regex
            $srcip = if ($line -match $patterns.srcip) { $Matches[1] } else { $null }
            $dstip = if ($line -match $patterns.dstip) { $Matches[1] } else { $null }
            $srcport = if ($line -match $patterns.srcport) { $Matches[1] } else { $null }
            $dstport = if ($line -match $patterns.dstport) { $Matches[1] } else { $null }
            $service = if ($line -match $patterns.service) { $Matches[1] } else { $null }
            $srcintf = if ($line -match $patterns.srcintf) { $Matches[1] } else { $null }
            $dstintf = if ($line -match $patterns.dstintf) { $Matches[1] } else { $null }
            $action = if ($line -match $patterns.action) { $Matches[1] } else { $null }
            $proto = if ($line -match $patterns.proto) { $Matches[1] } else { $null }
            
            # Skip if essential fields are missing
            if (-not $srcip -or -not $dstip -or -not $dstport) { continue }
            
            # Determine service name
            $serviceName = if ($service) { $service } else { Get-ServiceName $dstport $proto }
            
            # Create connection object
            $connection = [PSCustomObject]@{
                SourceIP = $srcip
                DestIP = $dstip
                SourcePort = $srcport
                DestPort = $dstport
                Service = $serviceName
                SourceInterface = if ($srcintf) { $srcintf } else { "unknown" }
                DestInterface = if ($dstintf) { $dstintf } else { "unknown" }
                Protocol = $proto
                Action = $action
                SourceSubnet = Convert-ToSubnet $srcip
                DestSubnet = Convert-ToSubnet $dstip
            }
            
            [void]$connections.Add($connection)
        
            # Create unique connection key
            $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.Service)|$($connection.SourceInterface)|$($connection.DestInterface)"
            
            if (-not $uniqueConnections.ContainsKey($key)) {
                $uniqueConnections[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                    Connection = $connection
                }
            }
            
            $uniqueConnections[$key].Count++
            $uniqueConnections[$key].LastSeen = Get-Date
        }
    }
    
    if ($ShowProgress) { Write-Host "Parsed $($connections.Count) connections, found $($uniqueConnections.Count) unique patterns" -ForegroundColor Green }
}

function Export-NetworkData {
    if ($ShowProgress) { Write-Host "Preparing network data for export..." -ForegroundColor Cyan }
    
    $exportData = [System.Collections.ArrayList]::new()
    
    foreach ($item in $uniqueConnections.GetEnumerator()) {
        $data = $item.Value
        $conn = $data.Connection
        
        $record = [PSCustomObject]@{
            SourceIP = $conn.SourceIP
            DestinationIP = $conn.DestIP
            SourcePort = $conn.SourcePort
            DestinationPort = $conn.DestPort
            Service = $conn.Service
            SourceInterface = $conn.SourceInterface
            DestinationInterface = $conn.DestInterface
            Protocol = $conn.Protocol
            Action = $conn.Action
            SourceSubnet = $conn.SourceSubnet
            DestinationSubnet = $conn.DestSubnet
            ConnectionCount = $data.Count
            FirstSeen = $data.FirstSeen
            LastSeen = $data.LastSeen
        }
        
        [void]$exportData.Add($record)
    }
    
    return $exportData | Sort-Object ConnectionCount -Descending
}

# Main execution
try {
    Write-Host "=== FortiAnalyzer Log Parser ===" -ForegroundColor Magenta
    
    # Validate input file
    if (-not (Test-Path $LogFilePath)) {
        throw "Log file not found: $LogFilePath"
    }
    
    # Parse log file
    Parse-LogFile -filePath $LogFilePath
    
    # Export network data
    $networkData = Export-NetworkData
    
    # Display results
    Write-Host "`n=== Network Traffic Analysis ===" -ForegroundColor Green
    $networkData | Select-Object -First 10 | Format-Table -AutoSize
    
    # Export to CSV file
    $networkData | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Host "`nNetwork data exported to: $OutputFile" -ForegroundColor Yellow
    
    # Summary statistics
    Write-Host "`n=== Summary ===" -ForegroundColor Magenta
    Write-Host "Total connections parsed: $($connections.Count)" -ForegroundColor White
    Write-Host "Unique connection patterns: $($uniqueConnections.Count)" -ForegroundColor White
    Write-Host "Top services by connection count:" -ForegroundColor White
    
    $topServices = $networkData | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 5
    foreach ($service in $topServices) {
        Write-Host "  $($service.Name): $($service.Count) patterns" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Error: $_"
    exit 1
}