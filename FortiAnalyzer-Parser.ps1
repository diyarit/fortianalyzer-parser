<#
.SYNOPSIS
    FortiAnalyzer Log Parser - CLI
.DESCRIPTION
    Parses FortiAnalyzer log files to extract network traffic patterns and generate
    FortiGate firewall policies. Uses the shared FortiAnalyzerParser module.
.VERSION
    4.0.0
.AUTHOR
    Diyar Abbas
.NOTES
    Requires PowerShell 5.1+
    Shared engine lives in FortiAnalyzerParser.psm1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$LogFilePath,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = 'NetworkTraffic.csv',

    [Parameter(Mandatory=$false)]
    [ValidateSet('CSV','JSON','HTML','TEXT')]
    [string]$OutputFormat = 'CSV',

    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress,

    [Parameter(Mandatory=$false)]
    [switch]$DebugMode,

    [Parameter(Mandatory=$false)]
    [switch]$UseParallel,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1,32)]
    [int]$MaxThreads = 4,

    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = '',

    [Parameter(Mandatory=$false)]
    [ValidateRange(8,32)]
    [int]$SubnetMask = 24,

    [Parameter(Mandatory=$false)]
    [string]$StartTime = '',

    [Parameter(Mandatory=$false)]
    [string]$EndTime = '',

    [Parameter(Mandatory=$false)]
    [string]$FilterSrcIP = '',

    [Parameter(Mandatory=$false)]
    [string]$FilterDstIP = '',

    [Parameter(Mandatory=$false)]
    [string]$FilterService = '',

    [Parameter(Mandatory=$false)]
    [string]$FilterAction = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Load shared module ────────────────────────────────────────────────────────
$modulePath = Join-Path $PSScriptRoot 'FortiAnalyzerParser.psm1'
if (-not (Test-Path $modulePath)) {
    throw "Shared module not found: $modulePath"
}
Import-Module $modulePath -Force

# Load System.Web for HTML encoding
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Get patterns and service mappings from module
$faPatterns = Get-FAServicePatterns
$faServiceMappings = Get-FAServiceMappings

# Get version from module manifest
$manifestPath = Join-Path $PSScriptRoot 'FortiAnalyzerParser.psd1'
if (Test-Path $manifestPath) {
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction SilentlyContinue
    $displayVersion = if ($manifest) { $manifest.Version.ToString() } else { '4.0.0' }
} else {
    $displayVersion = '4.0.0'
}

$metrics = Initialize-FAMetrics

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '==================================================' -ForegroundColor Magenta
Write-Host "  FortiAnalyzer Log Parser  v$displayVersion       " -ForegroundColor Magenta
Write-Host '==================================================' -ForegroundColor Magenta
Write-Host ''

# ── Main ──────────────────────────────────────────────────────────────────────
$connections       = [System.Collections.ArrayList]::new()
$uniqueConnections = @{}

try {
    if ($ConfigFile) { Import-FAConfig -Path $ConfigFile -ServiceMappings $script:FAServiceMappings }

    $correctExt = switch ($OutputFormat.ToUpper()) {
        'JSON' { '.json' }
        'HTML' { '.html' }
        'TEXT' { '.txt'  }
        default { '.csv'  }
    }
    if ($OutputFile -match '\.(csv|json|html|txt)$') {
        $OutputFile = $OutputFile -replace '\.(csv|json|html|txt)$', $correctExt
    } else {
        $OutputFile = $OutputFile + $correctExt
    }

    Write-FALog 'Validating prerequisites...' -Metrics $metrics
    $null = Test-FAPrerequisites -LogFilePath $LogFilePath -OutputFile $OutputFile

    # Build filter summary
    $filterParts = @()
    if ($FilterSrcIP)   { $filterParts += "SrcIP = '$FilterSrcIP'" }
    if ($FilterDstIP)   { $filterParts += "DstIP = '$FilterDstIP'" }
    if ($FilterService) {
        if ($FilterService -match '^\d+$') { $filterParts += "Port = $FilterService" }
        else { $filterParts += "Service contains '$FilterService'" }
    }
    if ($FilterAction)  { $filterParts += "Action = '$FilterAction'" }
    $filterSummary = if ($filterParts.Count -gt 0) { $filterParts -join ' AND ' } else { 'None' }
    Write-FALog "Active filters: $filterSummary" -Metrics $metrics

    # ── Process ───────────────────────────────────────────────────────────
    if ($UseParallel) {
        Write-FALog "Parallel mode: $MaxThreads threads" -Metrics $metrics

        $allLines  = [System.IO.File]::ReadAllLines($LogFilePath)
        $total     = $allLines.Count
        $chunkSize = [Math]::Max(1, [Math]::Ceiling($total / $MaxThreads))

        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
        $pool.Open()

        $jobs = @()
        for ($i = 0; $i -lt $total; $i += $chunkSize) {
            $chunk     = $allLines[$i..([Math]::Min($i + $chunkSize - 1, $total - 1))]
            $startLine = $i + 1

            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool

            [void]$ps.AddScript({
                param($Chunk, $StartLine, $Patterns, $ServiceMaps, $MaskBits, $StartTime, $EndTime,
                      $FilterService, $FilterAction)

                $results = [System.Collections.ArrayList]::new()
                $lineNum = $StartLine

                foreach ($line in $Chunk) {
                    if ([string]::IsNullOrWhiteSpace($line)) { $lineNum++; continue }

                    # Early-exit fast rejection
                    $mDst = $Patterns.dstport.Match($line)
                    if (-not $mDst.Success) { $lineNum++; continue }
                    $mSrc = $Patterns.srcip.Match($line)
                    if (-not $mSrc.Success) { $lineNum++; continue }
                    $mDip = $Patterns.dstip.Match($line)
                    if (-not $mDip.Success) { $lineNum++; continue }

                    $srcip   = $mSrc.Groups[1].Value
                    $dstip   = $mDip.Groups[1].Value
                    $dstport = $mDst.Groups[1].Value

                    if (-not $Patterns.ipValid.IsMatch($srcip))  { $lineNum++; continue }
                    if (-not $Patterns.ipValid.IsMatch($dstip))  { $lineNum++; continue }
                    if (-not $Patterns.portValid.IsMatch($dstport)) { $lineNum++; continue }

                    $mSvcRaw = $Patterns.service.Match($line)
                    $serviceRaw = if ($mSvcRaw.Success) { $mSvcRaw.Groups[1].Value } else { '' }

                    $mProto = $Patterns.proto.Match($line)
                    $proto  = if ($mProto.Success) { $mProto.Groups[1].Value } else { '' }

                    # Service lookup
                    $svcName = if (-not [string]::IsNullOrWhiteSpace($serviceRaw) -and $serviceRaw -ne 'unknown') {
                        $serviceRaw.ToUpper()
                    } elseif ($ServiceMaps.ContainsKey($dstport)) {
                        $ServiceMaps[$dstport]
                    } else {
                        switch ($proto) { '6' { "TCP/$dstport" } '17' { "UDP/$dstport" } default { "PROTO${proto}/$dstport" } }
                    }

                    $mAction = $Patterns.action.Match($line)
                    $action  = if ($mAction.Success) {
                        switch ($mAction.Groups[1].Value.ToLower()) {
                            'close'      { 'accept' }
                            'accept'     { 'accept' }
                            'deny'       { 'deny'   }
                            'server-rst' { 'accept' }
                            'client-rst' { 'accept' }
                            default      { $mAction.Groups[1].Value }
                        }
                    } else { '' }

                    # Service/action filter
                    if ($FilterService) {
                        if ($FilterService -match '^\d+$') {
                            if ($dstport -ne $FilterService) { $lineNum++; continue }
                        } else {
                            $fUpper = $FilterService.ToUpper()
                            $rawUpper = $serviceRaw.ToUpper()
                            $exact = ($rawUpper -eq $fUpper) -or ($svcName -eq $fUpper)
                            $partial = ($rawUpper -like "*$fUpper*") -or ($svcName -like "*$fUpper*")
                            if (-not $exact -and -not $partial) { $lineNum++; continue }
                        }
                    }
                    if ($FilterAction -and $action -ne $FilterAction) { $lineNum++; continue }

                    $mSrcPort = $Patterns.srcport.Match($line)
                    $srcport  = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { '' }

                    $mSrcInt = $Patterns.srcintf.Match($line)
                    $srcintf = if ($mSrcInt.Success) { $mSrcInt.Groups[1].Value } else { '' }

                    $mDstInt = $Patterns.dstintf.Match($line)
                    $dstintf = if ($mDstInt.Success) { $mDstInt.Groups[1].Value } else { '' }

                    $mTran = $Patterns.trandisp.Match($line)
                    $tran  = if ($mTran.Success) { $mTran.Groups[1].Value } else { 'noop' }
                    $nat   = if ($tran -match 'snat|dnat') { 'Enabled' } else { 'Disabled' }

                    # Subnets
                    $octets = $srcip -split '\.'
                    [uint32]$ipInt = ([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16) -bor ([uint32]$octets[2] -shl 8) -bor [uint32]$octets[3]
                    [uint32]$nm    = if ($MaskBits -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - $MaskBits) }
                    [uint32]$ni    = $ipInt -band $nm
                    $srcSubnet = "$(($ni -shr 24) -band 0xFF).$(($ni -shr 16) -band 0xFF).$(($ni -shr 8) -band 0xFF).$($ni -band 0xFF)/${MaskBits}"

                    $octets2 = $dstip -split '\.'
                    [uint32]$ipInt2 = ([uint32]$octets2[0] -shl 24) -bor ([uint32]$octets2[1] -shl 16) -bor ([uint32]$octets2[2] -shl 8) -bor [uint32]$octets2[3]
                    [uint32]$ni2    = $ipInt2 -band $nm
                    $dstSubnet = "$(($ni2 -shr 24) -band 0xFF).$(($ni2 -shr 16) -band 0xFF).$(($ni2 -shr 8) -band 0xFF).$($ni2 -band 0xFF)/${MaskBits}"

                    [void]$results.Add(@{
                        SourceIP=$srcip; DestIP=$dstip; SourcePort=$srcport; DestPort=$dstport
                        Service=$serviceRaw; SourceInterface=$srcintf; DestInterface=$dstintf
                        Action=$action; Protocol=$proto; NatEnabled=$nat
                        SourceSubnet=$srcSubnet; DestSubnet=$dstSubnet; ServiceName=$svcName
                        LineNumber=$lineNum; LogTimestamp=$null
                    })
                    $lineNum++
                }
                return $results
            })

            [void]$ps.AddParameters(@{
                Chunk         = $chunk
                StartLine     = $startLine
                Patterns      = $faPatterns
                ServiceMaps   = $faServiceMappings
                MaskBits      = $SubnetMask
                StartTime     = $StartTime
                EndTime       = $EndTime
                FilterService = $FilterService
                FilterAction  = $FilterAction
            })

            $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke() }
        }

        $batchTime = [DateTime]::Now
        foreach ($job in $jobs) {
            $chunkResults = $job.PS.EndInvoke($job.Handle)
            $job.PS.Dispose()
            foreach ($conn in $chunkResults) {
                $conn.PolicyName = Get-FAPolicyName $conn
                [void]$connections.Add($conn)
                $metrics.ProcessedLines++

                $key = "$($conn.SourceSubnet)|$($conn.DestSubnet)|$($conn.ServiceName)|$($conn.SourceInterface)|$($conn.DestInterface)"
                if (-not $uniqueConnections.ContainsKey($key)) {
                    $uniqueConnections[$key] = @{ Count=0; FirstSeen=$batchTime; LastSeen=$batchTime; Connection=$conn }
                }
                $uniqueConnections[$key].Count++
                $uniqueConnections[$key].LastSeen = $batchTime
            }
        }
        $pool.Close()
        $pool.Dispose()
    }
    else {
        # Single-threaded streaming
        $lineNumber    = 0
        $skippedFilter = 0
        $progressStep  = 5000
        $batchTime     = [DateTime]::Now

        $reader = [System.IO.StreamReader]::new($LogFilePath, [System.Text.Encoding]::UTF8, $true, 65536)
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                $lineNumber++

                try {
                    $connection = Invoke-FAParseLine -Line $line -LineNumber $lineNumber -MaskBits $SubnetMask -StartTime $StartTime -EndTime $EndTime
                    if ($null -ne $connection) {
                        if (-not (Test-FAServiceAction -RawService $connection.Service -DstPort $connection.DestPort -SvcName $connection.ServiceName -Action $connection.Action -FilterService $FilterService -FilterAction $FilterAction)) {
                            $skippedFilter++
                            $metrics.SkippedLines++
                            continue
                        }

                        $connection.PolicyName = Get-FAPolicyName $connection
                        [void]$connections.Add($connection)
                        $metrics.ProcessedLines++

                        $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.ServiceName)|$($connection.SourceInterface)|$($connection.DestInterface)"
                        if (-not $uniqueConnections.ContainsKey($key)) {
                            $uniqueConnections[$key] = @{ Count=0; FirstSeen=$batchTime; LastSeen=$batchTime; Connection=$connection }
                        }
                        $uniqueConnections[$key].Count++
                        $uniqueConnections[$key].LastSeen = $batchTime
                    }
                    else { $metrics.SkippedLines++ }
                }
                catch {
                    Write-FALog "Error on line $lineNumber : $_" -Level Error -Metrics $metrics
                    $metrics.SkippedLines++
                }

                if (($lineNumber % $progressStep) -eq 0) {
                    $batchTime = [DateTime]::Now
                    if ($ShowProgress) {
                        Write-Progress -Activity 'Parsing FortiAnalyzer log' `
                            -Status "Lines: $lineNumber  |  Matched: $($uniqueConnections.Count)  |  Filtered: $skippedFilter" `
                            -PercentComplete -1
                    }
                }
            }
        }
        finally { $reader.Dispose() }

        if ($ShowProgress) { Write-Progress -Activity 'Parsing FortiAnalyzer log' -Completed }
        Write-FALog "Finished: $lineNumber lines, $($uniqueConnections.Count) matched, $skippedFilter excluded." -Metrics $metrics
    }

    if ($connections.Count -eq 0) {
        Write-FALog 'No valid connections found. Check log format or filters.' -Level Warning -Metrics $metrics
        exit 0
    }

    # ── IP filter (post-parse) ────────────────────────────────────────────
    $filteredConnections = Select-FAByIPFilter -UniqueConnections $uniqueConnections -FilterSrcIP $FilterSrcIP -FilterDstIP $FilterDstIP

    # ── Export ────────────────────────────────────────────────────────────
    $exportData = @(Get-FAExportList -UniqueConnections $filteredConnections -FilterSrcIP $FilterSrcIP -FilterDstIP $FilterDstIP)

    $totalLines   = $metrics.ProcessedLines + $metrics.SkippedLines
    $excludedLines = $metrics.SkippedLines

    switch ($OutputFormat.ToUpper()) {
        'CSV'  { $exportData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 }
        'JSON' { $exportData | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputFile -Encoding UTF8 }
        'TEXT' {
            $txt = Build-FATextReport -Data $exportData -TotalLines $totalLines -ExcludedLines $excludedLines -FilterSummary $filterSummary
            [System.IO.File]::WriteAllText($OutputFile, $txt, [System.Text.Encoding]::UTF8)
        }
        'HTML' {
            $html = Build-FAHtmlReport -Data $exportData -TotalLines $totalLines -ExcludedLines $excludedLines -FilterSummary $filterSummary
            [System.IO.File]::WriteAllText($OutputFile, $html, [System.Text.Encoding]::UTF8)
        }
    }

    # ── Summary ───────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '=== Results ===' -ForegroundColor Green
    Write-Host "Unique connection patterns : $($exportData.Count)" -ForegroundColor Cyan

    if ($exportData.Count -gt 0) {
        Write-Host ''
        Write-Host 'Top 5 policies by traffic volume:' -ForegroundColor White
        $exportData | Select-Object -First 5 | ForEach-Object {
            Write-Host ('  {0,-35} {1} -> {2}  [{3}]  {4} flows' -f `
                $_.PolicyName, $_.Source, $_.Destination, $_.Service, $_.TrafficCount) -ForegroundColor Gray
        }
    }

    $elapsed  = [Math]::Round(([DateTime]::Now - $metrics.StartTime).TotalSeconds, 2)
    $memoryMB = [Math]::Round([System.GC]::GetTotalMemory($false) / 1MB, 2)

    Write-Host ''
    Write-Host '=== Performance ===' -ForegroundColor Cyan
    Write-Host "  Total time      : ${elapsed}s"           -ForegroundColor White
    Write-Host "  Memory usage    : ${memoryMB} MB"        -ForegroundColor White
    Write-Host "  Lines processed : $($metrics.ProcessedLines.ToString('N0'))"  -ForegroundColor White
    Write-Host "  Lines skipped   : $($metrics.SkippedLines.ToString('N0'))"    -ForegroundColor White
    Write-Host "  Errors          : $($metrics.ErrorCount)"   -ForegroundColor $(if($metrics.ErrorCount -gt 0){'Red'}else{'White'})
    Write-Host "  Warnings        : $($metrics.WarningCount)" -ForegroundColor $(if($metrics.WarningCount -gt 0){'Yellow'}else{'White'})
    Write-Host ''
    Write-Host "Output saved to: $OutputFile" -ForegroundColor Yellow
    Write-Host ''
}
catch {
    Write-Host ''
    Write-Host '=== Critical Error ===' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($DebugMode) { Write-Host $_.Exception.ToString() -ForegroundColor DarkRed }
    exit 1
}
finally {
    if ($ShowProgress) { Write-Progress -Activity 'Done' -Completed }
    # SHA1 is managed by the module
}
