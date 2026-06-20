<#
.SYNOPSIS
    FortiAnalyzer Parser - Shared Module
.DESCRIPTION
    Core parsing engine shared between CLI and GUI scripts.
    Do not run this file directly - import it via Import-Module or from the CLI/GUI scripts.
.VERSION
    4.0.0
#>

# -- Version (single source of truth) ------------------------------------------
$script:FAVersion = '4.1.0'

# -- Service Mappings ----------------------------------------------------------
$script:FAServiceMappings = @{
    '13'='DAYTIME';'20'='FTP-DATA';'21'='FTP';'22'='SSH';'23'='TELNET'
    '25'='SMTP';'37'='TIME';'53'='DNS';'67'='DHCP-SERVER';'68'='DHCP-CLIENT'
    '69'='TFTP';'79'='FINGER';'80'='HTTP';'110'='POP3';'111'='PORTMAPPER'
    '119'='NNTP';'123'='NTP';'143'='IMAP';'161'='SNMP';'162'='SNMP-TRAP'
    '179'='BGP';'194'='IRC';'199'='SMUX';'220'='IMAP3';'389'='LDAP'
    '443'='HTTPS';'465'='SMTPS';'500'='ISAKMP';'514'='SYSLOG';'515'='LPR'
    '520'='RIP';'521'='RIPNG';'587'='SMTP-SUBMISSION';'631'='IPP'
    '636'='LDAPS';'646'='LDP';'873'='RSYNC';'989'='FTPS-DATA';'990'='FTPS'
    '993'='IMAPS';'995'='POP3S';'1080'='SOCKS';'1194'='OPENVPN'
    '1645'='RADIUS-AUTH-OLD';'1646'='RADIUS-ACCT-OLD';'1720'='H323'
    '1723'='PPTP';'1812'='RADIUS-AUTH';'1813'='RADIUS-ACCT'
    '135'='MS-RPC';'137'='NETBIOS-NS';'138'='NETBIOS-DGM';'139'='NETBIOS-SSN'
    '445'='SMB';'1433'='MSSQL';'1434'='MSSQL-MONITOR';'3389'='RDP'
    '5985'='WINRM-HTTP';'5986'='WINRM-HTTPS'
    '1521'='ORACLE';'1522'='ORACLE-TNS';'3306'='MYSQL';'5432'='POSTGRESQL'
    '6379'='REDIS';'27017'='MONGODB';'9042'='CASSANDRA';'7000'='CASSANDRA-INTER'
    '11211'='MEMCACHED'
    '3000'='GRAFANA';'4000'='HTTP-4000';'5000'='DOCKER-REGISTRY'
    '8000'='HTTP-8000';'8008'='HTTP-8080';'8080'='HTTP-ALT';'8081'='NEXUS'
    '8086'='INFLUXDB';'8443'='HTTPS-ALT';'9000'='SONARQUBE';'9090'='PROMETHEUS'
    '9100'='PROMETHEUS-NODE'
    '902'='VMWARE-AUTH';'903'='VMWARE-CONSOLE';'5480'='VCENTER-MGMT'
    '8006'='PROXMOX';'16509'='LIBVIRT';'2375'='DOCKER-DAEMON';'2376'='DOCKER-DAEMON-TLS'
    '6443'='KUBERNETES-API';'10250'='KUBELET';'2379'='ETCD-CLIENT';'2380'='ETCD-PEER'
    '9200'='ELASTICSEARCH';'9300'='ELASTICSEARCH-TRANSPORT';'5601'='KIBANA'
    '5044'='LOGSTASH';'8200'='VAULT';'8500'='CONSUL'
}

# -- Compiled Regex Patterns (superset of CLI + GUI) --------------------------
$script:FAPatterns = @{
    srcip    = [regex]::new('srcip=(\d+\.\d+\.\d+\.\d+)',                          [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstip    = [regex]::new('dstip=(\d+\.\d+\.\d+\.\d+)',                          [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcport  = [regex]::new('srcport=(\d+)',                                         [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstport  = [regex]::new('dstport=(\d+)',                                         [System.Text.RegularExpressions.RegexOptions]::Compiled)
    service  = [regex]::new('service="([^"]*)"',                                     [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcintf  = [regex]::new('srcintf="([^"]*)"',                                     [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstintf  = [regex]::new('dstintf="([^"]*)"',                                     [System.Text.RegularExpressions.RegexOptions]::Compiled)
    action   = [regex]::new('action="([^"]*)"',                                      [System.Text.RegularExpressions.RegexOptions]::Compiled)
    proto    = [regex]::new('proto=(\d+)',                                           [System.Text.RegularExpressions.RegexOptions]::Compiled)
    trandisp = [regex]::new('trandisp="?([^"\s]+)"?',                               [System.Text.RegularExpressions.RegexOptions]::Compiled)
    logdate  = [regex]::new('date=(\d{4}-\d{2}-\d{2})',                             [System.Text.RegularExpressions.RegexOptions]::Compiled)
    logtime  = [regex]::new('time=(\d{2}:\d{2}:\d{2})',                             [System.Text.RegularExpressions.RegexOptions]::Compiled)
    ipValid  = [regex]::new('^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    portValid= [regex]::new('^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

# -- Single combined pattern for one-pass parsing ------------------------------
$script:FACombinedPattern = [regex]::new(
    'srcip=(?<srcip>\d+\.\d+\.\d+\.\d+).*?dstip=(?<dstip>\d+\.\d+\.\d+\.\d+)' +
    '.*?(?:srcport=(?<srcport>\d+))?' +
    '.*?dstport=(?<dstport>\d+)' +
    '.*?(?:service="(?<service>[^"]*)")?' +
    '.*?(?:srcintf="(?<srcintf>[^"]*)")?' +
    '.*?(?:dstintf="(?<dstintf>[^"]*)")?' +
    '.*?(?:action="(?<action>[^"]*)")?' +
    '.*?(?:proto=(?<proto>\d+))?' +
    '.*?(?:trandisp="?(?<trandisp>[^"\s]+)"?)?' +
    '.*?(?:date=(?<logdate>\d{4}-\d{2}-\d{2}))?' +
    '.*?(?:time=(?<logtime>\d{2}:\d{2}:\d{2}))?',
    [System.Text.RegularExpressions.RegexOptions]::Compiled -bor
    [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture
)

# -- SHA1 instance (reused, disposed by caller) --------------------------------
$script:FASHA1 = $null

# -- Metrics -------------------------------------------------------------------
function Initialize-FAMetrics {
    [PSCustomObject]@{
        StartTime      = [DateTime]::Now
        ProcessedLines = 0
        SkippedLines   = 0
        ErrorCount     = 0
        WarningCount   = 0
    }
}

# -- Logging -------------------------------------------------------------------
function Write-FALog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info','Warning','Error','Debug')][string]$Level = 'Info',
        [PSCustomObject]$Metrics,
        [switch]$DebugMode
    )
    $ts  = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $msg = "[$ts] [$Level] $Message"
    switch ($Level) {
        'Error'   { Write-Host $msg -ForegroundColor Red;    if ($Metrics) { $Metrics.ErrorCount++ } }
        'Warning' { Write-Host $msg -ForegroundColor Yellow; if ($Metrics) { $Metrics.WarningCount++ } }
        'Debug'   { if ($DebugMode) { Write-Host $msg -ForegroundColor Cyan } }
        default   { Write-Host $msg -ForegroundColor White }
    }
}

# -- Config File Loader -------------------------------------------------------
function Import-FAConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$ServiceMappings
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return }
    try {
        $cfg = Get-Content $Path -Raw | ConvertFrom-Json
        if ($cfg.serviceMappings) {
            foreach ($prop in $cfg.serviceMappings.PSObject.Properties) {
                $ServiceMappings[$prop.Name] = $prop.Value
            }
        }
    }
    catch {
        Write-Warning "Failed to load config file '$Path': $_"
    }
}

# -- Prerequisite Validation --------------------------------------------------
function Test-FAPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogFilePath,
        [Parameter(Mandatory)][string]$OutputFile
    )
    if (-not (Test-Path $LogFilePath)) { throw "Log file not found: $LogFilePath" }

    $fileInfo = Get-Item $LogFilePath
    if ($fileInfo.Length -eq 0) { throw "Log file is empty: $LogFilePath" }

    $fileSizeMB = [Math]::Round($fileInfo.Length / 1MB, 2)
    if ($fileSizeMB -gt 500) {
        Write-Warning "Large file detected (${fileSizeMB} MB). Consider using parallel processing."
    }

    $outputDir = Split-Path $OutputFile -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    return $fileSizeMB
}

# -- Service Name Resolution --------------------------------------------------
function Get-FAServiceName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Port,
        [string]$Protocol = '',
        [string]$ServiceHint = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($ServiceHint) -and $ServiceHint -ne 'unknown') {
        return $ServiceHint.ToUpper()
    }
    if ($script:FAServiceMappings.ContainsKey($Port)) {
        return $script:FAServiceMappings[$Port]
    }
    switch ($Protocol) {
        '6'   { return "TCP/$Port" }
        '17'  { return "UDP/$Port" }
        default { return "PROTO${Protocol}/$Port" }
    }
}

# -- Subnet Conversion --------------------------------------------------------
function Convert-FASubnet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][int]$MaskBits
    )
    try {
        $octets = $IPAddress -split '\.'
        if ($octets.Count -ne 4) { return $IPAddress }

        [uint32]$ipInt   = ([uint32]$octets[0] -shl 24) -bor
                           ([uint32]$octets[1] -shl 16) -bor
                           ([uint32]$octets[2] -shl 8)  -bor
                           [uint32]$octets[3]
        [uint32]$netMask = if ($MaskBits -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - $MaskBits) }
        [uint32]$netInt  = $ipInt -band $netMask

        $a = ($netInt -shr 24) -band 0xFF
        $b = ($netInt -shr 16) -band 0xFF
        $c = ($netInt -shr 8)  -band 0xFF
        $d =  $netInt           -band 0xFF
        return "${a}.${b}.${c}.${d}/${MaskBits}"
    }
    catch {
        return $IPAddress
    }
}

# -- Policy Name Generation (collision-safe) ----------------------------------
function Get-FAPolicyName {
    [CmdletBinding()]
    param([hashtable]$Connection)

    $actionPrefix = if ($Connection.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
    $sourceIntf   = ($Connection.SourceInterface -replace '[^a-zA-Z0-9]','_').ToUpper()
    $destIntf     = ($Connection.DestInterface   -replace '[^a-zA-Z0-9]','_').ToUpper()
    $serviceClean = $Connection.ServiceName      -replace '[^a-zA-Z0-9]','_'

    $fullName = "${actionPrefix}_${sourceIntf}_TO_${destIntf}_${serviceClean}"
    if ($fullName.Length -le 35) { return $fullName }

    if ($null -eq $script:FASHA1) {
        $script:FASHA1 = [System.Security.Cryptography.SHA1]::Create()
    }
    $hashBytes = $script:FASHA1.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($serviceClean)
    )
    $shortHash = ([System.BitConverter]::ToString($hashBytes) -replace '-','').Substring(0,5)
    $shortened = "${actionPrefix}_${sourceIntf}_TO_${destIntf}_${shortHash}"
    if ($shortened.Length -gt 35) { $shortened = $shortened.Substring(0,35) }
    return $shortened
}

# -- Log Timestamp Extraction -------------------------------------------------
function Get-FALogTimestamp {
    [CmdletBinding()]
    param([string]$Line)
    try {
        $dm = $script:FAPatterns.logdate.Match($Line)
        $tm = $script:FAPatterns.logtime.Match($Line)
        if ($dm.Success -and $tm.Success) {
            return [datetime]::Parse("$($dm.Groups[1].Value) $($tm.Groups[1].Value)")
        }
    }
    catch { }
    return $null
}

# -- HTML Encoding -------------------------------------------------------------
function ConvertTo-FAHtmlSafe {
    [CmdletBinding()]
    param([string]$Value)
    return [System.Web.HttpUtility]::HtmlEncode($Value)
}

# -- Action Normalization ------------------------------------------------------
function ConvertTo-FAAction {
    [CmdletBinding()]
    param([string]$RawAction)
    switch ($RawAction.ToLower()) {
        'close'      { return 'accept' }
        'accept'     { return 'accept' }
        'deny'       { return 'deny' }
        'server-rst' { return 'accept' }
        'client-rst' { return 'accept' }
        default      { return $RawAction }
    }
}

# -- Service/Action Filter ----------------------------------------------------
function Test-FAServiceAction {
    <#
    .SYNOPSIS
        Returns $true if the connection passes service and action filters.
        Applied during parse for efficiency. IP filtering is separate (post-parse).
    .PARAMETER FilterService
        All-digit = exact port match. Text = partial match on service name.
    #>
    [CmdletBinding()]
    param(
        [string]$RawService,
        [string]$DstPort,
        [string]$SvcName,
        [string]$Action,
        [string]$FilterService,
        [string]$FilterAction
    )
    if ($FilterService) {
        if ($FilterService -match '^\d+$') {
            if ($DstPort -ne $FilterService) { return $false }
        }
        else {
            $fUpper   = $FilterService.ToUpper()
            $rawUpper = $RawService.ToUpper()
            $exactMatch   = ($rawUpper -eq $fUpper) -or ($SvcName -eq $fUpper)
            $partialMatch = ($rawUpper -like "*$fUpper*") -or ($SvcName -like "*$fUpper*")
            if (-not $exactMatch -and -not $partialMatch) { return $false }
        }
    }
    if ($FilterAction -and $Action -ne $FilterAction) { return $false }
    return $true
}

# -- IP Filter (post-parse: exact first, subnet fallback) ---------------------
function Select-FAByIPFilter {
    [CmdletBinding()]
    param(
        [hashtable]$UniqueConnections,
        [string]$FilterSrcIP,
        [string]$FilterDstIP
    )
    if (-not $FilterSrcIP -and -not $FilterDstIP) { return $UniqueConnections }

    $exact = @{}
    foreach ($kv in $UniqueConnections.GetEnumerator()) {
        $conn = $kv.Value.Connection
        $srcMatch = (-not $FilterSrcIP) -or ($conn.SourceIP -eq $FilterSrcIP)
        $dstMatch = (-not $FilterDstIP) -or ($conn.DestIP   -eq $FilterDstIP)
        if ($srcMatch -and $dstMatch) { $exact[$kv.Key] = $kv.Value }
    }
    if ($exact.Count -gt 0) { return $exact }

    $subnet = @{}
    foreach ($kv in $UniqueConnections.GetEnumerator()) {
        $conn = $kv.Value.Connection
        $srcMatch = (-not $FilterSrcIP) -or ($conn.SourceSubnet -like "*$FilterSrcIP*") -or ($conn.SourceIP -like "$FilterSrcIP*")
        $dstMatch = (-not $FilterDstIP) -or ($conn.DestSubnet   -like "*$FilterDstIP*") -or ($conn.DestIP   -like "$FilterDstIP*")
        if ($srcMatch -and $dstMatch) { $subnet[$kv.Key] = $kv.Value }
    }
    return $subnet
}

# -- Single-Line Parser (shared by CLI and runspace workers) -------------------
function Invoke-FAParseLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Line,
        [int]$LineNumber = 0,
        [int]$MaskBits = 24,
        [string]$StartTime = '',
        [string]$EndTime = ''
    )

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    # Early-exit: fast rejection of non-matching lines (check dstport first - most selective)
    $mDstPort = $script:FAPatterns.dstport.Match($Line)
    if (-not $mDstPort.Success) { return $null }
    $mSrcIp = $script:FAPatterns.srcip.Match($Line)
    if (-not $mSrcIp.Success) { return $null }
    $mDstIp = $script:FAPatterns.dstip.Match($Line)
    if (-not $mDstIp.Success) { return $null }

    $srcip   = $mSrcIp.Groups[1].Value
    $dstip   = $mDstIp.Groups[1].Value
    $dstport = $mDstPort.Groups[1].Value

    if (-not $script:FAPatterns.ipValid.IsMatch($srcip))  { return $null }
    if (-not $script:FAPatterns.ipValid.IsMatch($dstip))  { return $null }
    if (-not $script:FAPatterns.portValid.IsMatch($dstport)) { return $null }

    # Extract remaining fields only after fast-path passes
    $mSrcPort = $script:FAPatterns.srcport.Match($Line)
    $srcport  = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { '' }

    if ($srcport -and -not $script:FAPatterns.portValid.IsMatch($srcport)) { return $null }

    $mSvc     = $script:FAPatterns.service.Match($Line)
    $service  = if ($mSvc.Success) { $mSvc.Groups[1].Value } else { '' }

    $mSrcIntf = $script:FAPatterns.srcintf.Match($Line)
    $srcintf  = if ($mSrcIntf.Success) { $mSrcIntf.Groups[1].Value } else { '' }

    $mDstIntf = $script:FAPatterns.dstintf.Match($Line)
    $dstintf  = if ($mDstIntf.Success) { $mDstIntf.Groups[1].Value } else { '' }

    $mAction  = $script:FAPatterns.action.Match($Line)
    $action   = if ($mAction.Success) { ConvertTo-FAAction $mAction.Groups[1].Value } else { '' }

    $mProto   = $script:FAPatterns.proto.Match($Line)
    $proto    = if ($mProto.Success) { $mProto.Groups[1].Value } else { '' }

    $mTran    = $script:FAPatterns.trandisp.Match($Line)
    $tran     = if ($mTran.Success) { $mTran.Groups[1].Value } else { 'noop' }
    $nat      = if ($tran -match 'snat|dnat') { 'Enabled' } else { 'Disabled' }

    # Timestamp extraction and time-range filter
    $logTs = Get-FALogTimestamp $Line
    if ($StartTime -and $logTs) {
        $stDt = $null
        if ([datetime]::TryParse($StartTime, [ref]$stDt) -and $logTs -lt $stDt) { return $null }
    }
    if ($EndTime -and $logTs) {
        $etDt = $null
        if ([datetime]::TryParse($EndTime, [ref]$etDt) -and $logTs -gt $etDt) { return $null }
    }

    $serviceName = Get-FAServiceName $dstport $proto $service

    return @{
        SourceIP        = $srcip
        DestIP          = $dstip
        SourcePort      = $srcport
        DestPort        = $dstport
        Service         = $service
        SourceInterface = $srcintf
        DestInterface   = $dstintf
        Action          = $action
        Protocol        = $proto
        NatEnabled      = $nat
        SourceSubnet    = Convert-FASubnet $srcip $MaskBits
        DestSubnet      = Convert-FASubnet $dstip $MaskBits
        ServiceName     = $serviceName
        LineNumber      = $LineNumber
        LogTimestamp    = $logTs
    }
}

# -- Build Export List from UniqueConnections ----------------------------------
function Get-FAExportList {
    [CmdletBinding()]
    param(
        [hashtable]$UniqueConnections,
        [string]$FilterSrcIP = '',
        [string]$FilterDstIP = ''
    )
    $list = [System.Collections.ArrayList]::new()
    foreach ($kv in $UniqueConnections.GetEnumerator()) {
        $d    = $kv.Value
        $conn = $d.Connection
        [void]$list.Add([PSCustomObject]@{
            PolicyName        = $conn.PolicyName
            IncomingInterface = $conn.SourceInterface
            OutgoingInterface = $conn.DestInterface
            Source            = if ($FilterSrcIP) { $conn.SourceIP } else { $conn.SourceSubnet }
            Destination       = if ($FilterDstIP) { $conn.DestIP } else { $conn.DestSubnet }
            Service           = $conn.ServiceName
            Action            = $conn.Action
            NatEnabled        = $conn.NatEnabled
            TrafficCount      = $d.Count
            FirstSeen         = $d.FirstSeen
            LastSeen          = $d.LastSeen
            SourceIP          = $conn.SourceIP
            DestinationIP     = $conn.DestIP
            SourcePort        = $conn.SourcePort
            DestinationPort   = $conn.DestPort
            Protocol          = $conn.Protocol
        })
    }
    return @($list | Sort-Object TrafficCount -Descending)
}

# -- TEXT Report Builder -------------------------------------------------------
function Build-FATextReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [int]$TotalLines,
        [int]$ExcludedLines,
        [string]$FilterSummary = 'None'
    )
    $Data = @($Data)
    $ts   = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
    $sb   = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine("=== FORTIGATE LOG ANALYSIS RESULTS v$script:FAVersion ===")
    [void]$sb.AppendLine("Analysis Date          : $ts")
    [void]$sb.AppendLine("Total Lines Read       : $($TotalLines.ToString('N0'))")
    [void]$sb.AppendLine("Lines Excluded (filter): $($ExcludedLines.ToString('N0'))")
    [void]$sb.AppendLine("Unique Policy Patterns : $($Data.Count)")
    [void]$sb.AppendLine("Active Filters         : $FilterSummary")
    [void]$sb.AppendLine("")

    $idx = 0
    foreach ($item in $Data) {
        $idx++
        $act = if ($item.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
        [void]$sb.AppendLine("Policy        : $($item.PolicyName)")
        [void]$sb.AppendLine("Source        : $($item.Source) via $($item.IncomingInterface)")
        [void]$sb.AppendLine("Destination   : $($item.Destination) via $($item.OutgoingInterface)")
        [void]$sb.AppendLine("Service       : $($item.Service)")
        [void]$sb.AppendLine("Action        : $act")
        [void]$sb.AppendLine("NAT           : $($item.NatEnabled)")
        [void]$sb.AppendLine("Traffic Count : $($item.TrafficCount)")
        if ($idx -lt $Data.Count) { [void]$sb.AppendLine("============================") }
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== SUMMARY ===")
    [void]$sb.AppendLine("Policies Required : $($Data.Count)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Generated by FortiAnalyzer Log Parser v$script:FAVersion")
    return $sb.ToString()
}

# -- HTML Report Builder -------------------------------------------------------
function Build-FAHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [int]$TotalLines,
        [int]$ExcludedLines,
        [string]$FilterSummary = 'None'
    )
    $Data = @($Data)
    $ts         = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
    $totalFlows = $TotalLines.ToString('N0')
    $uniquePat  = $Data.Count.ToString('N0')
    $skippedStr = $ExcludedLines.ToString('N0')
    $filterHtml = ConvertTo-FAHtmlSafe $FilterSummary
    $version    = $script:FAVersion

    # -- Chart data --------------------------------------------------------
    $topServices = @($Data | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 10)
    $topSrcIPs   = @($Data | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 10)
    $allowCount  = @($Data | Where-Object Action -eq 'accept').Count
    $denyCount   = @($Data | Where-Object Action -eq 'deny').Count
    $maxSvcCount = if ($topServices.Count -gt 0) { ($topServices | Measure-Object Count -Maximum).Maximum } else { 1 }
    $maxIPCount  = if ($topSrcIPs.Count -gt 0)   { ($topSrcIPs   | Measure-Object Count -Maximum).Maximum } else { 1 }
    $totalCount  = [Math]::Max($allowCount + $denyCount, 1)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiAnalyzer Traffic Analysis v$version</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e}
.hdr{background:linear-gradient(135deg,#1a1a2e,#0f3460);color:#e0e0e0;padding:24px 28px}
.hdr h1{font-size:1.5rem;font-weight:700}
.hdr .sub{margin-top:4px;font-size:.85rem;opacity:.7}
.wrap{max-width:1600px;margin:0 auto;padding:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:16px}
.card{background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 2px 8px rgba(0,0,0,.07)}
.card h3{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:#888;margin-bottom:6px}
.card .val{font-size:1.8rem;font-weight:800;color:#0f3460}
.filter-bar{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:10px 16px;margin-bottom:16px;font-size:.85rem;color:#92400e}
.filter-bar strong{color:#78350f}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
@media(max-width:900px){.charts{grid-template-columns:1fr}}
.chart-box{background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 2px 8px rgba(0,0,0,.07)}
.chart-box h3{font-size:.8rem;text-transform:uppercase;letter-spacing:1px;color:#666;margin-bottom:12px}
.bar-row{display:flex;align-items:center;margin-bottom:6px;font-size:.78rem}
.bar-label{width:120px;text-align:right;padding-right:10px;color:#555;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:18px;background:#f0f0f0;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .3s}
.bar-val{width:50px;padding-left:8px;font-weight:600;color:#333}
.donut-wrap{display:flex;align-items:center;gap:20px}
.donut{width:100px;height:100px;border-radius:50%;position:relative}
.donut-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.1rem;font-weight:800;color:#333}
.donut-legend{font-size:.82rem;line-height:1.8}
.legend-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.search-bar{margin-bottom:12px}
.search-bar input{width:100%;padding:8px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:.88rem}
.tbl-wrap{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.07);overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.85rem}
thead th{background:#0f3460;color:#fff;padding:11px 13px;text-align:left;font-weight:600;white-space:nowrap;cursor:pointer;user-select:none}
thead th:hover{background:#1a4a7a}
thead th::after{content:' \25B2';font-size:.6rem;opacity:.4}
thead th.sort-desc::after{content:' \25BC';opacity:.8}
tbody td{padding:10px 13px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#f7f9fc}
.badge{display:inline-block;padding:1px 9px;border-radius:10px;font-size:.72rem;font-weight:700}
.allow{background:#d4edda;color:#155724}
.deny{background:#f8d7da;color:#721c24}
.nat-on{background:#dbeafe;color:#1e40af}
.mono{font-family:'Courier New',monospace;font-size:.8rem}
.footer{text-align:center;padding:16px;color:#aaa;font-size:.78rem}
.expand-btn{cursor:pointer;color:#0f3460;font-weight:600;font-size:.78rem}
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail-cell{padding:8px 13px 12px;background:#f9fafb;font-size:.8rem;color:#555;border-bottom:2px solid #e5e7EB}
@media print{
  .search-bar,.expand-btn{display:none!important}
  .hdr{background:#1a1a2e!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  tbody tr:hover{background:none}
  .tbl-wrap{box-shadow:none;border:1px solid #ddd}
  .chart-box{break-inside:avoid}
  @page{margin:1cm}
}
</style>
</head>
<body>
<div class="hdr">
  <h1>FortiAnalyzer Network Traffic Analysis</h1>
  <div class="sub">v$version &mdash; Generated $ts</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><h3>Lines Read</h3><div class="val">$totalFlows</div></div>
    <div class="card"><h3>Excluded by Filters</h3><div class="val">$skippedStr</div></div>
    <div class="card"><h3>Policies Required</h3><div class="val">$uniquePat</div></div>
  </div>
  <div class="filter-bar"><strong>Active Filters:</strong> $filterHtml</div>

  <div class="charts">
    <div class="chart-box">
      <h3>Top 10 Services</h3>
"@)

    foreach ($svc in $topServices) {
        $pct = [Math]::Round(($svc.Count / $maxSvcCount) * 100)
        $name = ConvertTo-FAHtmlSafe $svc.Name
        [void]$sb.Append(@"
      <div class="bar-row">
        <div class="bar-label" title="$name">$name</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:#3B82F6"></div></div>
        <div class="bar-val">$($svc.Count)</div>
      </div>
"@)
    }

    [void]$sb.Append(@"
    </div>
    <div class="chart-box">
      <h3>Action Breakdown</h3>
      <div class="donut-wrap">
        <div class="donut" style="background:conic-gradient(#22c55e 0% $([Math]::Round($allowCount/$totalCount*100))%, #ef4444 $([Math]::Round($allowCount/$totalCount*100))% 100%)">
          <div class="donut-center">$($Data.Count)</div>
        </div>
        <div class="donut-legend">
          <div><span class="legend-dot" style="background:#22c55e"></span>ALLOW: $allowCount ($([Math]::Round($allowCount/$totalCount*100))%)</div>
          <div><span class="legend-dot" style="background:#ef4444"></span>DENY: $denyCount ($([Math]::Round($denyCount/$totalCount*100))%)</div>
        </div>
      </div>
    </div>
  </div>

  <div class="search-bar">
    <input type="text" id="searchInput" placeholder="Search policies, IPs, services..." onkeyup="filterTable()">
  </div>

  <div class="tbl-wrap">
  <table id="policyTable">
    <thead><tr>
      <th>#</th><th>Policy Name</th><th>In Intf</th><th>Out Intf</th>
      <th>Source</th><th>Destination</th><th>Service</th>
      <th>Action</th><th>NAT</th><th>Traffic</th><th></th>
    </tr></thead>
    <tbody>
"@)

    $rowNum = 0
    foreach ($item in $Data) {
        $rowNum++
        $pn       = ConvertTo-FAHtmlSafe $item.PolicyName
        $ii       = ConvertTo-FAHtmlSafe $item.IncomingInterface
        $oi       = ConvertTo-FAHtmlSafe $item.OutgoingInterface
        $src      = ConvertTo-FAHtmlSafe $item.Source
        $dst      = ConvertTo-FAHtmlSafe $item.Destination
        $svc      = ConvertTo-FAHtmlSafe $item.Service
        $actLabel = if ($item.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
        $actClass = if ($item.Action -eq 'accept') { 'allow' } else { 'deny' }
        $natLabel = ConvertTo-FAHtmlSafe $item.NatEnabled
        $natClass = if ($item.NatEnabled -eq 'Enabled') { 'nat-on' } else { '' }
        $srcIP    = ConvertTo-FAHtmlSafe $item.SourceIP
        $dstIP    = ConvertTo-FAHtmlSafe $item.DestinationIP

        [void]$sb.Append(@"
    <tr>
      <td style="color:#bbb">$rowNum</td>
      <td class="mono">$pn</td>
      <td>$ii</td><td>$oi</td>
      <td class="mono">$src</td><td class="mono">$dst</td>
      <td><strong>$svc</strong></td>
      <td><span class="badge $actClass">$actLabel</span></td>
      <td><span class="badge $natClass">$natLabel</span></td>
      <td>$($item.TrafficCount.ToString('N0'))</td>
      <td><span class="expand-btn" onclick="toggleDetail(this)">&#9660;</span></td>
    </tr>
    <tr class="detail-row"><td colspan="11" class="detail-cell">
      <strong>Source IP:</strong> $srcIP &nbsp;|&nbsp;
      <strong>Dest IP:</strong> $dstIP &nbsp;|&nbsp;
      <strong>Src Port:</strong> $($item.SourcePort) &nbsp;|&nbsp;
      <strong>Dst Port:</strong> $($item.DestinationPort) &nbsp;|&nbsp;
      <strong>Protocol:</strong> $($item.Protocol) &nbsp;|&nbsp;
      <strong>First Seen:</strong> $($item.FirstSeen) &nbsp;|&nbsp;
      <strong>Last Seen:</strong> $($item.LastSeen)
    </td></tr>
"@)
    }

    [void]$sb.Append(@"
    </tbody></table></div>
  <div class="footer">FortiAnalyzer Log Parser v$version &mdash; $TotalLines lines processed</div>
</div>
<script>
function filterTable(){
  var input=document.getElementById('searchInput').value.toLowerCase();
  var rows=document.querySelectorAll('#policyTable tbody tr:not(.detail-row)');
  rows.forEach(function(r){
    var match=r.textContent.toLowerCase().includes(input);
    r.style.display=match?'':'none';
    var detail=r.nextElementSibling;
    if(detail&&detail.classList.contains('detail-row'))detail.style.display='none';
  });
}
function toggleDetail(btn){
  var row=btn.closest('tr');
  var detail=row.nextElementSibling;
  if(detail&&detail.classList.contains('detail-row')){
    detail.classList.toggle('open');
    btn.innerHTML=detail.classList.contains('open')?'&#9650;':'&#9660;';
  }
}
document.querySelectorAll('#policyTable thead th').forEach(function(th,i){
  th.addEventListener('click',function(){
    var table=document.getElementById('policyTable');
    var tbody=table.querySelector('tbody');
    var rows=Array.from(tbody.querySelectorAll('tr:not(.detail-row)'));
    var detailRows=Array.from(tbody.querySelectorAll('tr.detail-row'));
    var dir=th.classList.contains('sort-asc')?'desc':'asc';
    document.querySelectorAll('#policyTable thead th').forEach(function(h){h.classList.remove('sort-asc','sort-desc')});
    th.classList.add('sort-'+dir);
    var getVal=function(r,c){
      var cell=r.cells[c];
      if(!cell)return'';
      var n=parseFloat(cell.textContent.replace(/,/g,''));
      return isNaN(n)?cell.textContent.toLowerCase():n;
    };
    rows.sort(function(a,b){
      var va=getVal(a,i),vb=getVal(b,i);
      if(typeof va==='number'&&typeof vb==='number'){return dir==='asc'?va-vb:vb-va}
      return dir==='asc'?va.localeCompare(vb):vb.localeCompare(va);
    });
    rows.forEach(function(r){
      tbody.appendChild(r);
      var d=r.nextElementSibling;
      if(d&&d.classList.contains('detail-row'))tbody.appendChild(d);
    });
  });
});
</script>
</body></html>
"@)
    return $sb.ToString()
}

# -- Get Combined Pattern (for parallel workers) -------------------------------
function Get-FACombinedPattern {
    return $script:FACombinedPattern
}

# -- Get Individual Patterns (for parallel workers) ----------------------------
function Get-FAServicePatterns {
    return $script:FAPatterns
}

# -- Get Service Mappings (for parallel workers) --------------------------------
function Get-FAServiceMappings {
    return $script:FAServiceMappings
}

# ##############################################################################
# ADVANCED ANALYSIS FUNCTIONS
# ##############################################################################

# -- Shadow / Redundant Rule Detection ----------------------------------------
function Find-FAShadowRules {
    <#
    .SYNOPSIS
        Detects shadow (redundant) firewall rules where a later rule is fully
        subsumed by an earlier rule with the same action.
    .DESCRIPTION
        For each policy pair (i < j), checks if policy j's source, destination,
        and service are all subsets of policy i. If so, policy j is shadowed
        and can never be hit. Returns an array of shadow findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Policies
    )
    $findings = [System.Collections.ArrayList]::new()
    $pols = @($Policies)

    for ($i = 0; $i -lt $pols.Count; $i++) {
        for ($j = $i + 1; $j -lt $pols.Count; $j++) {
            $a = $pols[$i]
            $b = $pols[$j]

            # Same action required for shadow
            if ($a.Action -ne $b.Action) { continue }

            # A shadows B if A's criteria encompass B's (A is broader or equal)
            $aSrc = $a.Source; $bSrc = $b.Source
            $aDst = $a.Destination; $bDst = $b.Destination
            $aSvc = $a.Service; $bSvc = $b.Service

            $srcOk = ($aSrc -eq $bSrc) -or ($aSrc -eq '0.0.0.0/0') -or ($aSrc -eq 'any') -or ($aSrc -eq '0.0.0.0')
            $dstOk = ($aDst -eq $bDst) -or ($aDst -eq '0.0.0.0/0') -or ($aDst -eq 'any') -or ($aDst -eq '0.0.0.0')
            $svcOk = ($aSvc -eq $bSvc) -or ($aSvc -eq 'any') -or ($aSvc -eq '*')

            if ($srcOk -and $dstOk -and $svcOk) {
                [void]$findings.Add([PSCustomObject]@{
                    Type        = 'Shadow Rule'
                    Severity    = 'Warning'
                    ShadowedBy  = $a.PolicyName
                    ShadowedRule = $b.PolicyName
                    Source      = $b.Source
                    Destination = $b.Destination
                    Service     = $b.Service
                    Message     = "Rule '$($b.PolicyName)' is fully shadowed by '$($a.PolicyName)' and can never be matched."
                })
            }
        }
    }
    return @($findings)
}

# -- Compliance / Least-Privilege Checking -------------------------------------
function Test-FACompliance {
    <#
    .SYNOPSIS
        Checks parsed policies against security best practices and compliance rules.
    .DESCRIPTION
        Returns an array of compliance findings with severity levels.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Policies
    )
    $findings = [System.Collections.ArrayList]::new()

    foreach ($pol in $Policies) {
        # Rule 1: Overly broad source (any)
        if ($pol.Source -match '^0\.0\.0\.0/0$|^any$') {
            [void]$findings.Add([PSCustomObject]@{
                Type     = 'Overly Broad Source'
                Severity = 'High'
                Policy   = $pol.PolicyName
                Field    = 'Source'
                Value    = $pol.Source
                Message  = "Source is 'any' - this rule applies to all source IPs. Restrict to specific subnets."
            })
        }

        # Rule 2: Overly broad destination (any)
        if ($pol.Destination -match '^0\.0\.0\.0/0$|^any$') {
            [void]$findings.Add([PSCustomObject]@{
                Type     = 'Overly Broad Destination'
                Severity = 'High'
                Policy   = $pol.PolicyName
                Field    = 'Destination'
                Value    = $pol.Destination
                Message  = "Destination is 'any' - this rule allows traffic to all destinations."
            })
        }

        # Rule 3: High-risk services exposed
        $highRiskServices = @('RDP','TELNET','FTP','SMB','MS-RPC','WINRM-HTTP','DOCKER-DAEMON','VNC')
        foreach ($svc in $highRiskServices) {
            if ($pol.Service -like "*$svc*") {
                [void]$findings.Add([PSCustomObject]@{
                    Type     = 'High-Risk Service'
                    Severity = 'Critical'
                    Policy   = $pol.PolicyName
                    Field    = 'Service'
                    Value    = $pol.Service
                    Message  = "High-risk service '$svc' is exposed. Consider replacing with SSH/HTTPS or restricting access."
                })
            }
        }

        # Rule 4: RDP from non-internal sources
        if ($pol.Service -like '*RDP*' -and $pol.Source -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
            [void]$findings.Add([PSCustomObject]@{
                Type     = 'RDP from External'
                Severity = 'Critical'
                Policy   = $pol.PolicyName
                Field    = 'Source'
                Value    = $pol.Source
                Message  = "RDP is exposed from a non-RFC1918 source ($($pol.Source)). This is a critical security risk."
            })
        }

        # Rule 5: Deny rules with very low traffic (possible stale rule)
        if ($pol.Action -eq 'deny' -and $pol.TrafficCount -lt 3) {
            [void]$findings.Add([PSCustomObject]@{
                Type     = 'Low-Traffic Deny Rule'
                Severity = 'Info'
                Policy   = $pol.PolicyName
                Field    = 'TrafficCount'
                Value    = $pol.TrafficCount
                Message  = "Deny rule has only $($pol.TrafficCount) hit(s). Consider removing if no longer needed."
            })
        }

        # Rule 6: No explicit deny-all at the end
        # (checked externally - caller should verify last rule)
    }

    # Check for missing deny-all (last rule should be a deny)
    if ($Policies.Count -gt 0) {
        $lastPolicy = $Policies[-1]
        if ($lastPolicy.Action -ne 'deny' -or $lastPolicy.Source -notmatch 'any|0\.0\.0\.0/0') {
            [void]$findings.Add([PSCustomObject]@{
                Type     = 'Missing Deny-All'
                Severity = 'High'
                Policy   = '(end of rule list)'
                Field    = 'Action'
                Value    = $lastPolicy.Action
                Message  = 'No explicit deny-all rule found at the end of the policy list. FortiGate implicit deny may mask issues.'
            })
        }
    }

    return @($findings)
}

# -- FortiGate CLI Export ------------------------------------------------------
function Export-FAFortiGateCLI {
    <#
    .SYNOPSIS
        Generates FortiGate CLI `config firewall policy` snippets.
    .DESCRIPTION
        Outputs paste-ready CLI commands for direct FortiGate deployment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Policies,
        [int]$StartPolicyID = 1
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# FortiAnalyzer Parser - Generated Firewall Policies')
    [void]$sb.AppendLine("# Generated: $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine('# Paste into FortiGate CLI or import via SSH')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('config firewall policy')

    $policyID = $StartPolicyID
    foreach ($pol in $Policies) {
        $act = if ($pol.Action -eq 'accept') { 'accept' } else { 'deny' }
        $svcName = ($pol.Service -replace '[^a-zA-Z0-9_-]','_').ToLower()
        $srcName = "SRC_$($policyID)"
        $dstName = "DST_$($policyID)"

        [void]$sb.AppendLine("    edit $policyID")
        [void]$sb.AppendLine("        set name `"$($pol.PolicyName)`"")
        [void]$sb.AppendLine("        set srcintf `"$($pol.IncomingInterface)`"")
        [void]$sb.AppendLine("        set dstintf `"$($pol.OutgoingInterface)`"")
        [void]$sb.AppendLine("        set srcaddr `"$srcName`"")
        [void]$sb.AppendLine("        set dstaddr `"$dstName`"")
        [void]$sb.AppendLine("        set service `"$svcName`"")
        [void]$sb.AppendLine("        set action $act")
        if ($pol.NatEnabled -eq 'Enabled') {
            [void]$sb.AppendLine("        set nat enable")
        }
        [void]$sb.AppendLine("        set logtraffic all")
        [void]$sb.AppendLine("    next")

        # Address objects
        [void]$sb.AppendLine("    # Address objects for policy $policyID")
        [void]$sb.AppendLine("    config firewall address")
        [void]$sb.AppendLine("        edit `"$srcName`"")
        [void]$sb.AppendLine("            set subnet $($pol.Source)")
        [void]$sb.AppendLine("        next")
        [void]$sb.AppendLine("        edit `"$dstName`"")
        [void]$sb.AppendLine("            set subnet $($pol.Destination)")
        [void]$sb.AppendLine("        next")
        [void]$sb.AppendLine("    end")

        # Service object
        [void]$sb.AppendLine("    config firewall service custom")
        [void]$sb.AppendLine("        edit `"$svcName`"")
        if ($pol.DestinationPort -match '^\d+$') {
            [void]$sb.AppendLine("            set tcpportrange $($pol.DestinationPort)")
        }
        [void]$sb.AppendLine("        next")
        [void]$sb.AppendLine("    end")
        [void]$sb.AppendLine('')

        $policyID++
    }

    [void]$sb.AppendLine('end')
    return $sb.ToString()
}

# -- Rule Diff / Comparison ----------------------------------------------------
function Compare-FARules {
    <#
    .SYNOPSIS
        Compares two sets of parsed policies and identifies added, removed, and modified rules.
    .PARAMETER Baseline
        The baseline (before) policy list.
    .PARAMETER Current
        The current (after) policy list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Baseline,
        [Parameter(Mandatory)][array]$Current
    )

    $baselineHash = @{}
    foreach ($pol in $Baseline) {
        $key = "$($pol.Source)|$($pol.Destination)|$($pol.Service)|$($pol.IncomingInterface)|$($pol.OutgoingInterface)"
        $baselineHash[$key] = $pol
    }

    $currentHash = @{}
    foreach ($pol in $Current) {
        $key = "$($pol.Source)|$($pol.Destination)|$($pol.Service)|$($pol.IncomingInterface)|$($pol.OutgoingInterface)"
        $currentHash[$key] = $pol
    }

    $added      = [System.Collections.ArrayList]::new()
    $removed    = [System.Collections.ArrayList]::new()
    $modified   = [System.Collections.ArrayList]::new()
    $unchanged  = 0

    # Find added and modified
    foreach ($kv in $currentHash.GetEnumerator()) {
        if ($baselineHash.ContainsKey($kv.Key)) {
            $b = $baselineHash[$kv.Key]
            $c = $kv.Value
            if ($b.Action -ne $c.Action -or $b.TrafficCount -ne $c.TrafficCount) {
                [void]$modified.Add([PSCustomObject]@{
                    Change   = 'Modified'
                    Policy   = $c.PolicyName
                    Source   = $c.Source
                    Dest     = $c.Destination
                    Service  = $c.Service
                    OldAction = $b.Action
                    NewAction = $c.Action
                })
            } else {
                $unchanged++
            }
        } else {
            [void]$added.Add([PSCustomObject]@{
                Change  = 'Added'
                Policy  = $kv.Value.PolicyName
                Source  = $kv.Value.Source
                Dest    = $kv.Value.Destination
                Service = $kv.Value.Service
                Action  = $kv.Value.Action
            })
        }
    }

    # Find removed
    foreach ($kv in $baselineHash.GetEnumerator()) {
        if (-not $currentHash.ContainsKey($kv.Key)) {
            [void]$removed.Add([PSCustomObject]@{
                Change  = 'Removed'
                Policy  = $kv.Value.PolicyName
                Source  = $kv.Value.Source
                Dest    = $kv.Value.Destination
                Service = $kv.Value.Service
                Action  = $kv.Value.Action
            })
        }
    }

    return [PSCustomObject]@{
        Added     = @($added)
        Removed   = @($removed)
        Modified  = @($modified)
        Unchanged = $unchanged
        Summary   = "+$($added.Count) added, -$($removed.Count) removed, ~$($modified.Count) modified, =$unchanged unchanged"
    }
}

# -- FortiManager XML Export --------------------------------------------------
function Export-FAFortiManagerXML {
    <#
    .SYNOPSIS
        Generates FortiManager-importable XML for firewall policies.
    .DESCRIPTION
        Creates XML compatible with FortiManager's "Import Policy" functionality.
        The XML contains address objects, service objects, and policy entries.
    .PARAMETER Policies
        Array of parsed policy objects (from Get-FAExportList).
    .PARAMETER PackageName
        Name of the FortiManager policy package (default: "FortiAnalyzer_AutoGenerated").
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Policies,
        [string]$PackageName = 'FortiAnalyzer_AutoGenerated'
    )

    $xml = [System.Xml.XmlDocument]@{}
    $root = $xml.CreateElement('results')
    $xml.AppendChild($root) | Out-Null

    $pdom = $xml.CreateElement('policy-package')
    $pdom.SetAttribute('name', $PackageName)
    $root.AppendChild($pdom) | Out-Null

    # Collect unique addresses and services
    $addrMap = @{}
    $svcMap  = @{}

    foreach ($pol in $Policies) {
        $srcKey = $pol.Source -replace '[^a-zA-Z0-9.]','_'
        $dstKey = $pol.Destination -replace '[^a-zA-Z0-9.]','_'
        $svcKey = $pol.Service -replace '[^a-zA-Z0-9]','_'

        if (-not $addrMap.ContainsKey($srcKey)) {
            $addrMap[$srcKey] = @{ Name="ADDR_$srcKey"; Subnet=$pol.Source }
        }
        if (-not $addrMap.ContainsKey($dstKey)) {
            $addrMap[$dstKey] = @{ Name="ADDR_$dstKey"; Subnet=$pol.Destination }
        }
        if (-not $svcMap.ContainsKey($svcKey)) {
            $svcMap[$svcKey] = @{ Name=$svcKey; Port=$pol.DestinationPort }
        }
    }

    # Write address objects
    $addrs = $xml.CreateElement('addresses')
    foreach ($kv in $addrMap.GetEnumerator()) {
        $a = $xml.CreateElement('address')
        $a.SetAttribute('name', $kv.Value.Name)
        $a.SetAttribute('subnet', $kv.Value.Subnet)
        $addrs.AppendChild($a) | Out-Null
    }
    $pdom.AppendChild($addrs) | Out-Null

    # Write service objects
    $svcs = $xml.CreateElement('services')
    foreach ($kv in $svcMap.GetEnumerator()) {
        $s = $xml.CreateElement('service')
        $s.SetAttribute('name', $kv.Value.Name)
        if ($kv.Value.Port -match '^\d+$') {
            $s.SetAttribute('tcp-portrange', $kv.Value.Port)
        }
        $svcs.AppendChild($s) | Out-Null
    }
    $pdom.AppendChild($svcs) | Out-Null

    # Write policies
    $pols = $xml.CreateElement('policies')
    $seq = 1
    foreach ($pol in $Policies) {
        $p = $xml.CreateElement('policy')
        $p.SetAttribute('sequence', $seq)
        $p.SetAttribute('name', $pol.PolicyName)

        $p.AppendChild(($xml.CreateElement('src')). AppendChild($xml.CreateElement('addr')) -as [System.Xml.XmlElement]).InnerText = "ADDR_$($pol.Source -replace '[^a-zA-Z0-9.]','_')"
        $p.AppendChild(($xml.CreateElement('dst')). AppendChild($xml.CreateElement('addr')) -as [System.Xml.XmlElement]).InnerText = "ADDR_$($pol.Destination -replace '[^a-zA-Z0-9.]','_')"
        $p.AppendChild(($xml.CreateElement('svc')). AppendChild($xml.CreateElement('name')) -as [System.Xml.XmlElement]).InnerText = $pol.Service -replace '[^a-zA-Z0-9]','_'
        $p.AppendChild(($xml.CreateElement('action'))).InnerText = $pol.Action
        $p.AppendChild(($xml.CreateElement('srcintf'))).InnerText = $pol.IncomingInterface
        $p.AppendChild(($xml.CreateElement('dstintf'))).InnerText = $pol.OutgoingInterface

        if ($pol.NatEnabled -eq 'Enabled') {
            $p.AppendChild(($xml.CreateElement('nat'))).InnerText = 'enable'
        }

        $pols.AppendChild($p) | Out-Null
        $seq++
    }
    $pdom.AppendChild($pols) | Out-Null

    $sb = [System.Text.StringBuilder]::new()
    $sw = [System.IO.StringWriter]::new($sb)
    $xw = [System.Xml.XmlTextWriter]::new($sw)
    $xw.Formatting = [System.Xml.Formatting]::Indented
    $xw.Indentation = 2
    $xml.WriteTo($xw)
    $xw.Close()

    return $sb.ToString()
}

# -- Expose version and mappings as module-level variables ----------------------
$FAVersion         = $script:FAVersion
$FAServiceMappings = $script:FAServiceMappings
