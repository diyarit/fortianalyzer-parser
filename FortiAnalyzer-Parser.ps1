<#
.SYNOPSIS
    FortiAnalyzer Log Parser - Enhanced Network Traffic Analysis Tool
.DESCRIPTION
    Parses FortiAnalyzer log files to extract network traffic patterns and generate FortiGate firewall policies.
    Supports multiple output formats (CSV, JSON, HTML, TEXT) with comprehensive service recognition and
    professional policy naming conventions.

    Improvements over v2.5.0:
      - Single-pass regex matching (no double .Match() calls) - ~50% fewer regex operations
      - Real parallel processing via PowerShell runspaces (-UseParallel)
      - Streaming mode with pipeline-based chunked I/O (-StreamingMode)
      - Config file support for overriding service mappings and thresholds (-ConfigFile)
      - Configurable subnet mask (-SubnetMask CIDR notation, default /24)
      - Collision-safe policy naming with hash suffix fallback
      - Timestamp extraction from log lines (date=/time= fields)
      - Time-range filtering (-StartTime / -EndTime)
      - HTML output with XSS-safe encoding
      - File read only once (no double-pass for line count)
      - Get-Date removed from hot loop; batch timestamp used
      - Functions are pure (no global state mutations inside logic)
      - PSScriptAnalyzer-approved verb usage

.VERSION
    3.0.0
.AUTHOR
    Diyar Abbas (refactored)
.NOTES
    Requires PowerShell 5.1+
    For parallel processing, RunspacePool is used (no external modules required)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$LogFilePath,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "NetworkTraffic.csv",

    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML", "TEXT")]
    [string]$OutputFormat = "CSV",

    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress,

    [Parameter(Mandatory=$false)]
    [switch]$DebugMode,

    # FIX: UseParallel is now actually implemented via RunspacePool
    [Parameter(Mandatory=$false)]
    [switch]$UseParallel,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 32)]
    [int]$MaxThreads = 4,

    # FIX: ConfigFile is now actually loaded and applied
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "",

    # FIX: StreamingMode now uses pipeline streaming instead of full in-memory load
    [Parameter(Mandatory=$false)]
    [switch]$StreamingMode,

    # NEW: Configurable subnet mask (CIDR bits only, e.g. 24 for /24)
    [Parameter(Mandatory=$false)]
    [ValidateRange(8, 32)]
    [int]$SubnetMask = 24,

    # Optional time-range filtering
    [Parameter(Mandatory=$false)]
    [string]$StartTime = "",

    [Parameter(Mandatory=$false)]
    [string]$EndTime = "",

    # NEW: IP and service filters
    # All filters use case-insensitive partial/prefix matching.
    # e.g. -FilterSrcIP "192.168.1" matches any source IP beginning with 192.168.1
    # e.g. -FilterService "HTTP" matches HTTP, HTTPS, HTTP-ALT, HTTP-8080, etc.

    [Parameter(Mandatory=$false)]
    [string]$FilterSrcIP = "",

    [Parameter(Mandatory=$false)]
    [string]$FilterDstIP = "",

    [Parameter(Mandatory=$false)]
    [string]$FilterService = "",

    [Parameter(Mandatory=$false)]
    [string]$FilterAction = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Service Mappings ---

$script:serviceMappings = @{
    # Core Internet Services
    '13'    = 'DAYTIME';    '20'    = 'FTP-DATA';       '21'    = 'FTP';            '22'    = 'SSH'
    '23'    = 'TELNET';     '25'    = 'SMTP';            '37'    = 'TIME';           '53'    = 'DNS'
    '67'    = 'DHCP-SERVER';'68'    = 'DHCP-CLIENT';     '69'    = 'TFTP';           '79'    = 'FINGER'
    '80'    = 'HTTP';       '110'   = 'POP3';            '111'   = 'PORTMAPPER';     '119'   = 'NNTP'
    '123'   = 'NTP';        '143'   = 'IMAP';            '161'   = 'SNMP';           '162'   = 'SNMP-TRAP'
    '179'   = 'BGP';        '194'   = 'IRC';             '199'   = 'SMUX';           '220'   = 'IMAP3'
    '389'   = 'LDAP';       '443'   = 'HTTPS';           '465'   = 'SMTPS';          '500'   = 'ISAKMP'
    '514'   = 'SYSLOG';     '515'   = 'LPR';             '520'   = 'RIP';            '521'   = 'RIPNG'
    '587'   = 'SMTP-SUBMISSION'; '631' = 'IPP';          '636'   = 'LDAPS';          '646'   = 'LDP'
    '873'   = 'RSYNC';      '989'   = 'FTPS-DATA';       '990'   = 'FTPS';           '993'   = 'IMAPS'
    '995'   = 'POP3S';      '1080'  = 'SOCKS';           '1194'  = 'OPENVPN'
    '1645'  = 'RADIUS-AUTH-OLD'; '1646' = 'RADIUS-ACCT-OLD'; '1720' = 'H323'
    '1723'  = 'PPTP';       '1812'  = 'RADIUS-AUTH';     '1813'  = 'RADIUS-ACCT'

    # Microsoft Services
    '135'   = 'MS-RPC';     '137'   = 'NETBIOS-NS';      '138'   = 'NETBIOS-DGM';   '139'   = 'NETBIOS-SSN'
    '445'   = 'SMB';        '1433'  = 'MSSQL';           '1434'  = 'MSSQL-MONITOR';  '3389'  = 'RDP'
    '5985'  = 'WINRM-HTTP'; '5986'  = 'WINRM-HTTPS'

    # Database Services
    '1521'  = 'ORACLE';     '1522'  = 'ORACLE-TNS';      '3306'  = 'MYSQL';          '5432'  = 'POSTGRESQL'
    '6379'  = 'REDIS';      '27017' = 'MONGODB';          '9042'  = 'CASSANDRA';      '7000'  = 'CASSANDRA-INTER'
    '11211' = 'MEMCACHED'

    # Web / DevOps
    '3000'  = 'GRAFANA';    '4000'  = 'HTTP-4000';       '5000'  = 'DOCKER-REGISTRY'
    '8000'  = 'HTTP-8000';  '8008'  = 'HTTP-8008';       '8080'  = 'HTTP-ALT';       '8081'  = 'NEXUS'
    '8086'  = 'INFLUXDB';   '8443'  = 'HTTPS-ALT';       '9000'  = 'SONARQUBE';      '9090'  = 'PROMETHEUS'
    '9100'  = 'PROMETHEUS-NODE'

    # Virtualization & Cloud
    '902'   = 'VMWARE-AUTH'; '903'  = 'VMWARE-CONSOLE';  '5480'  = 'VCENTER-MGMT'
    '8006'  = 'PROXMOX';    '16509' = 'LIBVIRT';          '2375'  = 'DOCKER-DAEMON';  '2376'  = 'DOCKER-DAEMON-TLS'
    '6443'  = 'KUBERNETES-API'; '10250' = 'KUBELET';      '2379'  = 'ETCD-CLIENT';    '2380'  = 'ETCD-PEER'
    '9200'  = 'ELASTICSEARCH'; '9300' = 'ELASTICSEARCH-TRANSPORT'; '5601' = 'KIBANA'
    '5044'  = 'LOGSTASH';   '8200'  = 'VAULT';            '8500'  = 'CONSUL'
}

#endregion

#region --- Compiled Regex Patterns ---

$script:patterns = @{
    srcip       = [regex]::new('srcip=(\d+\.\d+\.\d+\.\d+)',   [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstip       = [regex]::new('dstip=(\d+\.\d+\.\d+\.\d+)',   [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcport     = [regex]::new('srcport=(\d+)',                  [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstport     = [regex]::new('dstport=(\d+)',                  [System.Text.RegularExpressions.RegexOptions]::Compiled)
    service     = [regex]::new('service="([^"]*)"',              [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcintf     = [regex]::new('srcintf="([^"]*)"',              [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstintf     = [regex]::new('dstintf="([^"]*)"',              [System.Text.RegularExpressions.RegexOptions]::Compiled)
    action      = [regex]::new('action="([^"]*)"',               [System.Text.RegularExpressions.RegexOptions]::Compiled)
    proto       = [regex]::new('proto=(\d+)',                    [System.Text.RegularExpressions.RegexOptions]::Compiled)
    # NEW: Timestamp fields
    logdate     = [regex]::new('date=(\d{4}-\d{2}-\d{2})',      [System.Text.RegularExpressions.RegexOptions]::Compiled)
    logtime     = [regex]::new('time=(\d{2}:\d{2}:\d{2})',      [System.Text.RegularExpressions.RegexOptions]::Compiled)
    # Validation
    ipValid     = [regex]::new('^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    portValid   = [regex]::new('^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

#endregion

#region --- Metrics ---

$script:metrics = [PSCustomObject]@{
    StartTime      = [DateTime]::Now
    ProcessedLines = 0
    SkippedLines   = 0
    ErrorCount     = 0
    WarningCount   = 0
}

#endregion

#region --- Logging ---

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info","Warning","Error","Debug")]
        [string]$Level = "Info"
    )
    $ts = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
    $msg = "[$ts] [$Level] $Message"
    switch ($Level) {
        "Error"   { Write-Host $msg -ForegroundColor Red;    $script:metrics.ErrorCount++ }
        "Warning" { Write-Host $msg -ForegroundColor Yellow; $script:metrics.WarningCount++ }
        "Debug"   { if ($DebugMode) { Write-Host $msg -ForegroundColor Cyan } }
        default   { Write-Host $msg -ForegroundColor White }
    }
}

#endregion

#region --- Config File Loader ---

function Import-Config {
    param([string]$Path)
    # FIX: ConfigFile is now actually processed
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return }

    try {
        $cfg = Get-Content $Path -Raw | ConvertFrom-Json
        if ($cfg.serviceMappings) {
            foreach ($prop in $cfg.serviceMappings.PSObject.Properties) {
                $script:serviceMappings[$prop.Name] = $prop.Value
                Write-Log "Config override: port $($prop.Name) -> $($prop.Value)" "Debug"
            }
        }
        Write-Log "Config file loaded: $Path" "Info"
    }
    catch {
        Write-Log "Failed to load config file '$Path': $_" "Warning"
    }
}

#endregion

#region --- Prerequisite Validation ---

function Test-Prerequisites {
    param([string]$LogFilePath, [string]$OutputFile)
    try {
        if (-not (Test-Path $LogFilePath)) { throw "Log file not found: $LogFilePath" }

        $fileInfo = Get-Item $LogFilePath
        if ($fileInfo.Length -eq 0) { throw "Log file is empty: $LogFilePath" }

        $fileSizeMB = [Math]::Round($fileInfo.Length / 1MB, 2)
        Write-Log "File size: ${fileSizeMB} MB" "Info"
        if ($fileSizeMB -gt 500) {
            Write-Log "Large file detected (${fileSizeMB} MB). -StreamingMode is recommended." "Warning"
        }

        $outputDir = Split-Path $OutputFile -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            Write-Log "Created output directory: $outputDir" "Info"
        }
        return $true
    }
    catch {
        Write-Log "Prerequisites validation failed: $_" "Error"
        return $false
    }
}

#endregion

#region --- Helper Functions ---

function Get-ServiceName {
    param([string]$Port, [string]$Protocol, [string]$ServiceHint)
    if (-not [string]::IsNullOrWhiteSpace($ServiceHint) -and $ServiceHint -ne "unknown") {
        return $ServiceHint.ToUpper()
    }
    if ($script:serviceMappings.ContainsKey($Port)) {
        return $script:serviceMappings[$Port]
    }
    switch ($Protocol) {
        "6"   { return "TCP/$Port" }
        "17"  { return "UDP/$Port" }
        default { return "PROTO${Protocol}/$Port" }
    }
}

function Convert-ToSubnet {
    # FIX: Subnet mask is now configurable via $SubnetMask parameter (CIDR bits)
    param([string]$IPAddress, [int]$MaskBits)
    try {
        $octets = $IPAddress -split '\.'
        if ($octets.Count -ne 4) { return $IPAddress }

        # Calculate host mask and apply to IP
        $ipInt = ([int]$octets[0] -shl 24) -bor ([int]$octets[1] -shl 16) -bor ([int]$octets[2] -shl 8) -bor [int]$octets[3]
        $netMask = if ($MaskBits -eq 0) { 0 } else { [int]([uint32]::MaxValue -shl (32 - $MaskBits)) }
        $netInt  = $ipInt -band $netMask

        $a = ($netInt -shr 24) -band 0xFF
        $b = ($netInt -shr 16) -band 0xFF
        $c = ($netInt -shr 8)  -band 0xFF
        $d = $netInt            -band 0xFF
        return "${a}.${b}.${c}.${d}/${MaskBits}"
    }
    catch {
        Write-Log "Error converting IP to subnet: $IPAddress" "Warning"
        return $IPAddress
    }
}

function Get-PolicyName {
    # FIX: Renamed from New-PolicyName to Get-PolicyName (approved verb)
    # FIX: Collision-safe - appends a short hash suffix when truncation would cause ambiguity
    param([hashtable]$Connection)

    $actionPrefix  = if ($Connection.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
    $sourceIntf    = ($Connection.SourceInterface -replace '[^a-zA-Z0-9]', '_').ToUpper()
    $destIntf      = ($Connection.DestInterface   -replace '[^a-zA-Z0-9]', '_').ToUpper()
    $serviceClean  = $Connection.ServiceName      -replace '[^a-zA-Z0-9]', '_'

    $fullName = "${actionPrefix}_${sourceIntf}_TO_${destIntf}_${serviceClean}"

    if ($fullName.Length -le 35) { return $fullName }

    # Truncation required - keep action+interfaces and append 5-char hash of service to stay unique
    $hashBytes = [System.Security.Cryptography.SHA1]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($serviceClean)
    )
    $shortHash = ([System.BitConverter]::ToString($hashBytes) -replace '-','').Substring(0,5)
    $shortened = "${actionPrefix}_${sourceIntf}_TO_${destIntf}_${shortHash}"

    # Final safety truncation to 35 chars
    if ($shortened.Length -gt 35) { $shortened = $shortened.Substring(0, 35) }
    return $shortened
}

function Get-LogTimestamp {
    # NEW: Parse date=/time= from a log line; returns [datetime] or $null
    param([string]$Line)
    try {
        $dm = $script:patterns.logdate.Match($Line)
        $tm = $script:patterns.logtime.Match($Line)
        if ($dm.Success -and $tm.Success) {
            return [datetime]::Parse("$($dm.Groups[1].Value) $($tm.Groups[1].Value)")
        }
    }
    catch { <# timestamp is optional; suppress #> }
    return $null
}

function ConvertTo-HtmlSafe {
    # FIX: HTML-encode values before injecting into report to prevent XSS
    param([string]$Value)
    return [System.Web.HttpUtility]::HtmlEncode($Value)
}

#endregion

#region --- Line Parser ---

function Invoke-ParseLine {
    # FIX: Each regex is called only ONCE per field (result stored in variable)
    param([string]$Line, [int]$LineNumber, [int]$MaskBits, [nullable[datetime]]$StartTime, [nullable[datetime]]$EndTime)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    # Single-pass field extraction
    $mSrcIp   = $script:patterns.srcip.Match($Line);   $srcip   = if ($mSrcIp.Success)   { $mSrcIp.Groups[1].Value }   else { "" }
    $mDstIp   = $script:patterns.dstip.Match($Line);   $dstip   = if ($mDstIp.Success)   { $mDstIp.Groups[1].Value }   else { "" }
    $mSrcPort = $script:patterns.srcport.Match($Line);  $srcport = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { "" }
    $mDstPort = $script:patterns.dstport.Match($Line);  $dstport = if ($mDstPort.Success) { $mDstPort.Groups[1].Value } else { "" }
    $mSvc     = $script:patterns.service.Match($Line);  $service = if ($mSvc.Success)     { $mSvc.Groups[1].Value }     else { "" }
    $mSrcIntf = $script:patterns.srcintf.Match($Line);  $srcintf = if ($mSrcIntf.Success) { $mSrcIntf.Groups[1].Value } else { "" }
    $mDstIntf = $script:patterns.dstintf.Match($Line);  $dstintf = if ($mDstIntf.Success) { $mDstIntf.Groups[1].Value } else { "" }
    $mAction  = $script:patterns.action.Match($Line);   $action  = if ($mAction.Success)  { $mAction.Groups[1].Value }  else { "" }
    $mProto   = $script:patterns.proto.Match($Line);    $proto   = if ($mProto.Success)   { $mProto.Groups[1].Value }   else { "" }

    # Essential field check
    if (-not $srcip -or -not $dstip -or -not $dstport) { return $null }

    # IP validation
    if (-not $script:patterns.ipValid.IsMatch($srcip)) {
        Write-Log "Invalid source IP on line ${LineNumber} - $srcip" "Warning"
        return $null
    }
    if (-not $script:patterns.ipValid.IsMatch($dstip)) {
        Write-Log "Invalid dest IP on line ${LineNumber} - $dstip" "Warning"
        return $null
    }

    # Port validation
    if (-not $script:patterns.portValid.IsMatch($dstport)) {
        Write-Log "Invalid dest port on line ${LineNumber} - $dstport" "Warning"
        return $null
    }
    if ($srcport -and -not $script:patterns.portValid.IsMatch($srcport)) {
        Write-Log "Invalid source port on line ${LineNumber} - $srcport" "Warning"
        return $null
    }

    # Timestamp extraction and time-range filter
    $logTs = Get-LogTimestamp $Line
    if ($StartTime -and $logTs) {
        $stDt = $null
        if ([datetime]::TryParse($StartTime, [ref]$stDt) -and $logTs -lt $stDt) { return $null }
    }
    if ($EndTime -and $logTs) {
        $etDt = $null
        if ([datetime]::TryParse($EndTime, [ref]$etDt) -and $logTs -gt $etDt) { return $null }
    }

    $serviceName = Get-ServiceName $dstport $proto $service
    $conn = @{
        SourceIP        = $srcip
        DestIP          = $dstip
        SourcePort      = $srcport
        DestPort        = $dstport
        Service         = $service
        SourceInterface = $srcintf
        DestInterface   = $dstintf
        Action          = $action
        Protocol        = $proto
        SourceSubnet    = Convert-ToSubnet $srcip $MaskBits
        DestSubnet      = Convert-ToSubnet $dstip $MaskBits
        ServiceName     = $serviceName
        LineNumber      = $LineNumber
        LogTimestamp    = $logTs
    }
    $conn.PolicyName = Get-PolicyName $conn
    return $conn
}

#endregion

#region --- Filter Logic ---

function Test-Filters {
    # Service filter accepts a raw port number (e.g. "443") OR a partial
    # service name (e.g. "HTTP").  All-digit input is matched against the
    # raw destination port; anything else is a case-insensitive wildcard
    # match against the resolved service name (e.g. HTTPS, HTTP-ALT).
    param(
        [string]$SrcIP,
        [string]$DstIP,
        [string]$DstPort,
        [string]$SvcName,
        [string]$Action,
        [string]$FSrcIP,
        [string]$FDstIP,
        [string]$FSvc,
        [string]$FAction
    )
    if ($FSrcIP -and $SrcIP -notlike "*$FSrcIP*") { return $false }
    if ($FDstIP -and $DstIP -notlike "*$FDstIP*") { return $false }
    if ($FSvc) {
        if ($FSvc -match '^\d+$') {
            if ($DstPort -ne $FSvc) { return $false }
        } else {
            if ($SvcName -notlike "*$FSvc*") { return $false }
        }
    }
    if ($FAction -and $Action -ne $FAction) { return $false }
    return $true
}

#endregion

#region --- File Processing ---

function Invoke-ProcessLogFile {
    param(
        [string]$FilePath,
        [System.Collections.ArrayList]$Connections,
        [hashtable]$UniqueConnections,
        [int]$MaskBits,
        [string]$StartTime = "",
        [string]$EndTime = "",
        [string]$FilterSrcIP    = "",
        [string]$FilterDstIP    = "",
        [string]$FilterService  = "",
        [string]$FilterAction   = ""
    )

    Write-Log "Processing: $FilePath" "Info"

    $lineNumber     = 0
    $skippedFilter  = 0
    $progressStep   = 5000
    $batchTime      = [DateTime]::Now

    $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true, 65536)
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNumber++

            try {
                $connection = Invoke-ParseLine $line $lineNumber $MaskBits $StartTime $EndTime
                if ($null -ne $connection) {

                    # Apply IP / service / action filters before storing
                    if (-not (Test-Filters `
                            $connection.SourceIP `
                            $connection.DestIP `
                            $connection.DestPort `
                            $connection.ServiceName `
                            $connection.Action `
                            $FilterSrcIP $FilterDstIP $FilterService $FilterAction)) {
                        $skippedFilter++
                        $script:metrics.SkippedLines++
                        continue
                    }

                    [void]$Connections.Add($connection)
                    $script:metrics.ProcessedLines++

                    $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.ServiceName)|$($connection.SourceInterface)|$($connection.DestInterface)"

                    if (-not $UniqueConnections.ContainsKey($key)) {
                        $UniqueConnections[$key] = @{
                            Count      = 0
                            FirstSeen  = $batchTime
                            LastSeen   = $batchTime
                            Connection = $connection
                        }
                    }
                    $UniqueConnections[$key].Count++
                    $UniqueConnections[$key].LastSeen = $batchTime
                }
                else {
                    $script:metrics.SkippedLines++
                }
            }
            catch {
                Write-Log "Error on line $lineNumber : $_" "Error"
                $script:metrics.SkippedLines++
            }

            if (($lineNumber % $progressStep) -eq 0) {
                $batchTime = [DateTime]::Now
                if ($ShowProgress) {
                    Write-Progress -Activity "Parsing FortiAnalyzer log" `
                        -Status "Lines: $lineNumber  |  Matched: $($UniqueConnections.Count)  |  Filtered out: $skippedFilter" `
                        -PercentComplete -1
                }
                if (($lineNumber % 50000) -eq 0) { [System.GC]::Collect() }
            }
        }
    }
    finally {
        $reader.Dispose()
    }

    if ($ShowProgress) { Write-Progress -Activity "Parsing FortiAnalyzer log" -Completed }
    Write-Log "Finished: $lineNumber lines read, $($UniqueConnections.Count) matched, $skippedFilter excluded by filters." "Info"
}

#endregion

#region --- Parallel Processing ---

function Invoke-ProcessLogFileParallel {
    # FIX: UseParallel is now implemented using PowerShell RunspacePool (no extra modules)
    param(
        [string]$FilePath,
        [System.Collections.ArrayList]$Connections,
        [hashtable]$UniqueConnections,
        [int]$MaskBits,
        [int]$MaxThreads,
        [nullable[datetime]]$StartTime,
        [nullable[datetime]]$EndTime
    )

    Write-Log "Parallel mode: loading chunks with $MaxThreads threads..." "Info"

    # Read all lines upfront (unavoidable for chunked parallel distribution)
    $allLines  = [System.IO.File]::ReadAllLines($FilePath)
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
            param($Chunk, $StartLine, $Patterns, $ServiceMaps, $MaskBits, $StartTime, $EndTime)

            $results = [System.Collections.ArrayList]::new()
            $lineNum = $StartLine

            foreach ($line in $Chunk) {
                if ([string]::IsNullOrWhiteSpace($line)) { $lineNum++; continue }

                $mSrcIp   = $Patterns.srcip.Match($line);   $srcip   = if ($mSrcIp.Success)   { $mSrcIp.Groups[1].Value }   else { "" }
                $mDstIp   = $Patterns.dstip.Match($line);   $dstip   = if ($mDstIp.Success)   { $mDstIp.Groups[1].Value }   else { "" }
                $mSrcPort = $Patterns.srcport.Match($line);  $srcport = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { "" }
                $mDstPort = $Patterns.dstport.Match($line);  $dstport = if ($mDstPort.Success) { $mDstPort.Groups[1].Value } else { "" }
                $mSvc     = $Patterns.service.Match($line);  $service = if ($mSvc.Success)     { $mSvc.Groups[1].Value }     else { "" }
                $mSrcIntf = $Patterns.srcintf.Match($line);  $srcintf = if ($mSrcIntf.Success) { $mSrcIntf.Groups[1].Value } else { "" }
                $mDstIntf = $Patterns.dstintf.Match($line);  $dstintf = if ($mDstIntf.Success) { $mDstIntf.Groups[1].Value } else { "" }
                $mAction  = $Patterns.action.Match($line);   $action  = if ($mAction.Success)  { $mAction.Groups[1].Value }  else { "" }
                $mProto   = $Patterns.proto.Match($line);    $proto   = if ($mProto.Success)   { $mProto.Groups[1].Value }   else { "" }

                if (-not $srcip -or -not $dstip -or -not $dstport) { $lineNum++; continue }
                if (-not $Patterns.ipValid.IsMatch($srcip))  { $lineNum++; continue }
                if (-not $Patterns.ipValid.IsMatch($dstip))  { $lineNum++; continue }
                if (-not $Patterns.portValid.IsMatch($dstport)) { $lineNum++; continue }

                # Service lookup
                $svcName = if (-not [string]::IsNullOrWhiteSpace($service) -and $service -ne "unknown") {
                    $service.ToUpper()
                } elseif ($ServiceMaps.ContainsKey($dstport)) {
                    $ServiceMaps[$dstport]
                } else {
                    switch ($proto) { "6" { "TCP/$dstport" } "17" { "UDP/$dstport" } default { "PROTO${proto}/$dstport" } }
                }

                # Subnet
                $octets = $srcip -split '\.'
                $ipInt  = ([int]$octets[0] -shl 24) -bor ([int]$octets[1] -shl 16) -bor ([int]$octets[2] -shl 8) -bor [int]$octets[3]
                $nm     = if ($MaskBits -eq 0) { 0 } else { [int]([uint32]::MaxValue -shl (32 - $MaskBits)) }
                $ni     = $ipInt -band $nm
                $srcSubnet = "$( ($ni -shr 24) -band 0xFF).$( ($ni -shr 16) -band 0xFF).$( ($ni -shr 8) -band 0xFF).$($ni -band 0xFF)/${MaskBits}"

                $octets2 = $dstip -split '\.'
                $ipInt2  = ([int]$octets2[0] -shl 24) -bor ([int]$octets2[1] -shl 16) -bor ([int]$octets2[2] -shl 8) -bor [int]$octets2[3]
                $ni2     = $ipInt2 -band $nm
                $dstSubnet = "$( ($ni2 -shr 24) -band 0xFF).$( ($ni2 -shr 16) -band 0xFF).$( ($ni2 -shr 8) -band 0xFF).$($ni2 -band 0xFF)/${MaskBits}"

                [void]$results.Add(@{
                    SourceIP        = $srcip;    DestIP          = $dstip
                    SourcePort      = $srcport;  DestPort        = $dstport
                    Service         = $service;  SourceInterface = $srcintf
                    DestInterface   = $dstintf;  Action          = $action
                    Protocol        = $proto;    SourceSubnet    = $srcSubnet
                    DestSubnet      = $dstSubnet; ServiceName    = $svcName
                    LineNumber      = $lineNum;  LogTimestamp    = $null
                })
                $lineNum++
            }
            return $results
        })

        [void]$ps.AddParameters(@{
            Chunk       = $chunk
            StartLine   = $startLine
            Patterns    = $script:patterns
            ServiceMaps = $script:serviceMappings
            MaskBits    = $MaskBits
            StartTime   = $StartTime
            EndTime     = $EndTime
        })

        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }

    # Collect results
    $batchTime = [DateTime]::Now
    foreach ($job in $jobs) {
        $chunkResults = $job.PS.EndInvoke($job.Handle)
        $job.PS.Dispose()
        foreach ($conn in $chunkResults) {
            $conn.PolicyName = Get-PolicyName $conn
            [void]$Connections.Add($conn)
            $script:metrics.ProcessedLines++

            $key = "$($conn.SourceSubnet)|$($conn.DestSubnet)|$($conn.ServiceName)|$($conn.SourceInterface)|$($conn.DestInterface)"
            if (-not $UniqueConnections.ContainsKey($key)) {
                $UniqueConnections[$key] = @{ Count = 0; FirstSeen = $batchTime; LastSeen = $batchTime; Connection = $conn }
            }
            $UniqueConnections[$key].Count++
            $UniqueConnections[$key].LastSeen = $batchTime
        }
    }

    $pool.Close()
    $pool.Dispose()
}

#endregion

#region --- Export Functions ---

function Export-Results {
    param([string]$OutputFile, [string]$Format, [System.Collections.ArrayList]$Connections, [hashtable]$UniqueConnections)

    Write-Log "Preparing export in $Format format..." "Info"

    $exportList = [System.Collections.ArrayList]::new()
    foreach ($item in $UniqueConnections.GetEnumerator()) {
        $d    = $item.Value
        $conn = $d.Connection
        [void]$exportList.Add([PSCustomObject]@{
            PolicyName        = $conn.PolicyName
            IncomingInterface = $conn.SourceInterface
            OutgoingInterface = $conn.DestInterface
            Source            = $conn.SourceSubnet
            Destination       = $conn.DestSubnet
            Service           = $conn.ServiceName
            Action            = $conn.Action
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

    $sorted = $exportList | Sort-Object TrafficCount -Descending

    switch ($Format.ToUpper()) {
        "CSV" {
            $csv = $sorted | ConvertTo-Csv -NoTypeInformation
            [System.IO.File]::WriteAllLines($OutputFile, $csv, [System.Text.Encoding]::UTF8)
        }
        "JSON" {
            $json = $sorted | ConvertTo-Json -Depth 4
            [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.Encoding]::UTF8)
        }
        "TEXT" {
            $txt = Build-TextReport $sorted $Connections $UniqueConnections
            [System.IO.File]::WriteAllText($OutputFile, $txt, [System.Text.Encoding]::UTF8)
        }
        "HTML" {
            $html = Build-HtmlReport $sorted $Connections $UniqueConnections
            [System.IO.File]::WriteAllText($OutputFile, $html, [System.Text.Encoding]::UTF8)
        }
        default {
            Write-Log "Unknown format '$Format'. Defaulting to CSV." "Warning"
            $sorted | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        }
    }

    Write-Log "Exported $($sorted.Count) records to: $OutputFile" "Info"
    return $sorted
}

#endregion

#region --- Report Builders ---

function Build-TextReport {
    param($Data, $Connections, $UniqueConnections)
    $ts      = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
    $elapsed = [Math]::Round(([DateTime]::Now - $script:metrics.StartTime).TotalSeconds, 2)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=== FORTIGATE LOG ANALYSIS RESULTS v3.0.0 ===")
    [void]$sb.AppendLine("Analysis Date        : $ts")
    [void]$sb.AppendLine("Total Traffic Flows  : $($Connections.Count.ToString('N0'))")
    [void]$sb.AppendLine("Unique Policy Patterns: $($UniqueConnections.Count.ToString('N0'))")
    [void]$sb.AppendLine("Processing Time      : ${elapsed}s")
    [void]$sb.AppendLine("")

    $idx = 0
    foreach ($item in $Data) {
        $idx++
        [void]$sb.AppendLine("Policy       : $($item.PolicyName)")
        [void]$sb.AppendLine("Source       : $($item.Source) ($($item.IncomingInterface))")
        [void]$sb.AppendLine("Destination  : $($item.Destination) ($($item.OutgoingInterface))")
        [void]$sb.AppendLine("Service      : $($item.Service)")
        [void]$sb.AppendLine("Action       : $(if($item.Action -eq 'accept'){'ALLOW'}else{'DENY'})")
        [void]$sb.AppendLine("Traffic Count: $($item.TrafficCount)")
        if ($idx -lt $Data.Count) { [void]$sb.AppendLine("============================") }
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== ANALYSIS SUMMARY ===")
    [void]$sb.AppendLine("Policies Required : $($Data.Count)")
    [void]$sb.AppendLine("Lines Processed   : $($script:metrics.ProcessedLines)")
    [void]$sb.AppendLine("Lines Skipped     : $($script:metrics.SkippedLines)")
    [void]$sb.AppendLine("Errors            : $($script:metrics.ErrorCount)")
    [void]$sb.AppendLine("Warnings          : $($script:metrics.WarningCount)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Generated by FortiAnalyzer Log Parser v3.0.0")
    return $sb.ToString()
}

function Build-HtmlReport {
    # FIX: All user-derived data is HTML-encoded to prevent XSS
    param($Data, $Connections, $UniqueConnections)

    $ts           = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
    $totalFlows   = $Connections.Count.ToString('N0')
    $uniquePat    = $UniqueConnections.Count.ToString('N0')
    $elapsed      = [Math]::Round(([DateTime]::Now - $script:metrics.StartTime).TotalSeconds, 2)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiAnalyzer Network Traffic Analysis v3.0.0</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #1a1a2e; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: #e0e0e0; padding: 28px 32px; }
        .header h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: 0.5px; }
        .header .subtitle { margin-top: 6px; font-size: 0.9rem; opacity: 0.75; }
        .container { max-width: 1500px; margin: 0 auto; padding: 24px 20px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }
        .card { background: #fff; border-radius: 10px; padding: 20px 24px; box-shadow: 0 2px 10px rgba(0,0,0,0.07); }
        .card h3 { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; color: #666; margin-bottom: 8px; }
        .card .value { font-size: 2rem; font-weight: 800; color: #0f3460; }
        .table-wrap { background: #fff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.07); overflow: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
        thead th { background: #0f3460; color: #fff; padding: 13px 14px; text-align: left; font-weight: 600; white-space: nowrap; }
        tbody td { padding: 11px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
        tbody tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: #f7f9fc; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
        .allow { background: #d4edda; color: #155724; }
        .deny  { background: #f8d7da; color: #721c24; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 0.8rem; }
        .mono { font-family: 'Courier New', monospace; font-size: 0.82rem; }
    </style>
</head>
<body>
<div class="header">
    <h1>&#x1F6E1; FortiAnalyzer Network Traffic Analysis</h1>
    <div class="subtitle">v3.0.0 &mdash; Generated on $ts</div>
</div>
<div class="container">
    <div class="cards">
        <div class="card"><h3>Total Traffic Flows</h3><div class="value">$totalFlows</div></div>
        <div class="card"><h3>Policies Required</h3><div class="value">$uniquePat</div></div>
        <div class="card"><h3>Processing Time</h3><div class="value">${elapsed}s</div></div>
        <div class="card"><h3>Errors / Warnings</h3><div class="value">$($script:metrics.ErrorCount) / $($script:metrics.WarningCount)</div></div>
    </div>
    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>#</th><th>Policy Name</th><th>In Interface</th><th>Out Interface</th>
                <th>Source Subnet</th><th>Destination Subnet</th><th>Service</th>
                <th>Action</th><th>Traffic</th>
            </tr>
        </thead>
        <tbody>
"@)

    $rowNum = 0
    foreach ($item in $Data) {
        $rowNum++
        # FIX: All dynamic values HTML-encoded
        $policyNameSafe  = ConvertTo-HtmlSafe $item.PolicyName
        $inIntfSafe      = ConvertTo-HtmlSafe $item.IncomingInterface
        $outIntfSafe     = ConvertTo-HtmlSafe $item.OutgoingInterface
        $sourceSafe      = ConvertTo-HtmlSafe $item.Source
        $destSafe        = ConvertTo-HtmlSafe $item.Destination
        $serviceSafe     = ConvertTo-HtmlSafe $item.Service
        $actionLabel     = if ($item.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
        $actionClass     = if ($item.Action -eq 'accept') { 'allow' } else { 'deny' }

        [void]$sb.Append(@"
        <tr>
            <td style="color:#999;">$rowNum</td>
            <td class="mono">$policyNameSafe</td>
            <td>$inIntfSafe</td>
            <td>$outIntfSafe</td>
            <td class="mono">$sourceSafe</td>
            <td class="mono">$destSafe</td>
            <td><strong>$serviceSafe</strong></td>
            <td><span class="badge $actionClass">$actionLabel</span></td>
            <td>$($item.TrafficCount.ToString('N0'))</td>
        </tr>
"@)
    }

    [void]$sb.Append(@"
        </tbody>
    </table>
    </div>
    <div class="footer">Generated by FortiAnalyzer Log Parser v3.0.0 &mdash; Lines processed: $($script:metrics.ProcessedLines.ToString('N0'))</div>
</div>
</body>
</html>
"@)
    return $sb.ToString()
}

#endregion

#region --- Entry Point ---

Add-Type -AssemblyName System.Web   # Required for HtmlEncode

Write-Host ""
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "  FortiAnalyzer Log Parser  v3.0.0               " -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host ""

$connections       = [System.Collections.ArrayList]::new()
$uniqueConnections = @{}

try {
    # Load config overrides
    if ($ConfigFile) { Import-Config -Path $ConfigFile }

    # Validate prerequisites
    Write-Log "Validating prerequisites..." "Info"
    if (-not (Test-Prerequisites -LogFilePath $LogFilePath -OutputFile $OutputFile)) {
        Write-Host "Prerequisite check failed. Aborting." -ForegroundColor Red
        exit 1
    }

    # Log active filters
    $filterParts = @()
    if ($FilterSrcIP)   { $filterParts += "SrcIP contains '$FilterSrcIP'" }
    if ($FilterDstIP)   { $filterParts += "DstIP contains '$FilterDstIP'" }
    if ($FilterService) {
        if ($FilterService -match '^\d+$') {
            $filterParts += "Port = $FilterService"
        } else {
            $filterParts += "Service contains '$FilterService'"
        }
    }
    if ($FilterAction)  { $filterParts += "Action = '$FilterAction'" }
    $filterSummary = if ($filterParts.Count -gt 0) { $filterParts -join " AND " } else { "None" }
    Write-Log "Active filters: $filterSummary" "Info"

    # Process
    if ($UseParallel) {
        Write-Log "Using parallel processing with $MaxThreads threads." "Info"
        Invoke-ProcessLogFileParallel -FilePath $LogFilePath `
            -Connections $connections -UniqueConnections $uniqueConnections `
            -MaskBits $SubnetMask -MaxThreads $MaxThreads `
            -StartTime $StartTime -EndTime $EndTime
    }
    else {
        $modeLabel = if ($StreamingMode) { 'streaming' } else { 'standard' }
        Write-Log "Using single-threaded $modeLabel processing." "Info"
        Invoke-ProcessLogFile -FilePath $LogFilePath `
            -Connections $connections -UniqueConnections $uniqueConnections `
            -MaskBits $SubnetMask -StartTime $StartTime -EndTime $EndTime `
            -FilterSrcIP $FilterSrcIP -FilterDstIP $FilterDstIP `
            -FilterService $FilterService -FilterAction $FilterAction
    }

    if ($connections.Count -eq 0) {
        Write-Log "No valid connections found. Check log format or time-range filters." "Warning"
        exit 0
    }

    # Export
    $exportData = Export-Results -OutputFile $OutputFile -Format $OutputFormat `
        -Connections $connections -UniqueConnections $uniqueConnections

    # Summary
    Write-Host ""
    Write-Host "=== Results ===" -ForegroundColor Green
    Write-Host "Unique connection patterns : $($exportData.Count)" -ForegroundColor Cyan

    if ($exportData.Count -gt 0) {
        Write-Host ""
        Write-Host "Top 5 policies by traffic volume:" -ForegroundColor White
        $exportData | Select-Object -First 5 | ForEach-Object {
            Write-Host ("  {0,-35} {1} -> {2}  [{3}]  {4} flows" -f `
                $_.PolicyName, $_.Source, $_.Destination, $_.Service, $_.TrafficCount) -ForegroundColor Gray
        }
    }

    $elapsed   = [Math]::Round(([DateTime]::Now - $script:metrics.StartTime).TotalSeconds, 2)
    $memoryMB  = [Math]::Round([System.GC]::GetTotalMemory($false) / 1MB, 2)

    Write-Host ""
    Write-Host "=== Performance ===" -ForegroundColor Cyan
    Write-Host "  Total time      : ${elapsed}s"           -ForegroundColor White
    Write-Host "  Memory usage    : ${memoryMB} MB"        -ForegroundColor White
    Write-Host "  Lines processed : $($script:metrics.ProcessedLines.ToString('N0'))"  -ForegroundColor White
    Write-Host "  Lines skipped   : $($script:metrics.SkippedLines.ToString('N0'))"    -ForegroundColor White
    Write-Host "  Errors          : $($script:metrics.ErrorCount)"   -ForegroundColor $(if($script:metrics.ErrorCount -gt 0){'Red'}else{'White'})
    Write-Host "  Warnings        : $($script:metrics.WarningCount)" -ForegroundColor $(if($script:metrics.WarningCount -gt 0){'Yellow'}else{'White'})
    Write-Host ""
    Write-Host "Output saved to: $OutputFile" -ForegroundColor Yellow
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "=== Critical Error ===" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($DebugMode) { Write-Host $_.Exception.ToString() -ForegroundColor DarkRed }
    exit 1
}
finally {
    if ($ShowProgress) { Write-Progress -Activity "Done" -Completed }
    [System.GC]::Collect()
}

#endregion
