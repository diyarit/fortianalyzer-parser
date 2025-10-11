<#
.SYNOPSIS
    FortiAnalyzer Log Parser
.DESCRIPTION
    Parses FortiAnalyzer logs and extracts network traffic patterns for analysis.
    Exports connection data to CSV, JSON, or HTML format for further review and analysis.
.AUTHOR
    Diyar Abbas
.VERSION
    2.2
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true)]
    [string]$LogFilePath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "NetworkTraffic.csv",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML")]
    [string]$OutputFormat = "CSV",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress,
    
    [Parameter(Mandatory=$false)]
    [switch]$DebugMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseParallel,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 16)]
    [int]$MaxThreads = 4
)

# Pre-compiled regex patterns for better performance
$patterns = @{
    srcip = [regex]::new('srcip=(\d+\.\d+\.\d+\.\d+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstip = [regex]::new('dstip=(\d+\.\d+\.\d+\.\d+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcport = [regex]::new('srcport=(\d+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstport = [regex]::new('dstport=(\d+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    service = [regex]::new('service="([^"]+)"', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcintf = [regex]::new('srcintf="([^"]+)"', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstintf = [regex]::new('dstintf="([^"]+)"', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    action = [regex]::new('action="([^"]+)"', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    proto = [regex]::new('proto=(\d+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

# IP address validation regex
$ipValidationRegex = [regex]::new('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

# Port validation regex (1-65535)
$portValidationRegex = [regex]::new('^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$', [System.Text.RegularExpressions.RegexOptions]::Compiled)

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

# Error tracking
$errorCount = 0
$warningCount = 0
$processedLines = 0
$skippedLines = 0

# Memory monitoring
$initialMemory = [System.GC]::GetTotalMemory($false)

function Test-InputValidation {
    param(
        [string]$LogFilePath,
        [string]$OutputFile
    )
    
    try {
        # Validate input file
        if (-not (Test-Path $LogFilePath)) {
            throw "Log file not found: $LogFilePath"
        }
        
        $fileInfo = Get-Item $LogFilePath
        if ($fileInfo.Length -eq 0) {
            throw "Log file is empty: $LogFilePath"
        }
        
        # Check file size and warn if very large
        $fileSizeMB = [Math]::Round($fileInfo.Length / 1MB, 2)
        if ($fileSizeMB -gt 500) {
            Write-Warning "Large file detected ($fileSizeMB MB). Processing may take significant time."
            if ($ShowProgress) {
                Write-Host "Consider using -ShowProgress for better monitoring." -ForegroundColor Yellow
            }
        }
        
        # Validate output file path
        $outputDir = Split-Path $OutputFile -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            try {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                if ($DebugMode) { Write-Host "Created output directory: $outputDir" -ForegroundColor Green }
            } catch {
                throw "Cannot create output directory: $outputDir. Error: $_"
            }
        }
        
        # Check write permissions for output file
        try {
            [System.IO.File]::WriteAllText($OutputFile, "")
            Remove-Item $OutputFile -Force
        } catch {
            throw "Cannot write to output file: $OutputFile. Error: $_"
        }
        
        if ($DebugMode) { Write-Host "Input validation completed successfully" -ForegroundColor Green }
        return $true
        
    } catch {
        Write-Error "Input validation failed: $_"
        return $false
    }
}

function Test-IPAddress {
    param([string]$ipAddress)
    
    if ([string]::IsNullOrWhiteSpace($ipAddress)) {
        return $false
    }
    
    return $ipValidationRegex.IsMatch($ipAddress)
}

function Test-PortNumber {
    param([string]$port)
    
    if ([string]::IsNullOrWhiteSpace($port)) {
        return $false
    }
    
    return $portValidationRegex.IsMatch($port)
}

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { 
            Write-Error $logMessage
            $script:errorCount++
        }
        "Warning" { 
            Write-Warning $logMessage
            $script:warningCount++
        }
        "Verbose" { 
            if ($DebugMode) { Write-Host $logMessage -ForegroundColor Cyan }
        }
        default { 
            Write-Host $logMessage -ForegroundColor White
        }
    }
}

function Get-MemoryUsage {
    $currentMemory = [System.GC]::GetTotalMemory($false)
    $memoryUsed = [Math]::Round(($currentMemory - $initialMemory) / 1MB, 2)
    return $memoryUsed
}

function Convert-ToSubnet {
    param([string]$ipAddress)
    
    try {
        if (-not (Test-IPAddress $ipAddress)) {
            Write-LogMessage "Invalid IP address for subnet conversion: $ipAddress" "Warning"
            return $ipAddress
        }
        
        $octets = $ipAddress -split '\.'
        if ($octets.Count -eq 4) {
            return "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
        }
        return $ipAddress
    } catch {
        Write-LogMessage "Error converting IP to subnet: $ipAddress - $_" "Error"
        return $ipAddress
    }
}

function Get-ServiceName {
    param([string]$port, [string]$protocol)
    
    try {
        if ([string]::IsNullOrWhiteSpace($port)) {
            return "unknown"
        }
        
        if ($serviceMappings.ContainsKey($port)) {
            return $serviceMappings[$port]
        }
        return "tcp/$port"
    } catch {
        Write-LogMessage "Error getting service name for port $port - $_" "Error"
        return "tcp/$port"
    }
}

function Process-LogChunk {
    param(
        [string[]]$Lines,
        [int]$StartLineNumber = 0
    )
    
    $localConnections = [System.Collections.ArrayList]::new()
    $localUniqueConnections = @{}
    $localProcessedLines = 0
    $localSkippedLines = 0
    $localErrorCount = 0
    $localWarningCount = 0
    
    foreach ($line in $Lines) {
        $localProcessedLines++
        
        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) {
            $localSkippedLines++
            continue
        }
        
        try {
            # Extract fields using pre-compiled regex patterns
            $srcip = $null
            $dstip = $null
            $srcport = $null
            $dstport = $null
            $service = $null
            $srcintf = $null
            $dstintf = $null
            $action = $null
            $proto = $null
            
            # Use pre-compiled regex for better performance
            $srcipMatch = $patterns.srcip.Match($line)
            if ($srcipMatch.Success) { $srcip = $srcipMatch.Groups[1].Value }
            
            $dstipMatch = $patterns.dstip.Match($line)
            if ($dstipMatch.Success) { $dstip = $dstipMatch.Groups[1].Value }
            
            $srcportMatch = $patterns.srcport.Match($line)
            if ($srcportMatch.Success) { $srcport = $srcportMatch.Groups[1].Value }
            
            $dstportMatch = $patterns.dstport.Match($line)
            if ($dstportMatch.Success) { $dstport = $dstportMatch.Groups[1].Value }
            
            $serviceMatch = $patterns.service.Match($line)
            if ($serviceMatch.Success) { $service = $serviceMatch.Groups[1].Value }
            
            $srcintfMatch = $patterns.srcintf.Match($line)
            if ($srcintfMatch.Success) { $srcintf = $srcintfMatch.Groups[1].Value }
            
            $dstintfMatch = $patterns.dstintf.Match($line)
            if ($dstintfMatch.Success) { $dstintf = $dstintfMatch.Groups[1].Value }
            
            $actionMatch = $patterns.action.Match($line)
            if ($actionMatch.Success) { $action = $actionMatch.Groups[1].Value }
            
            $protoMatch = $patterns.proto.Match($line)
            if ($protoMatch.Success) { $proto = $protoMatch.Groups[1].Value }
            
            # Validate essential fields
            if (-not $srcip -or -not $dstip -or -not $dstport) {
                $localSkippedLines++
                if ($DebugMode) { Write-LogMessage "Skipping line $($StartLineNumber + $localProcessedLines) - missing essential fields" "Verbose" }
                continue
            }
            
            # Validate IP addresses
            if (-not (Test-IPAddress $srcip)) {
                Write-LogMessage "Invalid source IP address on line $($StartLineNumber + $localProcessedLines) : $srcip" "Warning"
                $localSkippedLines++
                $localWarningCount++
                continue
            }
            
            if (-not (Test-IPAddress $dstip)) {
                Write-LogMessage "Invalid destination IP address on line $($StartLineNumber + $localProcessedLines) : $dstip" "Warning"
                $localSkippedLines++
                $localWarningCount++
                continue
            }
            
            # Validate port numbers
            if ($srcport -and -not (Test-PortNumber $srcport)) {
                Write-LogMessage "Invalid source port on line $($StartLineNumber + $localProcessedLines) : $srcport" "Warning"
                $srcport = $null
                $localWarningCount++
            }
            
            if (-not (Test-PortNumber $dstport)) {
                Write-LogMessage "Invalid destination port on line $($StartLineNumber + $localProcessedLines) : $dstport" "Warning"
                $localSkippedLines++
                $localWarningCount++
                continue
            }
            
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
            
            [void]$localConnections.Add($connection)
        
            # Create unique connection key
            $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.Service)|$($connection.SourceInterface)|$($connection.DestInterface)"
            
            if (-not $localUniqueConnections.ContainsKey($key)) {
                $localUniqueConnections[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                    Connection = $connection
                }
            }
            
            $localUniqueConnections[$key].Count++
            $localUniqueConnections[$key].LastSeen = Get-Date
            
        } catch {
            Write-LogMessage "Error processing line $($StartLineNumber + $localProcessedLines) : $_" "Error"
            $localSkippedLines++
            $localErrorCount++
            continue
        }
    }
    
    return @{
        Connections = $localConnections
        UniqueConnections = $localUniqueConnections
        ProcessedLines = $localProcessedLines
        SkippedLines = $localSkippedLines
        ErrorCount = $localErrorCount
        WarningCount = $localWarningCount
    }
}

function Parse-LogFile {
    param([string]$filePath)
    
    try {
        Write-LogMessage "Starting log file parsing: $filePath" "Info"
        
        $lineCount = 0
        $totalLines = 0
        $startTime = Get-Date
        
        # Get total lines efficiently for progress tracking
        if ($ShowProgress) {
            Write-LogMessage "Calculating total lines for progress tracking..." "Verbose"
            try {
                $totalLines = (Get-Content $filePath -ReadCount 1000 | Measure-Object).Count
                Write-LogMessage "Total lines to process: $totalLines" "Info"
            } catch {
                Write-LogMessage "Could not calculate total lines, progress tracking disabled: $_" "Warning"
                $totalLines = 0
            }
        }
        
        # Determine if we should use parallel processing
        if ($UseParallel) {
            Write-LogMessage "Using parallel processing with $MaxThreads threads" "Info"
            
            # Check if ThreadJob module is available
            if (-not (Get-Module -ListAvailable -Name ThreadJob)) {
                Write-LogMessage "ThreadJob module not available. Falling back to sequential processing." "Warning"
                $UseParallel = $false
            } else {
                try {
                    Import-Module ThreadJob
                } catch {
                    Write-LogMessage "Failed to import ThreadJob module. Falling back to sequential processing: $_" "Warning"
                    $UseParallel = $false
                }
            }
            
            if ($UseParallel) {
                # Import the ThreadJob module
                Import-Module ThreadJob
                
                # Read the file in chunks
                $chunkSize = 1000
                $fileContent = Get-Content $filePath
                $chunks = [System.Collections.ArrayList]::new()
                
                # If file is empty, handle gracefully
                if ($fileContent.Count -eq 0) {
                    Write-LogMessage "Warning: Log file appears to be empty" "Warning"
                    return
                }
                
                for ($i = 0; $i -lt $fileContent.Count; $i += $chunkSize) {
                    $end = [Math]::Min($i + $chunkSize - 1, $fileContent.Count - 1)
                    [void]$chunks.Add($fileContent[$i..$end])
                }
                
                Write-LogMessage "File divided into $($chunks.Count) chunks for parallel processing" "Info"
                
                # Process chunks in parallel
                $jobs = @()
                foreach ($index in 0..($chunks.Count-1)) {
                    $startLine = $index * $chunkSize
                    $jobs += Start-ThreadJob -ScriptBlock {
                        param($chunk, $startLine)
                        
                        # Define helper functions in the job scope
                        function Test-IPAddress {
                            param([string]$ipAddress)
                            if ([string]::IsNullOrWhiteSpace($ipAddress)) { return $false }
                            return $ipAddress -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                        }
                        
                        function Test-PortNumber {
                            param([string]$port)
                            if ([string]::IsNullOrWhiteSpace($port)) { return $false }
                            return $port -match '^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
                        }
                        
                        function Get-ServiceName {
                            param([string]$port, [string]$protocol)
                            if ([string]::IsNullOrWhiteSpace($port)) { return "unknown" }
                            $serviceMappings = @{
                                '53' = 'DNS'; '80' = 'HTTP'; '443' = 'HTTPS'; '135' = 'DCE-RPC'
                                '3389' = 'RDP'; '9100' = 'TCP-9100'; '7680' = 'tcp/7680'; '9396' = 'VeeamConsole'
                            }
                            if ($serviceMappings.ContainsKey($port)) { return $serviceMappings[$port] }
                            return "tcp/$port"
                        }
                        
                        function Convert-ToSubnet {
                            param([string]$ipAddress)
                            if (-not (Test-IPAddress $ipAddress)) { return $ipAddress }
                            $octets = $ipAddress -split '\.'
                            if ($octets.Count -eq 4) { return "$($octets[0]).$($octets[1]).$($octets[2]).0/24" }
                            return $ipAddress
                        }
                        
                        # Process the chunk
                        $localConnections = [System.Collections.ArrayList]::new()
                        $localUniqueConnections = @{}
                        $localProcessedLines = 0
                        $localSkippedLines = 0
                        $localErrorCount = 0
                        $localWarningCount = 0
                        
                        foreach ($line in $chunk) {
                            $localProcessedLines++
                            
                            # Skip empty lines
                            if ([string]::IsNullOrWhiteSpace($line)) {
                                $localSkippedLines++
                                continue
                            }
                            
                            try {
                                # Extract fields using regex patterns
                                $srcip = $null; $dstip = $null; $srcport = $null; $dstport = $null
                                $service = $null; $srcintf = $null; $dstintf = $null; $action = $null; $proto = $null
                                
                                if ($line -match 'srcip=(\d+\.\d+\.\d+\.\d+)') { $srcip = $matches[1] }
                                if ($line -match 'dstip=(\d+\.\d+\.\d+\.\d+)') { $dstip = $matches[1] }
                                if ($line -match 'srcport=(\d+)') { $srcport = $matches[1] }
                                if ($line -match 'dstport=(\d+)') { $dstport = $matches[1] }
                                if ($line -match 'service="([^"]+)"') { $service = $matches[1] }
                                if ($line -match 'srcintf="([^"]+)"') { $srcintf = $matches[1] }
                                if ($line -match 'dstintf="([^"]+)"') { $dstintf = $matches[1] }
                                if ($line -match 'action="([^"]+)"') { $action = $matches[1] }
                                if ($line -match 'proto=(\d+)') { $proto = $matches[1] }
                                
                                # Validate essential fields
                                if (-not $srcip -or -not $dstip -or -not $dstport) {
                                    $localSkippedLines++
                                    continue
                                }
                                
                                # Validate IP addresses
                                if (-not (Test-IPAddress $srcip) -or -not (Test-IPAddress $dstip)) {
                                    $localWarningCount++
                                    $localSkippedLines++
                                    continue
                                }
                                
                                if (-not (Test-PortNumber $dstport)) {
                                    $localWarningCount++
                                    $localSkippedLines++
                                    continue
                                }
                                
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
                                
                                [void]$localConnections.Add($connection)
                            
                                # Create unique connection key
                                $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.Service)|$($connection.SourceInterface)|$($connection.DestInterface)"
                                
                                if (-not $localUniqueConnections.ContainsKey($key)) {
                                    $localUniqueConnections[$key] = @{
                                        Count = 0
                                        FirstSeen = Get-Date
                                        LastSeen = Get-Date
                                        Connection = $connection
                                    }
                                }
                                
                                $localUniqueConnections[$key].Count++
                                $localUniqueConnections[$key].LastSeen = Get-Date
                                
                            } catch {
                                $localErrorCount++
                                $localSkippedLines++
                                continue
                            }
                        }
                        
                        return @{
                            Connections = $localConnections
                            UniqueConnections = $localUniqueConnections
                            ProcessedLines = $localProcessedLines
                            SkippedLines = $localSkippedLines
                            ErrorCount = $localErrorCount
                            WarningCount = $localWarningCount
                        }
                    } -ArgumentList $chunks[$index], $startLine -ThrottleLimit $MaxThreads
                }
                
                # Track progress
                if ($ShowProgress) {
                    $completedJobs = 0
                    while ($completedJobs -lt $jobs.Count) {
                        $completedJobs = ($jobs | Where-Object { $_.State -eq 'Completed' }).Count
                        $percent = [Math]::Min(($completedJobs / $jobs.Count * 100), 100)
                        $memoryUsage = Get-MemoryUsage
                        Write-Progress -Activity "Parsing logs in parallel" -Status "Progress: $completedJobs/$($jobs.Count) jobs completed (Memory: ${memoryUsage}MB)" -PercentComplete $percent
                        Start-Sleep -Milliseconds 500
                    }
                }
                
                # Collect results from all jobs
                Write-LogMessage "Collecting results from parallel jobs..." "Info"
                foreach ($job in $jobs) {
                    $result = Receive-Job -Job $job
                    
                    # Merge connections
                    foreach ($conn in $result.Connections) {
                        [void]$connections.Add($conn)
                    }
                    
                    # Merge unique connections
                    foreach ($key in $result.UniqueConnections.Keys) {
                        if (-not $uniqueConnections.ContainsKey($key)) {
                            $uniqueConnections[$key] = $result.UniqueConnections[$key]
                        } else {
                            $uniqueConnections[$key].Count += $result.UniqueConnections[$key].Count
                            if ($result.UniqueConnections[$key].FirstSeen -lt $uniqueConnections[$key].FirstSeen) {
                                $uniqueConnections[$key].FirstSeen = $result.UniqueConnections[$key].FirstSeen
                            }
                            if ($result.UniqueConnections[$key].LastSeen -gt $uniqueConnections[$key].LastSeen) {
                                $uniqueConnections[$key].LastSeen = $result.UniqueConnections[$key].LastSeen
                            }
                        }
                    }
                    
                    # Update counters
                    $script:processedLines += $result.ProcessedLines
                    $script:skippedLines += $result.SkippedLines
                    $script:errorCount += $result.ErrorCount
                    $script:warningCount += $result.WarningCount
                    
                    # Clean up job
                    Remove-Job -Job $job -Force
                }
            }
        }
        
        # If not using parallel processing or parallel processing failed, use sequential processing
        if (-not $UseParallel) {
            Write-LogMessage "Using sequential processing" "Info"
            
            # Process file in chunks for memory efficiency
            Get-Content $filePath -ReadCount 1000 | ForEach-Object {
                $chunkResult = Process-LogChunk -Lines $_ -StartLineNumber $lineCount
                
                # Update line count
                $lineCount += $chunkResult.ProcessedLines + $chunkResult.SkippedLines
                
                # Update global counters
                $script:processedLines += $chunkResult.ProcessedLines
                $script:skippedLines += $chunkResult.SkippedLines
                $script:errorCount += $chunkResult.ErrorCount
                $script:warningCount += $chunkResult.WarningCount
                
                # Merge connections
                foreach ($conn in $chunkResult.Connections) {
                    [void]$connections.Add($conn)
                }
                
                # Merge unique connections
                foreach ($key in $chunkResult.UniqueConnections.Keys) {
                    if (-not $uniqueConnections.ContainsKey($key)) {
                        $uniqueConnections[$key] = $chunkResult.UniqueConnections[$key]
                    } else {
                        $uniqueConnections[$key].Count += $chunkResult.UniqueConnections[$key].Count
                        if ($chunkResult.UniqueConnections[$key].FirstSeen -lt $uniqueConnections[$key].FirstSeen) {
                            $uniqueConnections[$key].FirstSeen = $chunkResult.UniqueConnections[$key].FirstSeen
                        }
                        if ($chunkResult.UniqueConnections[$key].LastSeen -gt $uniqueConnections[$key].LastSeen) {
                            $uniqueConnections[$key].LastSeen = $chunkResult.UniqueConnections[$key].LastSeen
                        }
                    }
                }
                
                # Progress tracking
                if ($ShowProgress) {
                    $percent = if ($totalLines -gt 0) { [Math]::Min(($lineCount/$totalLines*100), 100) } else { 0 }
                    $memoryUsage = Get-MemoryUsage
                    Write-Progress -Activity "Parsing logs" -Status "Progress: $lineCount/$totalLines (Memory: ${memoryUsage}MB)" -PercentComplete $percent
                }
            }
        }
        
        $endTime = Get-Date
        $processingTime = ($endTime - $startTime).TotalSeconds
        $memoryUsage = Get-MemoryUsage
        
        Write-LogMessage "Parsing completed successfully" "Info"
        Write-LogMessage "Processing time: $([Math]::Round($processingTime, 2)) seconds" "Info"
        Write-LogMessage "Memory used: ${memoryUsage}MB" "Info"
        Write-LogMessage "Lines processed: $processedLines" "Info"
        Write-LogMessage "Lines skipped: $skippedLines" "Info"
        Write-LogMessage "Connections parsed: $($connections.Count)" "Info"
        Write-LogMessage "Unique patterns found: $($uniqueConnections.Count)" "Info"
        
        if ($errorCount -gt 0) {
            Write-LogMessage "Total errors encountered: $errorCount" "Warning"
        }
        
        if ($warningCount -gt 0) {
            Write-LogMessage "Total warnings: $warningCount" "Warning"
        }
        
    } catch {
        Write-LogMessage "Critical error in Parse-LogFile: $_" "Error"
        throw
    } finally {
        if ($ShowProgress) {
            Write-Progress -Activity "Parsing logs" -Completed
        }
    }
}

# Function to process log chunks in parallel
function Process-LogChunk {
    param(
        [string[]]$Lines,
        [int]$StartLineNumber = 0
    )
    
    $localConnections = [System.Collections.ArrayList]::new()
    $localUniqueConnections = @{}
    $localProcessedLines = 0
    $localSkippedLines = 0
    $localErrorCount = 0
    $localWarningCount = 0
    
    foreach ($line in $Lines) {
        $localProcessedLines++
        
        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) {
            $localSkippedLines++
            continue
        }
        
        try {
            # Extract fields using regex patterns
            $srcip = $null; $dstip = $null; $srcport = $null; $dstport = $null
            $service = $null; $srcintf = $null; $dstintf = $null; $action = $null; $proto = $null
            
            if ($line -match 'srcip=(\d+\.\d+\.\d+\.\d+)') { $srcip = $matches[1] }
            if ($line -match 'dstip=(\d+\.\d+\.\d+\.\d+)') { $dstip = $matches[1] }
            if ($line -match 'srcport=(\d+)') { $srcport = $matches[1] }
            if ($line -match 'dstport=(\d+)') { $dstport = $matches[1] }
            if ($line -match 'service="([^"]+)"') { $service = $matches[1] }
            if ($line -match 'srcintf="([^"]+)"') { $srcintf = $matches[1] }
            if ($line -match 'dstintf="([^"]+)"') { $dstintf = $matches[1] }
            if ($line -match 'action="([^"]+)"') { $action = $matches[1] }
            if ($line -match 'proto=(\d+)') { $proto = $matches[1] }
            
            # Validate essential fields
            if (-not $srcip -or -not $dstip -or -not $dstport) {
                $localSkippedLines++
                continue
            }
            
            # Validate IP addresses and ports
            if (-not (Test-IPAddress $srcip) -or -not (Test-IPAddress $dstip)) {
                $localWarningCount++
                $localSkippedLines++
                continue
            }
            
            if (-not (Test-PortNumber $dstport)) {
                $localWarningCount++
                $localSkippedLines++
                continue
            }
            
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
            
            [void]$localConnections.Add($connection)
        
            # Create unique connection key
            $key = "$($connection.SourceSubnet)|$($connection.DestSubnet)|$($connection.Service)|$($connection.SourceInterface)|$($connection.DestInterface)"
            
            if (-not $localUniqueConnections.ContainsKey($key)) {
                $localUniqueConnections[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                    Connection = $connection
                }
            }
            
            $localUniqueConnections[$key].Count++
            $localUniqueConnections[$key].LastSeen = Get-Date
            
        } catch {
            $localErrorCount++
            $localSkippedLines++
            continue
        }
    }
    
    return @{
        Connections = $localConnections
        UniqueConnections = $localUniqueConnections
        ProcessedLines = $localProcessedLines
        SkippedLines = $localSkippedLines
        ErrorCount = $localErrorCount
        WarningCount = $localWarningCount
    }
}

function Export-NetworkData {
    param(
        [string]$Format = "CSV",
        [string]$OutputFile
    )
    
    try {
        Write-LogMessage "Preparing network data for export in $Format format..." "Info"
        
        $exportData = [System.Collections.ArrayList]::new()
        $exportCount = 0
        
        foreach ($item in $uniqueConnections.GetEnumerator()) {
            try {
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
                $exportCount++
                
            } catch {
                Write-LogMessage "Error processing connection for export: $_" "Error"
                continue
            }
        }
        
        $sortedData = $exportData | Sort-Object ConnectionCount -Descending
        Write-LogMessage "Export data preparation completed: $exportCount records" "Info"
        
        # Export data in the specified format
        switch ($Format.ToUpper()) {
            "CSV" {
                $sortedData | Export-Csv -Path $OutputFile -NoTypeInformation
                Write-LogMessage "Data exported to CSV: $OutputFile" "Info"
            }
            "JSON" {
                $jsonOutput = $sortedData | ConvertTo-Json -Depth 4
                [System.IO.File]::WriteAllText($OutputFile, $jsonOutput)
                Write-LogMessage "Data exported to JSON: $OutputFile" "Info"
            }
            "HTML" {
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>FortiAnalyzer Network Traffic Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        .summary { background-color: #f8f8f8; padding: 10px; border-left: 5px solid #0066cc; margin: 20px 0; }
        .footer { margin-top: 20px; font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <h1>FortiAnalyzer Network Traffic Analysis</h1>
    <div class="summary">
        <p><strong>Total Connections:</strong> $($connections.Count)</p>
        <p><strong>Unique Connection Patterns:</strong> $($uniqueConnections.Count)</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
    <table>
        <tr>
            <th>Source Subnet</th>
            <th>Destination Subnet</th>
            <th>Service</th>
            <th>Count</th>
            <th>Source Interface</th>
            <th>Destination Interface</th>
            <th>Action</th>
            <th>First Seen</th>
            <th>Last Seen</th>
        </tr>
"@

                $htmlRows = ""
                foreach ($item in $sortedData) {
                    $htmlRows += @"
        <tr>
            <td>$($item.SourceSubnet)</td>
            <td>$($item.DestinationSubnet)</td>
            <td>$($item.Service)</td>
            <td>$($item.ConnectionCount)</td>
            <td>$($item.SourceInterface)</td>
            <td>$($item.DestinationInterface)</td>
            <td>$($item.Action)</td>
            <td>$($item.FirstSeen)</td>
            <td>$($item.LastSeen)</td>
        </tr>
"@
                }

                $htmlFooter = @"
    </table>
    <p class="footer">Generated by FortiAnalyzer Log Parser v2.2</p>
</body>
</html>
"@

                $htmlContent = $htmlHeader + $htmlRows + $htmlFooter
                [System.IO.File]::WriteAllText($OutputFile, $htmlContent)
                Write-LogMessage "Data exported to HTML: $OutputFile" "Info"
            }
            default {
                Write-LogMessage "Unsupported export format: $Format. Defaulting to CSV." "Warning"
                $sortedData | Export-Csv -Path $OutputFile -NoTypeInformation
            }
        }
        
        return $sortedData
        
    } catch {
        Write-LogMessage "Critical error in Export-NetworkData: $_" "Error"
        throw
    }
}

# Main execution
try {
    Write-Host "=== FortiAnalyzer Log Parser v2.2 ===" -ForegroundColor Magenta
    Write-Host "Enhanced with error handling, performance optimization, and input validation" -ForegroundColor Gray
    Write-Host ""
    
    $scriptStartTime = Get-Date
    
    # Input validation
    Write-LogMessage "Starting input validation..." "Info"
    if (-not (Test-InputValidation -LogFilePath $LogFilePath -OutputFile $OutputFile)) {
        throw "Input validation failed. Please check the log file path and output permissions."
    }
    
    # Parse log file
    Write-LogMessage "Starting log file processing..." "Info"
    if ($UseParallel) {
        Write-LogMessage "Using parallel processing with $MaxThreads threads" "Info"
    }
    Parse-LogFile -filePath $LogFilePath
    
    # Check if we have any data to export
    if ($connections.Count -eq 0) {
        Write-LogMessage "No valid connections found in the log file" "Warning"
        Write-Host "No network data to export. Please check your log file format." -ForegroundColor Yellow
        exit 0
    }
    
    # Export network data
    Write-LogMessage "Starting data export..." "Info"
    $networkData = Export-NetworkData -uniqueConnections $uniqueConnections -outputFile $OutputFile -outputFormat $OutputFormat
    
    # Display results
    Write-Host "`n=== Network Traffic Analysis ===" -ForegroundColor Green
    if ($networkData.Count -gt 0) {
        $networkData | Select-Object -First 10 | Format-Table -AutoSize
    } else {
        Write-Host "No data available for display" -ForegroundColor Yellow
    }
    
    # Verify the file was created and has content
    try {
        if (Test-Path $OutputFile) {
            $fileSize = (Get-Item $OutputFile).Length
            Write-LogMessage "Output file created successfully. Size: $fileSize bytes" "Info"
            Write-Host "`nNetwork data exported to: $OutputFile" -ForegroundColor Yellow
        } else {
            Write-LogMessage "Warning: Output file was not created successfully" "Warning"
        }
        
    } catch {
        Write-LogMessage "Error verifying output file: $_" "Error"
        throw
    }
    
    # Summary statistics
    $scriptEndTime = Get-Date
    $totalTime = ($scriptEndTime - $scriptStartTime).TotalSeconds
    $finalMemoryUsage = Get-MemoryUsage
    
    Write-Host "`n=== Processing Summary ===" -ForegroundColor Magenta
    Write-Host "Total execution time: $([Math]::Round($totalTime, 2)) seconds" -ForegroundColor White
    Write-Host "Peak memory usage: ${finalMemoryUsage}MB" -ForegroundColor White
    Write-Host "Lines processed: $processedLines" -ForegroundColor White
    Write-Host "Lines skipped: $skippedLines" -ForegroundColor White
    Write-Host "Total connections parsed: $($connections.Count)" -ForegroundColor White
    Write-Host "Unique connection patterns: $($uniqueConnections.Count)" -ForegroundColor White
    
    if ($errorCount -gt 0) {
        Write-Host "Errors encountered: $errorCount" -ForegroundColor Red
    }
    
    if ($warningCount -gt 0) {
        Write-Host "Warnings: $warningCount" -ForegroundColor Yellow
    }
    
    # Top services analysis
    if ($networkData.Count -gt 0) {
        Write-Host "`nTop services by connection count:" -ForegroundColor White
        $topServices = $networkData | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 5
        foreach ($service in $topServices) {
            Write-Host "  $($service.Name): $($service.Count) patterns" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n=== Processing Complete ===" -ForegroundColor Green
    Write-Host "Results saved to: $OutputFile" -ForegroundColor Yellow
    
} catch {
    Write-LogMessage "Critical error in main execution: $_" "Error"
    Write-Host "`n=== Error Summary ===" -ForegroundColor Red
    Write-Host "Total errors: $errorCount" -ForegroundColor Red
    Write-Host "Total warnings: $warningCount" -ForegroundColor Yellow
    Write-Host "Lines processed before error: $processedLines" -ForegroundColor White
    Write-Host "Lines skipped: $skippedLines" -ForegroundColor White
    
    if ($DebugMode) {
        Write-Host "`nFull error details:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }
    
    exit 1
} finally {
    # Cleanup
    if ($ShowProgress) {
        Write-Progress -Activity "Parsing logs" -Completed
    }
    
    # Force garbage collection to free memory
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    Write-LogMessage "Script execution completed" "Info"
}