<#
.SYNOPSIS
    FortiAnalyzer Log Parser - GUI Version
.DESCRIPTION
    Modern WPF GUI for the FortiAnalyzer Log Parser tool.
    Parses FortiAnalyzer log files to extract network traffic patterns and generate FortiGate firewall policies.
.VERSION
    2.7.0-WPF
.AUTHOR
    Diyar Abbas (GUI by Opencode)
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- XAML UI Definition ---
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="FortiAnalyzer Log Parser" Height="650" Width="900" 
        WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize"
        Background="#F3F4F6" FontFamily="Segoe UI">
    
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#3B82F6"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="4">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#2563EB"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#9CA3AF"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Padding" Value="5"/>
            <Setter Property="BorderBrush" Value="#D1D5DB"/>
            <Setter Property="Background" Value="White"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

        <Style TargetType="GroupBox">
            <Setter Property="BorderBrush" Value="#E5E7EB"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10"/>
            <Setter Property="Background" Value="White"/>
            <Setter Property="Margin" Value="0,0,0,10"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/> <!-- Header -->
            <RowDefinition Height="Auto"/> <!-- Input -->
            <RowDefinition Height="Auto"/> <!-- Options -->
            <RowDefinition Height="Auto"/> <!-- Action -->
            <RowDefinition Height="*"/>    <!-- Logs -->
            <RowDefinition Height="Auto"/> <!-- Status -->
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#1E3A8A" Padding="20">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="FortiAnalyzer" Foreground="White" FontSize="20" FontWeight="Bold"/>
                <TextBlock Text=" Log Parser" Foreground="#93C5FD" FontSize="20" FontWeight="Light"/>
                <TextBlock Text=" v2.7.0-WPF" Foreground="#60A5FA" FontSize="12" VerticalAlignment="Bottom" Margin="10,0,0,3"/>
            </StackPanel>
        </Border>

        <!-- Input Section -->
        <GroupBox Grid.Row="1" Header="Input Configuration" Margin="20,20,20,10" FontWeight="SemiBold">
            <Grid Margin="0,10,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Log File:" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="#374151"/>
                <TextBox Name="txtLogFile" Grid.Column="1" Height="30"/>
                <Button Name="btnBrowse" Content="Browse..." Grid.Column="2" Width="80" Height="30" Margin="10,0,0,0" Background="#4B5563"/>
            </Grid>
        </GroupBox>

        <!-- Output & Options -->
        <GroupBox Grid.Row="2" Header="Output &amp; Processing Options" Margin="20,0,20,10" FontWeight="SemiBold">
            <Grid Margin="0,10,0,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="150"/>
                </Grid.ColumnDefinitions>

                <!-- Row 1 -->
                <TextBlock Text="Output Path:" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="#374151"/>
                <TextBox Name="txtOutputFile" Grid.Column="1" Height="30" Text="NetworkTraffic.csv"/>
                
                <TextBlock Text="Format:" Grid.Column="2" VerticalAlignment="Center" Margin="20,0,10,0" Foreground="#374151"/>
                <ComboBox Name="cmbFormat" Grid.Column="3" Height="30" SelectedIndex="0" VerticalContentAlignment="Center" Padding="5">
                    <ComboBoxItem Content="CSV"/>
                    <ComboBoxItem Content="JSON"/>
                    <ComboBoxItem Content="HTML"/>
                    <ComboBoxItem Content="TEXT"/>
                </ComboBox>

                <!-- Row 2 -->
                <StackPanel Grid.Row="1" Grid.Column="1" Orientation="Horizontal" Margin="0,15,0,5">
                    <CheckBox Name="chkDebug" Content="Enable Debug Mode" Margin="0,0,20,0" VerticalAlignment="Center"/>
                    <CheckBox Name="chkParallel" Content="Parallel Processing (Faster)" VerticalAlignment="Center" IsEnabled="True" 
                              ToolTip="Uses Runspaces to process logs in background."/>
                </StackPanel>
            </Grid>
        </GroupBox>

        <!-- Action Button -->
        <Button Name="btnRun" Grid.Row="3" Content="START ANALYSIS" Margin="20,0,20,15" Height="45" FontSize="14" FontWeight="Bold" Background="#10B981"/>

        <!-- Log Output -->
        <Border Grid.Row="4" Margin="20,0,20,20" BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="4" Background="White">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border Background="#F9FAFB" Padding="10,5" BorderBrush="#E5E7EB" BorderThickness="0,0,0,1">
                    <TextBlock Text="Execution Log" Foreground="#6B7280" FontSize="11" FontWeight="SemiBold"/>
                </Border>
                <TextBox Name="txtLog" Grid.Row="1" BorderThickness="0" FontFamily="Consolas" FontSize="12" 
                         VerticalScrollBarVisibility="Auto" IsReadOnly="True" Padding="10"/>
            </Grid>
        </Border>

        <!-- Status Bar -->
        <Grid Grid.Row="5" Background="White">
            <ProgressBar Name="progressBar" Height="4" VerticalAlignment="Top" Background="Transparent" BorderThickness="0" Foreground="#3B82F6"/>
            <TextBlock Name="lblStatus" Text="Ready" Margin="10,8" FontSize="11" Foreground="#6B7280"/>
        </Grid>
    </Grid>
</Window>
"@

# --- Global Logic ---
$serviceMappings = @{
    '13' = 'DAYTIME'; '20' = 'FTP-DATA'; '21' = 'FTP'; '22' = 'SSH'; '23' = 'TELNET'
    '25' = 'SMTP'; '37' = 'TIME'; '53' = 'DNS'; '67' = 'DHCP-SERVER'; '68' = 'DHCP-CLIENT'
    '69' = 'TFTP'; '79' = 'FINGER'; '80' = 'HTTP'; '110' = 'POP3'; '111' = 'PORTMAPPER'
    '119' = 'NNTP'; '123' = 'NTP'; '143' = 'IMAP'; '161' = 'SNMP'; '162' = 'SNMP-TRAP'
    '179' = 'BGP'; '194' = 'IRC'; '199' = 'SMUX'; '220' = 'IMAP3'; '389' = 'LDAP'
    '443' = 'HTTPS'; '465' = 'SMTPS'; '500' = 'ISAKMP'; '514' = 'SYSLOG'; '515' = 'LPR'
    '520' = 'RIP'; '521' = 'RIPNG'; '587' = 'SMTP-SUBMISSION'; '631' = 'IPP'
    '636' = 'LDAPS'; '646' = 'LDP'; '873' = 'RSYNC'; '989' = 'FTPS-DATA'; '990' = 'FTPS'
    '993' = 'IMAPS'; '995' = 'POP3S'; '1080' = 'SOCKS'; '1194' = 'OPENVPN'
    '1645' = 'RADIUS-AUTH-OLD'; '1646' = 'RADIUS-ACCT-OLD'; '1720' = 'H323'
    '1723' = 'PPTP'; '1812' = 'RADIUS-AUTH'; '1813' = 'RADIUS-ACCT'
    '135' = 'MS-RPC'; '137' = 'NETBIOS-NS'; '138' = 'NETBIOS-DGM'; '139' = 'NETBIOS-SSN'
    '445' = 'SMB'; '1433' = 'MSSQL'; '1434' = 'MSSQL-MONITOR'; '3389' = 'RDP'
    '5985' = 'WINRM-HTTP'; '5986' = 'WINRM-HTTPS'
    '1521' = 'ORACLE'; '1522' = 'ORACLE-TNS'; '3306' = 'MYSQL'; '5432' = 'POSTGRESQL'
    '6379' = 'REDIS'; '27017' = 'MONGODB'; '9042' = 'CASSANDRA'; '7000' = 'CASSANDRA-INTER'
    '11211' = 'MEMCACHED'
    '3000' = 'GRAFANA'; '4000' = 'HTTP-4000'; '5000' = 'DOCKER-REGISTRY'
    '8000' = 'HTTP-8000'; '8008' = 'HTTP-8008'; '8080' = 'HTTP-ALT'; '8081' = 'NEXUS'
    '8086' = 'INFLUXDB'; '8443' = 'HTTPS-ALT'; '9000' = 'SONARQUBE'; '9090' = 'PROMETHEUS'
    '9100' = 'PROMETHEUS-NODE'
    '902' = 'VMWARE-AUTH'; '903' = 'VMWARE-CONSOLE'; '5480' = 'VCENTER-MGMT'
    '8006' = 'PROXMOX'; '16509' = 'LIBVIRT'; '2375' = 'DOCKER-DAEMON'; '2376' = 'DOCKER-DAEMON-TLS'
    '6443' = 'KUBERNETES-API'; '10250' = 'KUBELET'; '2379' = 'ETCD-CLIENT'; '2380' = 'ETCD-PEER'
    '9200' = 'ELASTICSEARCH'; '9300' = 'ELASTICSEARCH-TRANSPORT'; '5601' = 'KIBANA'
    '5044' = 'LOGSTASH'; '8200' = 'VAULT'; '8500' = 'CONSUL'
}

$patterns = @{
    srcip = 'srcip=(\d+\.\d+\.\d+\.\d+)'
    dstip = 'dstip=(\d+\.\d+\.\d+\.\d+)'
    srcport = 'srcport=(\d+)'
    dstport = 'dstport=(\d+)'
    service = 'service="([^"]*)"'
    srcintf = 'srcintf="([^"]*)"'
    dstintf = 'dstintf="([^"]*)"'
    action = 'action="([^"]*)"'
    proto = 'proto=(\d+)'
    trandisp = 'trandisp="?([^"\s]+)"?'
}

# --- Initialization ---
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Get Controls
$btnBrowse = $window.FindName("btnBrowse")
$txtLogFile = $window.FindName("txtLogFile")
$txtOutputFile = $window.FindName("txtOutputFile")
$cmbFormat = $window.FindName("cmbFormat")
$btnRun = $window.FindName("btnRun")
$logBox = $window.FindName("txtLog")
$pBar = $window.FindName("progressBar")
$lblStat = $window.FindName("lblStatus")
$chkDebug = $window.FindName("chkDebug")
$chkParallel = $window.FindName("chkParallel")

# Events
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Log Files (*.log)|*.log|All Files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq "OK") {
        $txtLogFile.Text = $dlg.FileName
        $dir = Split-Path $dlg.FileName -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($dlg.FileName)
        $txtOutputFile.Text = Join-Path $dir "$name-NetworkTraffic.csv"
    }
})

$cmbFormat.Add_SelectionChanged({
    # Get selected format safely
    $selected = $cmbFormat.SelectedItem
    $f = if ($selected -is [System.Windows.Controls.ComboBoxItem]) { 
        $selected.Content.ToString() 
    } elseif ($selected -ne $null) {
        $selected.ToString()
    } else { 
        $cmbFormat.Text 
    }

    $ext = switch($f) {
        "CSV" { ".csv" }
        "JSON" { ".json" }
        "HTML" { ".html" }
        "TEXT" { ".txt" }
        default { ".csv" }
    }
    
    # Update UI immediately
    if (-not [string]::IsNullOrWhiteSpace($txtOutputFile.Text)) {
        $current = $txtOutputFile.Text
        if ($current -match "\.(csv|json|html|txt)$") {
            $txtOutputFile.Text = $current -replace "\.(csv|json|html|txt)$", $ext
        } else {
            $txtOutputFile.Text = $current + $ext
        }
    }
})

    # Logic to start analysis (extracted for reuse)
    $Action_RunAnalysis = {
        $path = $txtLogFile.Text
        $out = $txtOutputFile.Text
        
        # Properly retrieve selected format content - handle both string and ComboBoxItem
        $selected = $cmbFormat.SelectedItem
        $fmt = if ($selected -is [System.Windows.Controls.ComboBoxItem]) { 
            $selected.Content.ToString() 
        } elseif ($selected -ne $null) {
            $selected.ToString()
        } else { 
            $cmbFormat.Text 
        }
        
        if ([string]::IsNullOrWhiteSpace($fmt)) { $fmt = "CSV" }
        
        # Force correct extension based on current format SELECTION, ignoring whatever text is in the box
        $ext = switch($fmt) {
            "CSV" { ".csv" }
            "JSON" { ".json" }
            "HTML" { ".html" }
            "TEXT" { ".txt" }
            default { ".csv" }
        }
        
        # Strip any known extension and append the correct one
        if ($out -match "\.(csv|json|html|txt)$") {
            $out = $out -replace "\.(csv|json|html|txt)$", $ext
        } else {
            $out = $out + $ext
        }
        # Update UI to reflect the actual file being used
        $txtOutputFile.Text = $out
        
        # Validation
        if (-not (Test-Path $path)) {
            [System.Windows.Forms.MessageBox]::Show("Log file not found!", "Error")
            return
        }

        $btnRun.IsEnabled = $false
        $btnRun.Content = "Processing..."
        $pBar.Value = 0
        $logBox.Clear()
        
        # Cleanup previous runspace if exists
        if ($script:rs) {
            $script:rs.Dispose()
            $script:rs = $null
        }

        # Prepare Runspace for background processing
        $uiHash = [hashtable]::Synchronized(@{
            Window = $window
            LogBox = $logBox
            ProgressBar = $pBar
            Status = $lblStat
            Path = $path
            Out = $out
            Fmt = $fmt
            Patterns = $patterns
            ServiceMappings = $serviceMappings
        })
        
        $script:rs = [runspacefactory]::CreateRunspace()
        $script:rs.ApartmentState = "STA"
        $script:rs.ThreadOptions = "ReuseThread"
        $script:rs.Open()
        $script:rs.SessionStateProxy.SetVariable("UI", $uiHash)
        
        $ps = [PowerShell]::Create()
        $ps.Runspace = $script:rs
        
        # Define script block for background processing
        $ps.AddScript({
            $path = $UI.Path
            $out = $UI.Out
            $fmt = $UI.Fmt
            
            # Ensure we really respect the format even if UI didn't update extension
            # If output file extension doesn't match format, force it
            $correctExt = switch($fmt) {
                "CSV" { ".csv" }
                "JSON" { ".json" }
                "HTML" { ".html" }
                "TEXT" { ".txt" }
                default { ".csv" }
            }
            
            # Check current extension
            if (-not $out.EndsWith($correctExt, [StringComparison]::OrdinalIgnoreCase)) {
                # Replace incorrect extension or append correct one
                if ($out -match "\.(csv|json|html|txt)$") {
                    $out = $out -replace "\.(csv|json|html|txt)$", $correctExt
                } else {
                    $out = $out + $correctExt
                }
            }
            
            # --- Helper Functions Inside Runspace ---
            function Get-ServiceName {
                param($Port, $Protocol, $ServiceHint, $Mappings)
                if (-not [string]::IsNullOrWhiteSpace($ServiceHint) -and $ServiceHint -ne "unknown") { return $ServiceHint }
                if ($Mappings.ContainsKey($Port)) { return $Mappings[$Port] }
                switch ($Protocol) { "6" { "TCP/$Port" } "17" { "UDP/$Port" } default { "PROTO$Protocol/$Port" } }
            }

            function Convert-ToSubnet {
                param($IPAddress)
                try {
                    $octets = $IPAddress -split '\.'
                    if ($octets.Count -eq 4) { return "$($octets[0]).$($octets[1]).$($octets[2]).0/24" }
                } catch {}
                return $IPAddress
            }

            function New-PolicyName {
                param($Conn)
                $act = if ($Conn.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
                $s = $Conn.SourceInterface.ToUpper() -replace '[^a-zA-Z0-9]', '_'
                $d = $Conn.DestInterface.ToUpper() -replace '[^a-zA-Z0-9]', '_'
                $svc = $Conn.ServiceName -replace '[^a-zA-Z0-9]', '_'
                $name = "${act}_${s}_TO_${d}_${svc}"
                if ($name.Length -gt 35) { $name = "${act}_${s}_TO_${d}" }
                return $name
            }

            # --- Compiled Regex ---
            $regSrcIp = [regex]::new($UI.Patterns.srcip, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regDstIp = [regex]::new($UI.Patterns.dstip, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regDstPort = [regex]::new($UI.Patterns.dstport, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regSrcPort = [regex]::new($UI.Patterns.srcport, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regSvc = [regex]::new($UI.Patterns.service, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regSrcInt = [regex]::new($UI.Patterns.srcintf, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regDstInt = [regex]::new($UI.Patterns.dstintf, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regAct = [regex]::new($UI.Patterns.action, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regProto = [regex]::new($UI.Patterns.proto, [System.Text.RegularExpressions.RegexOptions]::Compiled)
            $regTran = [regex]::new($UI.Patterns.trandisp, [System.Text.RegularExpressions.RegexOptions]::Compiled)

            $uniqueConnections = @{}
            $totalBytes = (Get-Item $path).Length
            $bytesRead = 0
            $lineNum = 0
            
            # --- PROCESSING ---
            $stream = [System.IO.StreamReader]::new($path)
            while ($null -ne ($line = $stream.ReadLine())) {
                $lineNum++
                $bytesRead += $line.Length + 2
                
                # Fast Parse
                $mDstPort = $regDstPort.Match($line)
                if ($mDstPort.Success) {
                    $mSrcIp = $regSrcIp.Match($line)
                    $mDstIp = $regDstIp.Match($line)
                    
                    if ($mSrcIp.Success -and $mDstIp.Success) {
                        $srcip = $mSrcIp.Groups[1].Value
                        $dstip = $mDstIp.Groups[1].Value
                        $dstport = $mDstPort.Groups[1].Value
                        
                        $srcport = if (($m = $regSrcPort.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $service = if (($m = $regSvc.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $srcintf = if (($m = $regSrcInt.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $dstintf = if (($m = $regDstInt.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $action = if (($m = $regAct.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $proto = if (($m = $regProto.Match($line)).Success) { $m.Groups[1].Value } else { "" }
                        $trandisp = if (($m = $regTran.Match($line)).Success) { $m.Groups[1].Value } else { "noop" }
                        $nat = if ($trandisp -match "snat|dnat") { "Enabled" } else { "Disabled" }
                        
                        # Create Connection Object
                        $conn = @{
                            SourceIP = $srcip; DestIP = $dstip; SourcePort = $srcport; DestPort = $dstport
                            Service = $service; SourceInterface = $srcintf; DestInterface = $dstintf
                            Action = $action; Protocol = $proto; NatEnabled = $nat
                            SourceSubnet = (Convert-ToSubnet $srcip)
                            DestSubnet = (Convert-ToSubnet $dstip)
                            ServiceName = (Get-ServiceName $dstport $proto $service $UI.ServiceMappings)
                            LineNumber = $lineNum
                        }
                        $conn.PolicyName = (New-PolicyName $conn)
                        
                        # Key for uniqueness
                        $key = "$($conn.SourceSubnet)|$($conn.DestSubnet)|$($conn.ServiceName)|$($conn.SourceInterface)|$($conn.DestInterface)"
                        if (-not $uniqueConnections.ContainsKey($key)) {
                            $uniqueConnections[$key] = @{ Count=0; Connection=$conn; FirstSeen=(Get-Date); LastSeen=(Get-Date) }
                        }
                        $uniqueConnections[$key].Count++
                    }
                }
                
                # Update UI
                if ($lineNum % 5000 -eq 0) {
                    $pct = [Math]::Min(($bytesRead / $totalBytes) * 100, 100)
                    $UI.Window.Dispatcher.Invoke([Action]{
                        $UI.ProgressBar.Value = $pct
                        $UI.Status.Text = "Processing line $lineNum..."
                    })
                }
            }
            $stream.Close()
            
            # --- EXPORT ---
            $UI.Window.Dispatcher.Invoke([Action]{ $UI.Status.Text = "Exporting data..." })
            
            $exportData = [System.Collections.ArrayList]::new()
            foreach ($key in $uniqueConnections.Keys) {
                $data = $uniqueConnections[$key]
                $c = $data.Connection
                # Strict Order: Name, In, Out, Src, Dst, Svc, Act, Nat
                $obj = [PSCustomObject]@{
                    PolicyName = $c.PolicyName
                    IncomingInterface = $c.SourceInterface
                    OutgoingInterface = $c.DestInterface
                    Source = $c.SourceSubnet
                    Destination = $c.DestSubnet
                    Service = $c.ServiceName
                    Action = $c.Action
                    NatEnabled = $c.NatEnabled
                    TrafficCount = $data.Count
                    FirstSeen = $data.FirstSeen
                    LastSeen = $data.LastSeen
                    SourceIP = $c.SourceIP
                    DestinationIP = $c.DestIP
                    SourcePort = $c.SourcePort
                    DestinationPort = $c.DestPort
                    Protocol = $c.Protocol
                }
                [void]$exportData.Add($obj)
            }
            $sorted = $exportData | Sort-Object TrafficCount -Descending
            
            # Select ordered properties for CSV/JSON to ensure order is respected in file
            $orderedData = $sorted | Select-Object PolicyName, IncomingInterface, OutgoingInterface, Source, Destination, Service, Action, NatEnabled, TrafficCount, FirstSeen, LastSeen, SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol

            if ($fmt -eq "CSV") {
                $orderedData | ConvertTo-Csv -NoTypeInformation | Set-Content $out -Encoding UTF8
            } elseif ($fmt -eq "JSON") {
                $orderedData | ConvertTo-Json -Depth 4 | Set-Content $out -Encoding UTF8
            } elseif ($fmt -eq "TEXT") {
                $currentDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss"
                $totalConnections = $uniqueConnections.Count.ToString('N0')
                
                $txt = @"
=== FORTIGATE LOG ANALYSIS RESULTS - ENHANCED ===

Analysis Date: $currentDate
Total Traffic Flows Analyzed: $totalConnections
Unique Policy Patterns: $totalConnections

"@
                foreach ($item in $sorted) {
                    $actionStr = if ($item.Action -eq 'accept') { 'allow' } else { 'deny' }
                    $txt += @"

Policy: $($item.PolicyName)
Incoming Interface: $($item.IncomingInterface)
Outgoing Interface: $($item.OutgoingInterface)
Source: $($item.Source)
Destination: $($item.Destination)
Services: $($item.Service)
Action: $actionStr
Nat Enabled: $($item.NatEnabled)
Traffic Count: $($item.TrafficCount)
============================
"@
                }
                $txt += @"

=== ANALYSIS SUMMARY ===
Total Policies Required: $($sorted.Count)
Generated by FortiAnalyzer Log Parser GUI v2.7.0
"@
                [System.IO.File]::WriteAllText($out, $txt, [System.Text.Encoding]::UTF8)
                
            } elseif ($fmt -eq "HTML") {
                 $currentDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss"
                 $totalConnections = $uniqueConnections.Count.ToString('N0')
                 
                 $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>FortiAnalyzer Network Traffic Analysis - Enhanced</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; }
        .header { background: linear-gradient(135deg, #4a90e2 0%, #357abd 100%); color: white; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FortiAnalyzer Network Traffic Analysis - Enhanced</h1>
        <div>Generated on $currentDate</div>
    </div>
    <div class="container">
        <div class="summary-cards">
            <div class="summary-card"><h3>Total Traffic Flows</h3><div style="font-size:28px;font-weight:700;">$totalConnections</div></div>
            <div class="summary-card"><h3>Policies Required</h3><div style="font-size:28px;font-weight:700;">$totalConnections</div></div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>Incoming Interface</th>
                    <th>Outgoing Interface</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Service</th>
                    <th>Action</th>
                    <th>Nat Enabled</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"@
                foreach ($item in $sorted) {
                    $html += @"
                    <tr>
                        <td>$($item.PolicyName)</td>
                        <td>$($item.IncomingInterface)</td>
                        <td>$($item.OutgoingInterface)</td>
                        <td>$($item.Source)</td>
                        <td>$($item.Destination)</td>
                        <td>$($item.Service)</td>
                        <td>$($item.Action)</td>
                        <td>$($item.NatEnabled)</td>
                        <td>$($item.TrafficCount)</td>
                    </tr>
"@
                }
                $html += @"
                </tbody>
            </table>
            <div style="text-align:center;padding:20px;color:#666;">
                Generated by FortiAnalyzer Log Parser GUI v2.7.0
            </div>
        </div>
    </body>
    </html>
"@
                [System.IO.File]::WriteAllText($out, $html, [System.Text.Encoding]::UTF8)
            }
            
            # Final UI Update
            $UI.Window.Dispatcher.Invoke([Action]{
                $UI.ProgressBar.Value = 100
                $UI.Status.Text = "Complete"
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $UI.LogBox.AppendText("[$timestamp] [Success] Analysis Complete. Processed $lineNum lines.`n")
                $UI.LogBox.AppendText("[$timestamp] [Success] Results saved to: $out`n")
                $UI.LogBox.ScrollToEnd()
                
                # Re-enable the Run button so user can start another analysis
                $btn = $UI.Window.FindName("btnRun")
                if ($btn) {
                    $btn.IsEnabled = $true
                    $btn.Content = "START ANALYSIS"
                }
                
                [System.Windows.Forms.MessageBox]::Show("Analysis Complete!`nSaved to: $out", "Success")
            })
        })
        
        $ps.BeginInvoke()
    }

    # Bind the logic to the button click
    $btnRun.Add_Click($Action_RunAnalysis)

    # --- Drag & Drop Logic ---
    $txtLogFile.AllowDrop = $true
    
    $txtLogFile.Add_PreviewDragOver({
        $_.Handled = $true
        if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $_.Effects = 'Copy'
        } else {
            $_.Effects = 'None'
        }
    })

    $txtLogFile.Add_Drop({
        $files = $_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        if ($files -and $files.Count -gt 0) {
            $path = $files[0]
            if (Test-Path $path) {
                # 1. Update Input Field
                $txtLogFile.Text = $path
                
                # 2. Auto-Update Output Path (similar to logic in SelectionChanged)
                $dir = Split-Path $path -Parent
                $name = [System.IO.Path]::GetFileNameWithoutExtension($path)
                
                # Determine current extension preference
                $selected = $cmbFormat.SelectedItem
                $f = if ($selected -is [System.Windows.Controls.ComboBoxItem]) { $selected.Content.ToString() } else { "CSV" }
                $ext = switch($f) { "JSON" {".json"} "HTML" {".html"} "TEXT" {".txt"} default {".csv"} }
                
                $txtOutputFile.Text = Join-Path $dir "$name-NetworkTraffic$ext"
                
                # 3. Auto-Start Processing
                $Action_RunAnalysis.Invoke()
            }
        }
    })

# Global Runspace variable for cleanup
$script:rs = $null

$window.ShowDialog() | Out-Null

if ($script:rs) {
    $script:rs.Close()
    $script:rs.Dispose()
}
