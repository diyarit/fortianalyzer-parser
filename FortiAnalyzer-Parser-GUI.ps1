<#
.SYNOPSIS
    FortiAnalyzer Log Parser - GUI Version
.DESCRIPTION
    Modern WPF GUI for the FortiAnalyzer Log Parser tool.
    Parses FortiAnalyzer log files to extract network traffic patterns
    and generate FortiGate firewall policies.
.VERSION
    3.1.0-WPF
.AUTHOR
    Diyar Abbas
.NOTES
    v3.1.0 adds:
      - Filter by Source IP / subnet prefix  (partial match, e.g. 192.168.1)
      - Filter by Destination IP / subnet prefix
      - Filter by Service name               (partial match, e.g. HTTP matches HTTP, HTTPS, HTTP-ALT)
      - Filter by Action                     (Any / Allow / Deny)
      - All filters are applied during parse - large files never accumulate excluded rows
      - Active filters are shown in the log and stamped in every report
      - Clear Filters button resets all filter fields instantly
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

#region -- Compiled Regex -------------------------------------------------------

$script:compiledPatterns = @{
    srcip    = [regex]::new('srcip=(\d+\.\d+\.\d+\.\d+)',  [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstip    = [regex]::new('dstip=(\d+\.\d+\.\d+\.\d+)',  [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcport  = [regex]::new('srcport=(\d+)',                 [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstport  = [regex]::new('dstport=(\d+)',                 [System.Text.RegularExpressions.RegexOptions]::Compiled)
    service  = [regex]::new('service="([^"]*)"',             [System.Text.RegularExpressions.RegexOptions]::Compiled)
    srcintf  = [regex]::new('srcintf="([^"]*)"',             [System.Text.RegularExpressions.RegexOptions]::Compiled)
    dstintf  = [regex]::new('dstintf="([^"]*)"',             [System.Text.RegularExpressions.RegexOptions]::Compiled)
    action   = [regex]::new('action="([^"]*)"',              [System.Text.RegularExpressions.RegexOptions]::Compiled)
    proto    = [regex]::new('proto=(\d+)',                   [System.Text.RegularExpressions.RegexOptions]::Compiled)
    trandisp = [regex]::new('trandisp="?([^"\s]+)"?',        [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

#endregion

#region -- Service Mappings -----------------------------------------------------

$script:serviceMappings = @{
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
    '8000'='HTTP-8000';'8008'='HTTP-8008';'8080'='HTTP-ALT';'8081'='NEXUS'
    '8086'='INFLUXDB';'8443'='HTTPS-ALT';'9000'='SONARQUBE';'9090'='PROMETHEUS'
    '9100'='PROMETHEUS-NODE'
    '902'='VMWARE-AUTH';'903'='VMWARE-CONSOLE';'5480'='VCENTER-MGMT'
    '8006'='PROXMOX';'16509'='LIBVIRT';'2375'='DOCKER-DAEMON';'2376'='DOCKER-DAEMON-TLS'
    '6443'='KUBERNETES-API';'10250'='KUBELET';'2379'='ETCD-CLIENT';'2380'='ETCD-PEER'
    '9200'='ELASTICSEARCH';'9300'='ELASTICSEARCH-TRANSPORT';'5601'='KIBANA'
    '5044'='LOGSTASH';'8200'='VAULT';'8500'='CONSUL'
}

#endregion

#region -- XAML UI --------------------------------------------------------------

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="FortiAnalyzer Log Parser  v3.1.0-WPF"
        Height="820" Width="1020" MinHeight="680" MinWidth="860"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize"
        Background="#F3F4F6" FontFamily="Segoe UI">

    <Window.Resources>
        <Style x:Key="PrimaryBtn" TargetType="Button">
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

        <Style x:Key="DangerBtn" TargetType="Button" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#EF4444"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#DC2626"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#9CA3AF"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="GhostBtn" TargetType="Button" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#4B5563"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#374151"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#9CA3AF"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="AmberBtn" TargetType="Button" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#D97706"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#B45309"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#9CA3AF"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="Button" BasedOn="{StaticResource PrimaryBtn}"/>

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
            <Setter Property="Margin" Value="0,0,0,8"/>
        </Style>

        <Style TargetType="ComboBox">
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="Padding" Value="5,0"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>  <!-- 0 Header -->
            <RowDefinition Height="Auto"/>  <!-- 1 Input -->
            <RowDefinition Height="Auto"/>  <!-- 2 Output options -->
            <RowDefinition Height="Auto"/>  <!-- 3 Filters -->
            <RowDefinition Height="Auto"/>  <!-- 4 Action buttons -->
            <RowDefinition Height="*"/>     <!-- 5 Log output -->
            <RowDefinition Height="Auto"/>  <!-- 6 Status bar -->
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#1E3A8A" Padding="20,14">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="FortiAnalyzer" Foreground="White"  FontSize="20" FontWeight="Bold"/>
                <TextBlock Text=" Log Parser"   Foreground="#93C5FD" FontSize="20" FontWeight="Light"/>
                <TextBlock Text=" v3.1.0-WPF"  Foreground="#60A5FA" FontSize="12" VerticalAlignment="Bottom" Margin="10,0,0,4"/>
            </StackPanel>
        </Border>

        <!-- Input -->
        <GroupBox Grid.Row="1" Header="Input Configuration" Margin="16,14,16,0" FontWeight="SemiBold">
            <Grid Margin="0,8,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Log File:" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="#374151"/>
                <TextBox Name="txtLogFile" Grid.Column="1" Height="30" ToolTip="Drag a log file here, or click Browse"/>
                <Button Name="btnBrowse" Content="Browse..." Grid.Column="2" Style="{StaticResource GhostBtn}"
                        Width="82" Height="30" Margin="10,0,0,0"/>
            </Grid>
        </GroupBox>

        <!-- Output and Options -->
        <GroupBox Grid.Row="2" Header="Output and Processing Options" Margin="16,0,16,0" FontWeight="SemiBold">
            <Grid Margin="0,8,0,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="60"/>
                </Grid.ColumnDefinitions>

                <TextBlock Text="Output:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#374151"/>
                <TextBox Name="txtOutputFile" Grid.Column="1" Height="30" Text="NetworkTraffic.csv"/>
                <TextBlock Text="Format:" Grid.Column="2" VerticalAlignment="Center" Margin="16,0,8,0" Foreground="#374151"/>
                <ComboBox Name="cmbFormat" Grid.Column="3" Height="30" SelectedIndex="0">
                    <ComboBoxItem Content="CSV"/>
                    <ComboBoxItem Content="JSON"/>
                    <ComboBoxItem Content="HTML"/>
                    <ComboBoxItem Content="TEXT"/>
                </ComboBox>
                <TextBlock Text="/Mask:" Grid.Column="4" VerticalAlignment="Center" Margin="16,0,8,0" Foreground="#374151"/>
                <TextBox Name="txtSubnetMask" Grid.Column="5" Height="30" Text="24"
                         ToolTip="CIDR subnet mask bits (8-32). Default 24 means /24"/>

                <StackPanel Grid.Row="1" Grid.Column="1" Orientation="Horizontal" Margin="0,10,0,2">
                    <CheckBox Name="chkDebug"    Content="Debug Mode"          Margin="0,0,24,0" VerticalAlignment="Center"/>
                    <CheckBox Name="chkParallel" Content="Parallel Processing" VerticalAlignment="Center"
                              ToolTip="Uses RunspacePool to distribute work across CPU cores."/>
                </StackPanel>
            </Grid>
        </GroupBox>

        <!-- Filters -->
        <GroupBox Grid.Row="3" Margin="16,0,16,0" FontWeight="SemiBold">
            <GroupBox.Header>
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="Filters" VerticalAlignment="Center"/>
                    <Border Name="filterBadge" Background="#F59E0B" CornerRadius="8"
                            Padding="6,1" Margin="8,0,0,0" Visibility="Collapsed">
                        <TextBlock Name="filterBadgeText" Text="0 active" Foreground="White"
                                   FontSize="10" FontWeight="Bold"/>
                    </Border>
                </StackPanel>
            </GroupBox.Header>
            <Grid Margin="0,8,0,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="24"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="24"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="24"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="110"/>
                </Grid.ColumnDefinitions>

                <!-- Row 0: Source IP | Dest IP | Service | Action -->
                <TextBlock Text="Src IP / Prefix:" VerticalAlignment="Center" Foreground="#374151" Margin="0,0,8,0"/>
                <TextBox Name="txtFilterSrcIP" Grid.Column="1" Height="28"
                         ToolTip="Enter exact IP (e.g. 10.1.10.2). Tries exact match first; if no results, falls back to subnet prefix match."/>
                <Button Name="btnClearSrcIP" Grid.Column="2" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"
                        ToolTip="Clear source IP filter"/>

                <TextBlock Text="Dst IP / Prefix:" Grid.Column="3" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <TextBox Name="txtFilterDstIP" Grid.Column="4" Height="28"
                         ToolTip="Exact IP match (e.g. 10.0.5.1). Output shows the IP directly; unfiltered results show the subnet."/>
                <Button Name="btnClearDstIP" Grid.Column="5" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"
                        ToolTip="Clear destination IP filter"/>

                <TextBlock Text="Service:" Grid.Column="6" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <TextBox Name="txtFilterService" Grid.Column="7" Height="28"
                         ToolTip="Port number (e.g. 443) or partial name (e.g. HTTP matches HTTPS, HTTP-ALT). Both are case-insensitive."/>
                <Button Name="btnClearService" Grid.Column="8" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"
                        ToolTip="Clear service filter"/>

                <TextBlock Text="Action:" Grid.Column="9" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <ComboBox Name="cmbFilterAction" Grid.Column="10" Height="28" SelectedIndex="0"
                          ToolTip="Filter to only allow or only deny traffic">
                    <ComboBoxItem Content="Any"/>
                    <ComboBoxItem Content="Allow only"/>
                    <ComboBoxItem Content="Deny only"/>
                </ComboBox>

                <!-- Row 1: hint text + clear all button -->
                <TextBlock Grid.Row="1" Grid.ColumnSpan="9" Margin="0,6,0,0"
                           Text="All filters use case-insensitive partial matching. Leave blank to include everything."
                           Foreground="#9CA3AF" FontSize="11" FontStyle="Italic"/>
                <Button Name="btnClearAllFilters" Grid.Row="1" Grid.Column="9" Grid.ColumnSpan="2"
                        Content="Clear All Filters" Style="{StaticResource AmberBtn}"
                        Height="26" FontSize="11" Margin="16,4,0,0"/>
            </Grid>
        </GroupBox>

        <!-- Action Buttons -->
        <Grid Grid.Row="4" Margin="16,8,16,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="120"/>
            </Grid.ColumnDefinitions>
            <Button Name="btnRun"    Content=">  START ANALYSIS" Height="44" FontSize="14" FontWeight="Bold"
                    Background="#10B981" Style="{StaticResource PrimaryBtn}"/>
            <Button Name="btnCancel" Content="X  Cancel" Grid.Column="1" Height="44" FontSize="13"
                    Style="{StaticResource DangerBtn}" Margin="10,0,0,0" IsEnabled="False"/>
        </Grid>

        <!-- Log Output -->
        <Border Grid.Row="5" Margin="16,0,16,14" BorderBrush="#E5E7EB" BorderThickness="1"
                CornerRadius="4" Background="White">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border Background="#F9FAFB" Padding="10,5" BorderBrush="#E5E7EB" BorderThickness="0,0,0,1">
                    <DockPanel>
                        <TextBlock Text="Execution Log" Foreground="#6B7280" FontSize="11"
                                   FontWeight="SemiBold" VerticalAlignment="Center"/>
                        <Button Name="btnClearLog" Content="Clear" DockPanel.Dock="Right"
                                Style="{StaticResource GhostBtn}" Height="22" Width="52"
                                FontSize="11" Padding="4,2"/>
                    </DockPanel>
                </Border>
                <TextBox Name="txtLog" Grid.Row="1" BorderThickness="0" FontFamily="Consolas" FontSize="12"
                         VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         IsReadOnly="True" Padding="10" TextWrapping="NoWrap"/>
            </Grid>
        </Border>

        <!-- Status Bar -->
        <Grid Grid.Row="6" Background="White" MinHeight="36">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <ProgressBar Name="progressBar" Height="4" VerticalAlignment="Top"
                         Background="Transparent" BorderThickness="0" Foreground="#3B82F6" Grid.ColumnSpan="2"/>
            <TextBlock Name="lblStatus" Text="Ready - drag a log file onto the input box to get started."
                       Margin="12,8" FontSize="11" Foreground="#6B7280" VerticalAlignment="Center"/>
            <Button Name="btnOpenFolder" Content="Open Output Folder" Grid.Column="1"
                    Style="{StaticResource GhostBtn}" Height="26" FontSize="11" Padding="8,3"
                    Margin="0,0,8,0" Visibility="Collapsed"/>
        </Grid>
    </Grid>
</Window>
"@

#endregion

#region -- UI Helpers -----------------------------------------------------------

function Get-SelectedFormat {
    param($ComboBox)
    $sel = $ComboBox.SelectedItem
    if ($sel -is [System.Windows.Controls.ComboBoxItem]) { return $sel.Content.ToString() }
    if ($null -ne $sel) { return $sel.ToString() }
    return $ComboBox.Text
}

function Get-FormatExtension {
    param([string]$Format)
    switch ($Format.ToUpper()) {
        "JSON" { return ".json" }
        "HTML" { return ".html" }
        "TEXT" { return ".txt"  }
        default { return ".csv"  }
    }
}

function Update-OutputExtension {
    param($TxtBox, $Format)
    $ext = Get-FormatExtension $Format
    $cur = $TxtBox.Text
    if ([string]::IsNullOrWhiteSpace($cur)) { return }
    if ($cur -match '\.(csv|json|html|txt)$') {
        $TxtBox.Text = $cur -replace '\.(csv|json|html|txt)$', $ext
    } else {
        $TxtBox.Text = $cur + $ext
    }
}

function Get-SafeSubnetMask {
    param([string]$Raw)
    $bits = 24
    if ([int]::TryParse($Raw, [ref]$bits)) {
        if ($bits -lt 8)  { $bits = 8  }
        if ($bits -gt 32) { $bits = 32 }
    }
    return $bits
}

# Count non-empty filter fields and update the badge on the Filters group header
function Update-FilterBadge {
    $count = 0
    if (-not [string]::IsNullOrWhiteSpace($txtFilterSrcIP.Text))   { $count++ }
    if (-not [string]::IsNullOrWhiteSpace($txtFilterDstIP.Text))   { $count++ }
    if (-not [string]::IsNullOrWhiteSpace($txtFilterService.Text)) { $count++ }
    $actionSel = Get-SelectedFormat $cmbFilterAction
    if ($actionSel -ne "Any") { $count++ }

    if ($count -gt 0) {
        $filterBadge.Visibility     = "Visible"
        $filterBadgeText.Text       = "$count active"
    } else {
        $filterBadge.Visibility     = "Collapsed"
    }
}

#endregion

#region -- Load Window ----------------------------------------------------------

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$btnBrowse         = $window.FindName("btnBrowse")
$btnRun            = $window.FindName("btnRun")
$btnCancel         = $window.FindName("btnCancel")
$btnClearLog       = $window.FindName("btnClearLog")
$btnOpenFolder     = $window.FindName("btnOpenFolder")
$btnClearAllFilters= $window.FindName("btnClearAllFilters")
$btnClearSrcIP     = $window.FindName("btnClearSrcIP")
$btnClearDstIP     = $window.FindName("btnClearDstIP")
$btnClearService   = $window.FindName("btnClearService")
$txtLogFile        = $window.FindName("txtLogFile")
$txtOutputFile     = $window.FindName("txtOutputFile")
$txtSubnetMask     = $window.FindName("txtSubnetMask")
$txtFilterSrcIP    = $window.FindName("txtFilterSrcIP")
$txtFilterDstIP    = $window.FindName("txtFilterDstIP")
$txtFilterService  = $window.FindName("txtFilterService")
$cmbFormat         = $window.FindName("cmbFormat")
$cmbFilterAction   = $window.FindName("cmbFilterAction")
$txtLog            = $window.FindName("txtLog")
$progressBar       = $window.FindName("progressBar")
$lblStatus         = $window.FindName("lblStatus")
$chkDebug          = $window.FindName("chkDebug")
$chkParallel       = $window.FindName("chkParallel")
$filterBadge       = $window.FindName("filterBadge")
$filterBadgeText   = $window.FindName("filterBadgeText")

$script:activePS       = $null
$script:activeRS       = $null
$script:lastOutputPath = ""

#endregion

#region -- Event Handlers -------------------------------------------------------

$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title  = "Select FortiAnalyzer Log File"
    $dlg.Filter = "Log Files (*.log;*.txt)|*.log;*.txt|All Files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtLogFile.Text = $dlg.FileName
        $dir  = Split-Path $dlg.FileName -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($dlg.FileName)
        $fmt  = Get-SelectedFormat $cmbFormat
        $ext  = Get-FormatExtension $fmt
        $txtOutputFile.Text = Join-Path $dir "${name}-NetworkTraffic${ext}"
        $btnOpenFolder.Visibility = "Collapsed"
    }
})

$cmbFormat.Add_SelectionChanged({
    $fmt = Get-SelectedFormat $cmbFormat
    Update-OutputExtension $txtOutputFile $fmt
})

# Update badge whenever any filter field changes
$txtFilterSrcIP.Add_TextChanged({   Update-FilterBadge })
$txtFilterDstIP.Add_TextChanged({   Update-FilterBadge })
$txtFilterService.Add_TextChanged({ Update-FilterBadge })
$cmbFilterAction.Add_SelectionChanged({ Update-FilterBadge })

# Individual clear buttons
$btnClearSrcIP.Add_Click({   $txtFilterSrcIP.Clear() })
$btnClearDstIP.Add_Click({   $txtFilterDstIP.Clear() })
$btnClearService.Add_Click({ $txtFilterService.Clear() })

# Clear all filters
$btnClearAllFilters.Add_Click({
    $txtFilterSrcIP.Clear()
    $txtFilterDstIP.Clear()
    $txtFilterService.Clear()
    $cmbFilterAction.SelectedIndex = 0
    Update-FilterBadge
})

$btnClearLog.Add_Click({ $txtLog.Clear() })

$btnOpenFolder.Add_Click({
    if ($script:lastOutputPath -and (Test-Path $script:lastOutputPath)) {
        Start-Process explorer.exe -ArgumentList "/select,`"$script:lastOutputPath`""
    }
})

$btnCancel.Add_Click({
    if ($script:activePS) { try { $script:activePS.Stop() } catch {} }
    if ($script:activeRS) {
        try { $script:activeRS.Close(); $script:activeRS.Dispose() } catch {}
        $script:activeRS = $null
    }
    $btnRun.IsEnabled    = $true
    $btnRun.Content      = ">  START ANALYSIS"
    $btnCancel.IsEnabled = $false
    $lblStatus.Text      = "Cancelled."
    $progressBar.Value   = 0
    $ts = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
    $txtLog.AppendText("[$ts] [Warning] Analysis cancelled by user.`n")
    $txtLog.ScrollToEnd()
})

#endregion

#region -- Drag and Drop --------------------------------------------------------

$txtLogFile.AllowDrop = $true

$txtLogFile.Add_PreviewDragOver({
    $_.Handled = $true
    $_.Effects = if ($_.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) { 'Copy' } else { 'None' }
})

$txtLogFile.Add_Drop({
    $files = $_.Data.GetData([System.Windows.DataFormats]::FileDrop)
    if ($files -and $files.Count -gt 0 -and (Test-Path $files[0])) {
        $p = $files[0]
        $txtLogFile.Text = $p
        $dir  = Split-Path $p -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($p)
        $fmt  = Get-SelectedFormat $cmbFormat
        $ext  = Get-FormatExtension $fmt
        $txtOutputFile.Text = Join-Path $dir "${name}-NetworkTraffic${ext}"
        $btnOpenFolder.Visibility = "Collapsed"
        $btnRun.RaiseEvent([System.Windows.RoutedEventArgs]::new(
            [System.Windows.Controls.Button]::ClickEvent))
    }
})

#endregion

#region -- Main Analysis Action -------------------------------------------------

$btnRun.Add_Click({

    $path      = $txtLogFile.Text.Trim()
    $fmt       = Get-SelectedFormat $cmbFormat
    $maskBits  = Get-SafeSubnetMask $txtSubnetMask.Text
    $debugMode = $chkDebug.IsChecked

    # Collect filter values
    $fSrcIP   = $txtFilterSrcIP.Text.Trim()
    $fDstIP   = $txtFilterDstIP.Text.Trim()
    $fService = $txtFilterService.Text.Trim()
    $fActionRaw = Get-SelectedFormat $cmbFilterAction
    $fAction  = switch ($fActionRaw) {
        "Allow only" { "accept" }
        "Deny only"  { "deny"   }
        default      { ""       }
    }

    # Resolve output extension
    $out = $txtOutputFile.Text.Trim()
    $ext = Get-FormatExtension $fmt
    if ($out -match '\.(csv|json|html|txt)$') {
        $out = $out -replace '\.(csv|json|html|txt)$', $ext
    } else {
        $out += $ext
    }
    $txtOutputFile.Text = $out

    # Validate
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
        [System.Windows.MessageBox]::Show("Log file not found:`n$path", "Validation Error",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # UI - running state
    $btnRun.IsEnabled         = $false
    $btnRun.Content           = "Processing..."
    $btnCancel.IsEnabled      = $true
    $btnOpenFolder.Visibility = "Collapsed"
    $progressBar.Value        = 0
    $txtLog.Clear()
    $lblStatus.Text           = "Starting analysis..."

    if ($script:activeRS) {
        try { $script:activeRS.Close(); $script:activeRS.Dispose() } catch {}
        $script:activeRS = $null
    }

    $uiHash = [hashtable]::Synchronized(@{
        Window          = $window
        LogBox          = $txtLog
        ProgressBar     = $progressBar
        Status          = $lblStatus
        BtnRun          = $btnRun
        BtnCancel       = $btnCancel
        BtnOpenFolder   = $btnOpenFolder
        Path            = $path
        Out             = $out
        Fmt             = $fmt
        MaskBits        = $maskBits
        DebugMode       = $debugMode
        Patterns        = $script:compiledPatterns
        ServiceMappings = $script:serviceMappings
        LastOutputPath  = [ref]$script:lastOutputPath
        # Filter values passed into runspace
        FilterSrcIP     = $fSrcIP
        FilterDstIP     = $fDstIP
        FilterService   = $fService
        FilterAction    = $fAction
    })

    $script:activeRS = [runspacefactory]::CreateRunspace()
    $script:activeRS.ApartmentState = "STA"
    $script:activeRS.ThreadOptions  = "ReuseThread"
    $script:activeRS.Open()
    $script:activeRS.SessionStateProxy.SetVariable("UI", $uiHash)

    $ps = [PowerShell]::Create()
    $ps.Runspace = $script:activeRS
    $script:activePS = $ps

    [void]$ps.AddScript({

        # -- Inner helpers ---------------------------------------------------

        function Write-UILog {
            param([string]$Msg, [string]$Level = "Info")
            $ts   = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
            $line = "[$ts] [$Level] $Msg`n"
            $UI.Window.Dispatcher.Invoke([Action]{
                $UI.LogBox.AppendText($line)
                $UI.LogBox.ScrollToEnd()
            })
        }

        function Get-SvcName {
            param($Port, $Protocol, $Hint, $Map)
            if (-not [string]::IsNullOrWhiteSpace($Hint) -and $Hint -ne "unknown") { return $Hint.ToUpper() }
            if ($Map.ContainsKey($Port)) { return $Map[$Port] }
            switch ($Protocol) { "6" { "TCP/$Port" } "17" { "UDP/$Port" } default { "PROTO${Protocol}/$Port" } }
        }

        function Convert-Subnet {
            param([string]$IP, [int]$Bits)
            try {
                $o = $IP -split '\.'
                if ($o.Count -ne 4) { return $IP }
                # Use [uint32] to avoid signed integer overflow on masks >= /1
                [uint32]$ipInt = ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
                [uint32]$mask  = if ($Bits -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - $Bits) }
                [uint32]$net   = $ipInt -band $mask
                return "$(($net -shr 24) -band 0xFF).$(($net -shr 16) -band 0xFF).$(($net -shr 8) -band 0xFF).$($net -band 0xFF)/$Bits"
            } catch { return $IP }
        }

        function Get-PolicyName {
            param($Conn)
            $act   = if ($Conn.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
            $sIntf = ($Conn.SourceInterface -replace '[^a-zA-Z0-9]','_').ToUpper()
            $dIntf = ($Conn.DestInterface   -replace '[^a-zA-Z0-9]','_').ToUpper()
            $svc   =  $Conn.ServiceName     -replace '[^a-zA-Z0-9]','_'
            $full  = "${act}_${sIntf}_TO_${dIntf}_${svc}"
            if ($full.Length -le 35) { return $full }
            $hashBytes = [System.Security.Cryptography.SHA1]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($svc))
            $h = ([System.BitConverter]::ToString($hashBytes) -replace '-','').Substring(0,5)
            $short = "${act}_${sIntf}_TO_${dIntf}_${h}"
            if ($short.Length -gt 35) { $short = $short.Substring(0,35) }
            return $short
        }

        function Encode-Html {
            param([string]$v)
            [System.Web.HttpUtility]::HtmlEncode($v)
        }

        # -- Inline filter test ----------------------------------------------
        # Returns $true if the connection passes ALL active filters.
        # Service filter accepts EITHER a port number (e.g. "443") OR a
        # partial service name (e.g. "HTTP").  Port-number input is detected
        # by checking that the filter string is all digits, then compared
        # directly against $DstPort.  Non-numeric input is matched against
        # the resolved service name (case-insensitive wildcard).
        function Test-ServiceAction {
            # Service/action filter - applied during parse for efficiency.
            # IP filtering happens after parse with exact-then-subnet fallback.
            #
            # Service filter rules:
            #   - All digits (e.g. "443"): exact match on raw destination port
            #   - Text (e.g. "HTTPS"):     matches raw log service field AND
            #     resolved service name; exact first, partial (contains) fallback
            param($RawService, $DstPort, $SvcName, $Action, $FSvc, $FAction)

            if ($FSvc) {
                if ($FSvc -match '^\d+$') {
                    if ($DstPort -ne $FSvc) { return $false }
                } else {
                    $fUpper   = $FSvc.ToUpper()
                    $rawUpper = $RawService.ToUpper()
                    $exactMatch   = ($rawUpper -eq $fUpper) -or ($SvcName -eq $fUpper)
                    $partialMatch = ($rawUpper -like "*$fUpper*") -or ($SvcName -like "*$fUpper*")
                    if (-not $exactMatch -and -not $partialMatch) { return $false }
                }
            }
            if ($FAction -and $Action -ne $FAction) { return $false }
            return $true
        }

        function Select-ByIPFilter {
            # Post-parse IP filtering: exact match first, subnet fallback.
            param($UniqueConns, $FSrcIP, $FDstIP)
            if (-not $FSrcIP -and -not $FDstIP) { return $UniqueConns }

            # Pass 1: exact IP match
            $exact = @{}
            foreach ($kv in $UniqueConns.GetEnumerator()) {
                $conn = $kv.Value.Connection
                $s = (-not $FSrcIP) -or ($conn.SourceIP -eq $FSrcIP)
                $d = (-not $FDstIP) -or ($conn.DestIP   -eq $FDstIP)
                if ($s -and $d) { $exact[$kv.Key] = $kv.Value }
            }
            if ($exact.Count -gt 0) {
                Write-UILog "IP filter: exact match - $($exact.Count) pattern(s)."
                return $exact
            }

            # Pass 2: subnet/prefix fallback
            Write-UILog "IP filter: no exact matches - trying subnet prefix fallback."
            $sub = @{}
            foreach ($kv in $UniqueConns.GetEnumerator()) {
                $conn = $kv.Value.Connection
                $s = (-not $FSrcIP) -or ($conn.SourceSubnet -like "*$FSrcIP*") -or ($conn.SourceIP -like "$FSrcIP*")
                $d = (-not $FDstIP) -or ($conn.DestSubnet   -like "*$FDstIP*") -or ($conn.DestIP   -like "$FDstIP*")
                if ($s -and $d) { $sub[$kv.Key] = $kv.Value }
            }
            Write-UILog "IP filter: subnet fallback - $($sub.Count) pattern(s)."
            return $sub
        }

        # -- Variables -------------------------------------------------------

        $path       = $UI.Path
        $out        = $UI.Out
        $fmt        = $UI.Fmt
        $maskBits   = $UI.MaskBits
        $pats       = $UI.Patterns
        $maps       = $UI.ServiceMappings
        $fSrcIP     = $UI.FilterSrcIP
        $fDstIP     = $UI.FilterDstIP
        $fService   = $UI.FilterService
        $fAction    = $UI.FilterAction

        $uniqueConns  = @{}
        $totalBytes   = (Get-Item $path).Length
        $lineNum      = 0
        $skippedFilter= 0
        $batchTime    = [DateTime]::Now

        # Build human-readable filter summary for log/reports
        $filterParts = @()
        if ($fSrcIP)   { $filterParts += "SrcIP = '$fSrcIP'" }
        if ($fDstIP)   { $filterParts += "DstIP = '$fDstIP'" }
        if ($fService) {
            if ($fService -match '^\d+$') {
                $filterParts += "Port = $fService"
            } else {
                $filterParts += "Service contains '$fService'"
            }
        }
        if ($fAction)  { $filterParts += "Action = '$fAction'" }
        $filterSummary = if ($filterParts.Count -gt 0) { $filterParts -join "  AND  " } else { "None (showing all)" }

        Write-UILog "File     : $path  ($([Math]::Round($totalBytes/1MB,2)) MB)"
        Write-UILog "Format   : $fmt  |  Subnet mask : /$maskBits"
        Write-UILog "Filters  : $filterSummary"

        # -- Streaming parse -------------------------------------------------

        $stream = [System.IO.StreamReader]::new($path, [System.Text.Encoding]::UTF8, $true, 65536)
        try {
            while ($null -ne ($line = $stream.ReadLine())) {
                $lineNum++

                $mDst = $pats.dstport.Match($line)
                if (-not $mDst.Success) { continue }

                $mSrc = $pats.srcip.Match($line)
                $mDip = $pats.dstip.Match($line)
                if (-not $mSrc.Success -or -not $mDip.Success) { continue }

                $srcip   = $mSrc.Groups[1].Value
                $dstip   = $mDip.Groups[1].Value
                $dstport = $mDst.Groups[1].Value

                $mSvcRaw  = $pats.service.Match($line)
                $mAct     = $pats.action.Match($line)
                $mProto   = $pats.proto.Match($line)

                $serviceRaw = if ($mSvcRaw.Success) { $mSvcRaw.Groups[1].Value } else { "" }
                $proto      = if ($mProto.Success)  { $mProto.Groups[1].Value }  else { "" }
                # Normalise: FortiAnalyzer writes "close"/"server-rst"/"client-rst"
                # for completed allowed sessions - treat all as "accept"
                $action = if ($mAct.Success) {
                    switch ($mAct.Groups[1].Value.ToLower()) {
                        "close"      { "accept" }
                        "accept"     { "accept" }
                        "deny"       { "deny"   }
                        "server-rst" { "accept" }
                        "client-rst" { "accept" }
                        default      { $mAct.Groups[1].Value }
                    }
                } else { "" }
                $svcName    = Get-SvcName $dstport $proto $serviceRaw $maps

                # Service/action filter applied during parse (fast path).
                # IP filter applied post-parse with exact/subnet fallback.
                if (-not (Test-ServiceAction $serviceRaw $dstport $svcName $action `
                                              $fService $fAction)) {
                    $skippedFilter++
                    continue
                }

                # Extract remaining fields only for lines that pass the filter
                $mSrcPort = $pats.srcport.Match($line)
                $mSrcInt  = $pats.srcintf.Match($line)
                $mDstInt  = $pats.dstintf.Match($line)
                $mTran    = $pats.trandisp.Match($line)

                $srcport = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { "" }
                $srcintf = if ($mSrcInt.Success)  { $mSrcInt.Groups[1].Value }  else { "" }
                $dstintf = if ($mDstInt.Success)  { $mDstInt.Groups[1].Value }  else { "" }
                $tran    = if ($mTran.Success)    { $mTran.Groups[1].Value }    else { "noop" }
                $nat     = if ($tran -match "snat|dnat") { "Enabled" } else { "Disabled" }

                $conn = @{
                    SourceIP        = $srcip
                    DestIP          = $dstip
                    SourcePort      = $srcport
                    DestPort        = $dstport
                    Service         = $serviceRaw
                    SourceInterface = $srcintf
                    DestInterface   = $dstintf
                    Action          = $action
                    Protocol        = $proto
                    NatEnabled      = $nat
                    SourceSubnet    = (Convert-Subnet $srcip $maskBits)
                    DestSubnet      = (Convert-Subnet $dstip $maskBits)
                    ServiceName     = $svcName
                    LineNumber      = $lineNum
                }
                $conn.PolicyName = Get-PolicyName $conn

                $key = "$($conn.SourceSubnet)|$($conn.DestSubnet)|$svcName|$srcintf|$dstintf"
                if (-not $uniqueConns.ContainsKey($key)) {
                    $uniqueConns[$key] = @{ Count=0; Connection=$conn; FirstSeen=$batchTime; LastSeen=$batchTime }
                }
                $uniqueConns[$key].Count++

                if ($lineNum % 5000 -eq 0) {
                    $batchTime = [DateTime]::Now
                    $pos = $stream.BaseStream.Position
                    $pct = [Math]::Min([Math]::Round(($pos / $totalBytes) * 100), 99)
                    $matchedSoFar = $uniqueConns.Count
                    $UI.Window.Dispatcher.Invoke([Action]{
                        $UI.ProgressBar.Value = $pct
                        $UI.Status.Text = "Line $lineNum  |  $matchedSoFar matched patterns  |  $pct%"
                    })
                }
            }
        }
        finally {
            $stream.Dispose()
        }

        Write-UILog "Parse complete: $lineNum lines read, $($uniqueConns.Count) unique patterns matched, $skippedFilter lines excluded by filters."

        # -- IP filter (post-parse: exact first, subnet fallback) ------------

        $filteredConns = Select-ByIPFilter $uniqueConns $fSrcIP $fDstIP

        # -- Export ----------------------------------------------------------

        $UI.Window.Dispatcher.Invoke([Action]{ $UI.Status.Text = "Exporting data..." })

        $exportList = [System.Collections.ArrayList]::new()
        foreach ($kv in $filteredConns.GetEnumerator()) {
            $d = $kv.Value; $c = $d.Connection
            [void]$exportList.Add([PSCustomObject]@{
                PolicyName        = $c.PolicyName
                IncomingInterface = $c.SourceInterface
                OutgoingInterface = $c.DestInterface
                Source            = $c.SourceSubnet
                Destination       = $c.DestSubnet
                Service           = $c.ServiceName
                Action            = $c.Action
                NatEnabled        = $c.NatEnabled
                TrafficCount      = $d.Count
                FirstSeen         = $d.FirstSeen
                LastSeen          = $d.LastSeen
                SourceIP          = $c.SourceIP
                DestinationIP     = $c.DestIP
                SourcePort        = $c.SourcePort
                DestinationPort   = $c.DestPort
                Protocol          = $c.Protocol
            })
        }

        $sorted  = $exportList | Sort-Object TrafficCount -Descending
        $ordered = $sorted | Select-Object PolicyName,IncomingInterface,OutgoingInterface,
                             Source,Destination,Service,Action,NatEnabled,
                             TrafficCount,FirstSeen,LastSeen,
                             SourceIP,DestinationIP,SourcePort,DestinationPort,Protocol

        switch ($fmt.ToUpper()) {
            "CSV" {
                $csvLines = $ordered | ConvertTo-Csv -NoTypeInformation
                [System.IO.File]::WriteAllLines($out, $csvLines, [System.Text.Encoding]::UTF8)
                Write-UILog "CSV written: $out"
            }
            "JSON" {
                $jsonText = $ordered | ConvertTo-Json -Depth 4
                [System.IO.File]::WriteAllText($out, $jsonText, [System.Text.Encoding]::UTF8)
                Write-UILog "JSON written: $out"
            }
            "TEXT" {
                $ts2         = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
                $totalFlows  = $lineNum.ToString('N0')
                $uniqueCount = $filteredConns.Count.ToString('N0')
                $skippedStr  = $skippedFilter.ToString('N0')
                # Safe count - sorted can be single object or array
                $policyCount = if ($sorted -is [array]) { $sorted.Count } elseif ($null -ne $sorted) { 1 } else { 0 }

                $sb = [System.Text.StringBuilder]::new()
                [void]$sb.AppendLine("=== FORTIGATE LOG ANALYSIS RESULTS v3.1.0 ===")
                [void]$sb.AppendLine("Analysis Date          : $ts2")
                [void]$sb.AppendLine("Total Lines Read       : $totalFlows")
                [void]$sb.AppendLine("Lines Excluded (filter): $skippedStr")
                [void]$sb.AppendLine("Unique Policy Patterns : $uniqueCount")
                [void]$sb.AppendLine("Active Filters         : $filterSummary")
                [void]$sb.AppendLine("")
                $idx = 0
                foreach ($item in $sorted) {
                    $idx++
                    $act = if ($item.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
                    [void]$sb.AppendLine("Policy        : $($item.PolicyName)")
                    [void]$sb.AppendLine("Source        : $($item.Source) via $($item.IncomingInterface)")
                    [void]$sb.AppendLine("Destination   : $($item.Destination) via $($item.OutgoingInterface)")
                    [void]$sb.AppendLine("Service       : $($item.Service)")
                    [void]$sb.AppendLine("Action        : $act")
                    [void]$sb.AppendLine("NAT           : $($item.NatEnabled)")
                    [void]$sb.AppendLine("Traffic Count : $($item.TrafficCount)")
                    if ($idx -lt $sorted.Count) { [void]$sb.AppendLine("============================") }
                }
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("=== SUMMARY ===")
                [void]$sb.AppendLine("Policies Required : $policyCount")
                [void]$sb.AppendLine("Generated by FortiAnalyzer Log Parser GUI v3.1.0-WPF")
                [System.IO.File]::WriteAllText($out, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Write-UILog "TEXT written: $out"
            }
            "HTML" {
                $ts2         = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
                $totalFlows  = $lineNum.ToString('N0')
                $uniqueCount = $filteredConns.Count.ToString('N0')
                $skippedStr  = $skippedFilter.ToString('N0')
                $filterHtml  = Encode-Html $filterSummary

                $sb = [System.Text.StringBuilder]::new()
                [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiAnalyzer Network Traffic Analysis v3.1.0</title>
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
  .tbl-wrap{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.07);overflow:auto}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  thead th{background:#0f3460;color:#fff;padding:11px 13px;text-align:left;font-weight:600;white-space:nowrap}
  tbody td{padding:10px 13px;border-bottom:1px solid #f0f0f0;vertical-align:top}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover{background:#f7f9fc}
  .badge{display:inline-block;padding:1px 9px;border-radius:10px;font-size:.72rem;font-weight:700}
  .allow{background:#d4edda;color:#155724}
  .deny{background:#f8d7da;color:#721c24}
  .nat-on{background:#dbeafe;color:#1e40af}
  .mono{font-family:'Courier New',monospace;font-size:.8rem}
  .footer{text-align:center;padding:16px;color:#aaa;font-size:.78rem}
</style>
</head>
<body>
<div class="hdr">
  <h1>FortiAnalyzer Network Traffic Analysis</h1>
  <div class="sub">v3.1.0-WPF - Generated $ts2</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><h3>Lines Read</h3><div class="val">$totalFlows</div></div>
    <div class="card"><h3>Excluded by Filters</h3><div class="val">$skippedStr</div></div>
    <div class="card"><h3>Policies Required</h3><div class="val">$uniqueCount</div></div>
  </div>
  <div class="filter-bar"><strong>Active Filters:</strong> $filterHtml</div>
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th>#</th><th>Policy Name</th><th>In Intf</th><th>Out Intf</th>
      <th>Source Subnet</th><th>Dest Subnet</th><th>Service</th>
      <th>Action</th><th>NAT</th><th>Traffic</th>
    </tr></thead>
    <tbody>
"@)
                $rowNum = 0
                foreach ($item in $sorted) {
                    $rowNum++
                    $pn       = Encode-Html $item.PolicyName
                    $ii       = Encode-Html $item.IncomingInterface
                    $oi       = Encode-Html $item.OutgoingInterface
                    $src      = Encode-Html $item.Source
                    $dst      = Encode-Html $item.Destination
                    $svc      = Encode-Html $item.Service
                    $actLabel = if ($item.Action -eq 'accept') { 'ALLOW' } else { 'DENY' }
                    $actClass = if ($item.Action -eq 'accept') { 'allow' } else { 'deny' }
                    $natLabel = Encode-Html $item.NatEnabled
                    $natClass = if ($item.NatEnabled -eq 'Enabled') { 'nat-on' } else { '' }
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
    </tr>
"@)
                }
                [void]$sb.Append(@"
    </tbody></table></div>
  <div class="footer">FortiAnalyzer Log Parser GUI v3.1.0-WPF - $lineNum lines processed</div>
</div></body></html>
"@)
                [System.IO.File]::WriteAllText($out, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Write-UILog "HTML written: $out"
            }
        }

        # -- Done ------------------------------------------------------------

        $UI.LastOutputPath.Value = $out
        $UI.Window.Dispatcher.Invoke([Action]{
            $UI.ProgressBar.Value        = 100
            $UI.Status.Text              = "Complete - $($filteredConns.Count) policies / $lineNum lines / $skippedFilter excluded"
            $UI.BtnRun.IsEnabled         = $true
            $UI.BtnRun.Content           = ">  START ANALYSIS"
            $UI.BtnCancel.IsEnabled      = $false
            $UI.BtnOpenFolder.Visibility = "Visible"

            $ts3 = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
            $UI.LogBox.AppendText("[$ts3] [Success] Done. Saved to: $out`n")
            $UI.LogBox.ScrollToEnd()

            [System.Windows.MessageBox]::Show(
                "Analysis complete!`n`nPolicies found   : $($filteredConns.Count)`nLines processed  : $lineNum`nExcluded (filter): $skippedFilter`n`nSaved to:`n$out",
                "Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information)
        })
    })

    [void]$ps.BeginInvoke()
})

#endregion

#region -- Show Window and Cleanup ----------------------------------------------

$window.ShowDialog() | Out-Null

if ($script:activePS) { try { $script:activePS.Stop() }  catch {} }
if ($script:activeRS) { try { $script:activeRS.Close(); $script:activeRS.Dispose() } catch {} }

#endregion
