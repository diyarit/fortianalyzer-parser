<#
.SYNOPSIS
    FortiAnalyzer Log Parser - GUI Version
.DESCRIPTION
    WPF GUI for the FortiAnalyzer Log Parser tool. Uses shared FortiAnalyzerParser module.
.VERSION
    4.0.0-WPF
.AUTHOR
    Diyar Abbas
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

# ── Load shared module ────────────────────────────────────────────────────────
$modulePath = Join-Path $PSScriptRoot 'FortiAnalyzerParser.psm1'
if (-not (Test-Path $modulePath)) {
    [System.Windows.MessageBox]::Show("Shared module not found:`n$modulePath", "Fatal Error",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    return
}
Import-Module $modulePath -Force

# Read version from manifest
$manifestPath = Join-Path $PSScriptRoot 'FortiAnalyzerParser.psd1'
if (Test-Path $manifestPath) {
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction SilentlyContinue
    if ($manifest) { $displayVersion = $manifest.Version.ToString() }
}
if (-not $displayVersion) { $displayVersion = '4.0.0' }

# ── XAML UI ───────────────────────────────────────────────────────────────────
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="FortiAnalyzer Log Parser  v$displayVersion-WPF"
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
                <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#DC2626"/></Trigger>
                <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#9CA3AF"/></Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="GhostBtn" TargetType="Button" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#4B5563"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#374151"/></Trigger>
                <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#9CA3AF"/></Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="AmberBtn" TargetType="Button" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#D97706"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#B45309"/></Trigger>
                <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#9CA3AF"/></Trigger>
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
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#1E3A8A" Padding="20,14">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="FortiAnalyzer" Foreground="White" FontSize="20" FontWeight="Bold"/>
                <TextBlock Text=" Log Parser" Foreground="#93C5FD" FontSize="20" FontWeight="Light"/>
                <TextBlock Name="lblVersion" Text=" v4.0.0-WPF" Foreground="#60A5FA" FontSize="12" VerticalAlignment="Bottom" Margin="10,0,0,4"/>
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
                    <CheckBox Name="chkDebug" Content="Debug Mode" Margin="0,0,24,0" VerticalAlignment="Center"/>
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
                    <Border Name="filterBadge" Background="#F59E0B" CornerRadius="8" Padding="6,1" Margin="8,0,0,0" Visibility="Collapsed">
                        <TextBlock Name="filterBadgeText" Text="0 active" Foreground="White" FontSize="10" FontWeight="Bold"/>
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
                <TextBlock Text="Src IP / Prefix:" VerticalAlignment="Center" Foreground="#374151" Margin="0,0,8,0"/>
                <TextBox Name="txtFilterSrcIP" Grid.Column="1" Height="28"/>
                <Button Name="btnClearSrcIP" Grid.Column="2" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"/>
                <TextBlock Text="Dst IP / Prefix:" Grid.Column="3" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <TextBox Name="txtFilterDstIP" Grid.Column="4" Height="28"/>
                <Button Name="btnClearDstIP" Grid.Column="5" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"/>
                <TextBlock Text="Service:" Grid.Column="6" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <TextBox Name="txtFilterService" Grid.Column="7" Height="28"/>
                <Button Name="btnClearService" Grid.Column="8" Content="x" Style="{StaticResource DangerBtn}"
                        Height="22" Width="20" FontSize="10" Padding="0" Margin="2,0,0,0"/>
                <TextBlock Text="Action:" Grid.Column="9" VerticalAlignment="Center" Foreground="#374151" Margin="16,0,8,0"/>
                <ComboBox Name="cmbFilterAction" Grid.Column="10" Height="28" SelectedIndex="0">
                    <ComboBoxItem Content="Any"/>
                    <ComboBoxItem Content="Allow only"/>
                    <ComboBoxItem Content="Deny only"/>
                </ComboBox>
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
            <Button Name="btnRun" Content=">  START ANALYSIS" Height="44" FontSize="14" FontWeight="Bold"
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
                                Style="{StaticResource GhostBtn}" Height="22" Width="52" FontSize="11" Padding="4,2"/>
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

# ── Load Window ───────────────────────────────────────────────────────────────
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$btnBrowse          = $window.FindName('btnBrowse')
$btnRun             = $window.FindName('btnRun')
$btnCancel          = $window.FindName('btnCancel')
$btnClearLog        = $window.FindName('btnClearLog')
$btnOpenFolder      = $window.FindName('btnOpenFolder')
$btnClearAllFilters = $window.FindName('btnClearAllFilters')
$btnClearSrcIP      = $window.FindName('btnClearSrcIP')
$btnClearDstIP      = $window.FindName('btnClearDstIP')
$btnClearService    = $window.FindName('btnClearService')
$txtLogFile         = $window.FindName('txtLogFile')
$txtOutputFile      = $window.FindName('txtOutputFile')
$txtSubnetMask      = $window.FindName('txtSubnetMask')
$txtFilterSrcIP     = $window.FindName('txtFilterSrcIP')
$txtFilterDstIP     = $window.FindName('txtFilterDstIP')
$txtFilterService   = $window.FindName('txtFilterService')
$cmbFormat          = $window.FindName('cmbFormat')
$cmbFilterAction    = $window.FindName('cmbFilterAction')
$txtLog             = $window.FindName('txtLog')
$progressBar        = $window.FindName('progressBar')
$lblStatus          = $window.FindName('lblStatus')
$lblVersion         = $window.FindName('lblVersion')
$chkDebug           = $window.FindName('chkDebug')
$chkParallel        = $window.FindName('chkParallel')
$filterBadge        = $window.FindName('filterBadge')
$filterBadgeText    = $window.FindName('filterBadgeText')

$lblVersion.Text = " v$displayVersion-WPF"
        $window.Title    = "FortiAnalyzer Log Parser  v$displayVersion-WPF"

$script:activePS       = $null
$script:activeRS       = $null
$script:lastOutputPath = ''

# ── Helpers ───────────────────────────────────────────────────────────────────
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
        'JSON' { return '.json' }
        'HTML' { return '.html' }
        'TEXT' { return '.txt'  }
        default { return '.csv'  }
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

function Update-FilterBadge {
    $count = 0
    if (-not [string]::IsNullOrWhiteSpace($txtFilterSrcIP.Text))   { $count++ }
    if (-not [string]::IsNullOrWhiteSpace($txtFilterDstIP.Text))   { $count++ }
    if (-not [string]::IsNullOrWhiteSpace($txtFilterService.Text)) { $count++ }
    $actionSel = Get-SelectedFormat $cmbFilterAction
    if ($actionSel -ne 'Any') { $count++ }
    if ($count -gt 0) {
        $filterBadge.Visibility  = 'Visible'
        $filterBadgeText.Text    = "$count active"
    } else {
        $filterBadge.Visibility  = 'Collapsed'
    }
}

# ── Event Handlers ────────────────────────────────────────────────────────────
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title  = 'Select FortiAnalyzer Log File'
    $dlg.Filter = 'Log Files (*.log;*.txt)|*.log;*.txt|All Files (*.*)|*.*'
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtLogFile.Text = $dlg.FileName
        $dir  = Split-Path $dlg.FileName -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($dlg.FileName)
        $fmt  = Get-SelectedFormat $cmbFormat
        $ext  = Get-FormatExtension $fmt
        $txtOutputFile.Text = Join-Path $dir "${name}-NetworkTraffic${ext}"
        $btnOpenFolder.Visibility = 'Collapsed'
    }
})

$cmbFormat.Add_SelectionChanged({
    Update-OutputExtension $txtOutputFile (Get-SelectedFormat $cmbFormat)
})

$txtFilterSrcIP.Add_TextChanged({   Update-FilterBadge })
$txtFilterDstIP.Add_TextChanged({   Update-FilterBadge })
$txtFilterService.Add_TextChanged({ Update-FilterBadge })
$cmbFilterAction.Add_SelectionChanged({ Update-FilterBadge })

$btnClearSrcIP.Add_Click({   $txtFilterSrcIP.Clear() })
$btnClearDstIP.Add_Click({   $txtFilterDstIP.Clear() })
$btnClearService.Add_Click({ $txtFilterService.Clear() })

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
    $btnRun.Content      = '>  START ANALYSIS'
    $btnCancel.IsEnabled = $false
    $lblStatus.Text      = 'Cancelled.'
    $progressBar.Value   = 0
    $ts = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $txtLog.AppendText("[$ts] [Warning] Analysis cancelled by user.`n")
    $txtLog.ScrollToEnd()
})

# ── Drag and Drop ─────────────────────────────────────────────────────────────
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
        $btnOpenFolder.Visibility = 'Collapsed'
        $btnRun.RaiseEvent([System.Windows.RoutedEventArgs]::new(
            [System.Windows.Controls.Button]::ClickEvent))
    }
})

# ── Main Analysis ─────────────────────────────────────────────────────────────
$btnRun.Add_Click({
    $path      = $txtLogFile.Text.Trim()
    $fmt       = Get-SelectedFormat $cmbFormat
    $maskBits  = Get-SafeSubnetMask $txtSubnetMask.Text
    $debugMode = $chkDebug.IsChecked

    $fSrcIP   = $txtFilterSrcIP.Text.Trim()
    $fDstIP   = $txtFilterDstIP.Text.Trim()
    $fService = $txtFilterService.Text.Trim()
    $fActionRaw = Get-SelectedFormat $cmbFilterAction
    $fAction  = switch ($fActionRaw) {
        'Allow only' { 'accept' }
        'Deny only'  { 'deny'   }
        default      { ''       }
    }

    $out = $txtOutputFile.Text.Trim()
    $ext = Get-FormatExtension $fmt
    if ($out -match '\.(csv|json|html|txt)$') {
        $out = $out -replace '\.(csv|json|html|txt)$', $ext
    } else {
        $out += $ext
    }
    $txtOutputFile.Text = $out

    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
        [System.Windows.MessageBox]::Show("Log file not found:`n$path", "Validation Error",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $btnRun.IsEnabled         = $false
    $btnRun.Content           = 'Processing...'
    $btnCancel.IsEnabled      = $true
    $btnOpenFolder.Visibility = 'Collapsed'
    $progressBar.Value        = 0
    $txtLog.Clear()
    $lblStatus.Text           = 'Starting analysis...'

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
        Patterns        = Get-FAServicePatterns
        ServiceMappings = Get-FAServiceMappings
        LastOutputPath  = [ref]$script:lastOutputPath
        FilterSrcIP     = $fSrcIP
        FilterDstIP     = $fDstIP
        FilterService   = $fService
        FilterAction    = $fAction
        Version         = $displayVersion
    })

    $script:activeRS = [runspacefactory]::CreateRunspace()
    $script:activeRS.ApartmentState = 'STA'
    $script:activeRS.ThreadOptions  = 'ReuseThread'
    $script:activeRS.Open()
    $script:activeRS.SessionStateProxy.SetVariable('UI', $uiHash)

    $ps = [PowerShell]::Create()
    $ps.Runspace = $script:activeRS
    $script:activePS = $ps

    [void]$ps.AddScript({
        # ── Inner helpers (using module functions via initial session state) ──
        function Write-UILog {
            param([string]$Msg, [string]$Level = 'Info')
            $ts   = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
            $line = "[$ts] [$Level] $Msg`n"
            $UI.Window.Dispatcher.Invoke([Action]{
                $UI.LogBox.AppendText($line)
                $UI.LogBox.ScrollToEnd()
            })
        }

        function Get-SvcName {
            param($Port, $Protocol, $Hint, $Map)
            if (-not [string]::IsNullOrWhiteSpace($Hint) -and $Hint -ne 'unknown') { return $Hint.ToUpper() }
            if ($Map.ContainsKey($Port)) { return $Map[$Port] }
            switch ($Protocol) { '6' { "TCP/$Port" } '17' { "UDP/$Port" } default { "PROTO${Protocol}/$Port" } }
        }

        function Convert-Subnet {
            param([string]$IP, [int]$Bits)
            try {
                $o = $IP -split '\.'
                if ($o.Count -ne 4) { return $IP }
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
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($svc))
            $sha1.Dispose()
            $h = ([System.BitConverter]::ToString($hashBytes) -replace '-','').Substring(0,5)
            $short = "${act}_${sIntf}_TO_${dIntf}_${h}"
            if ($short.Length -gt 35) { $short = $short.Substring(0,35) }
            return $short
        }

        function Encode-Html {
            param([string]$v)
            [System.Web.HttpUtility]::HtmlEncode($v)
        }

        function Test-ServiceAction {
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
            param($UniqueConns, $FSrcIP, $FDstIP)
            if (-not $FSrcIP -and -not $FDstIP) { return $UniqueConns }
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
            Write-UILog 'IP filter: no exact matches - trying subnet prefix fallback.'
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

        # ── Variables ──────────────────────────────────────────────────────
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

        $filterParts = @()
        if ($fSrcIP)   { $filterParts += "SrcIP = '$fSrcIP'" }
        if ($fDstIP)   { $filterParts += "DstIP = '$fDstIP'" }
        if ($fService) {
            if ($fService -match '^\d+$') { $filterParts += "Port = $fService" }
            else { $filterParts += "Service contains '$fService'" }
        }
        if ($fAction)  { $filterParts += "Action = '$fAction'" }
        $filterSummary = if ($filterParts.Count -gt 0) { $filterParts -join '  AND  ' } else { 'None (showing all)' }

        Write-UILog "File     : $path  ($([Math]::Round($totalBytes/1MB,2)) MB)"
        Write-UILog "Format   : $fmt  |  Subnet mask : /$maskBits"
        Write-UILog "Filters  : $filterSummary"

        # ── Streaming parse ────────────────────────────────────────────────
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

                $serviceRaw = if ($mSvcRaw.Success) { $mSvcRaw.Groups[1].Value } else { '' }
                $proto      = if ($mProto.Success)  { $mProto.Groups[1].Value }  else { '' }
                $action = if ($mAct.Success) {
                    switch ($mAct.Groups[1].Value.ToLower()) {
                        'close'      { 'accept' }
                        'accept'     { 'accept' }
                        'deny'       { 'deny'   }
                        'server-rst' { 'accept' }
                        'client-rst' { 'accept' }
                        default      { $mAct.Groups[1].Value }
                    }
                } else { '' }
                $svcName = Get-SvcName $dstport $proto $serviceRaw $maps

                if (-not (Test-ServiceAction $serviceRaw $dstport $svcName $action $fService $fAction)) {
                    $skippedFilter++
                    continue
                }

                $mSrcPort = $pats.srcport.Match($line)
                $mSrcInt  = $pats.srcintf.Match($line)
                $mDstInt  = $pats.dstintf.Match($line)
                $mTran    = $pats.trandisp.Match($line)

                $srcport = if ($mSrcPort.Success) { $mSrcPort.Groups[1].Value } else { '' }
                $srcintf = if ($mSrcInt.Success)  { $mSrcInt.Groups[1].Value }  else { '' }
                $dstintf = if ($mDstInt.Success)  { $mDstInt.Groups[1].Value }  else { '' }
                $tran    = if ($mTran.Success)    { $mTran.Groups[1].Value }    else { 'noop' }
                $nat     = if ($tran -match 'snat|dnat') { 'Enabled' } else { 'Disabled' }

                $conn = @{
                    SourceIP=$srcip; DestIP=$dstip; SourcePort=$srcport; DestPort=$dstport
                    Service=$serviceRaw; SourceInterface=$srcintf; DestInterface=$dstintf
                    Action=$action; Protocol=$proto; NatEnabled=$nat
                    SourceSubnet=(Convert-Subnet $srcip $maskBits); DestSubnet=(Convert-Subnet $dstip $maskBits)
                    ServiceName=$svcName; LineNumber=$lineNum
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
                    $UI.Window.Dispatcher.Invoke([Action]{
                        $UI.ProgressBar.Value = $pct
                        $UI.Status.Text = "Line $lineNum  |  $($uniqueConns.Count) matched patterns  |  $pct%"
                    })
                }
            }
        }
        finally { $stream.Dispose() }

        Write-UILog "Parse complete: $lineNum lines, $($uniqueConns.Count) unique patterns, $skippedFilter excluded."

        $filteredConns = Select-ByIPFilter $uniqueConns $fSrcIP $fDstIP

        # ── Export ─────────────────────────────────────────────────────────
        $UI.Window.Dispatcher.Invoke([Action]{ $UI.Status.Text = 'Exporting data...' })

        $exportList = [System.Collections.ArrayList]::new()
        foreach ($kv in $filteredConns.GetEnumerator()) {
            $d = $kv.Value; $c = $d.Connection
            [void]$exportList.Add([PSCustomObject]@{
                PolicyName=$c.PolicyName; IncomingInterface=$c.SourceInterface; OutgoingInterface=$c.DestInterface
                Source=$c.SourceSubnet; Destination=$c.DestSubnet; Service=$c.ServiceName
                Action=$c.Action; NatEnabled=$c.NatEnabled; TrafficCount=$d.Count
                FirstSeen=$d.FirstSeen; LastSeen=$d.LastSeen
                SourceIP=$c.SourceIP; DestinationIP=$c.DestIP
                SourcePort=$c.SourcePort; DestinationPort=$c.DestPort; Protocol=$c.Protocol
            })
        }

        $sorted  = $exportList | Sort-Object TrafficCount -Descending
        $ordered = $sorted | Select-Object PolicyName,IncomingInterface,OutgoingInterface,
                             Source,Destination,Service,Action,NatEnabled,
                             TrafficCount,FirstSeen,LastSeen,
                             SourceIP,DestinationIP,SourcePort,DestinationPort,Protocol

        switch ($fmt.ToUpper()) {
            'CSV' {
                $csvLines = $ordered | ConvertTo-Csv -NoTypeInformation
                [System.IO.File]::WriteAllLines($out, $csvLines, [System.Text.Encoding]::UTF8)
                Write-UILog "CSV written: $out"
            }
            'JSON' {
                $jsonText = $ordered | ConvertTo-Json -Depth 4
                [System.IO.File]::WriteAllText($out, $jsonText, [System.Text.Encoding]::UTF8)
                Write-UILog "JSON written: $out"
            }
            'TEXT' {
                $ts2         = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
                $totalFlows  = $lineNum.ToString('N0')
                $uniqueCount = $filteredConns.Count.ToString('N0')
                $skippedStr  = $skippedFilter.ToString('N0')
                $policyCount = if ($sorted -is [array]) { $sorted.Count } elseif ($null -ne $sorted) { 1 } else { 0 }
                $ver = $UI.Version

                $sb = [System.Text.StringBuilder]::new()
                [void]$sb.AppendLine("=== FORTIGATE LOG ANALYSIS RESULTS v$ver ===")
                [void]$sb.AppendLine("Analysis Date          : $ts2")
                [void]$sb.AppendLine("Total Lines Read       : $totalFlows")
                [void]$sb.AppendLine("Lines Excluded (filter): $skippedStr")
                [void]$sb.AppendLine("Unique Policy Patterns : $uniqueCount")
                [void]$sb.AppendLine("Active Filters         : $filterSummary")
                [void]$sb.AppendLine('')
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
                    if ($idx -lt $sorted.Count) { [void]$sb.AppendLine('============================') }
                }
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('=== SUMMARY ===')
                [void]$sb.AppendLine("Policies Required : $policyCount")
                [void]$sb.AppendLine("Generated by FortiAnalyzer Log Parser GUI v$ver-WPF")
                [System.IO.File]::WriteAllText($out, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Write-UILog "TEXT written: $out"
            }
            'HTML' {
                $ts2         = [DateTime]::Now.ToString("MMMM dd, yyyy 'at' HH:mm:ss")
                $totalFlows  = $lineNum.ToString('N0')
                $uniqueCount = $filteredConns.Count.ToString('N0')
                $skippedStr  = $skippedFilter.ToString('N0')
                $filterHtml  = Encode-Html $filterSummary
                $ver = $UI.Version

                # Build chart data
                $topServices = @($sorted | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 10)
                $topSrcIPs   = @($sorted | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 10)
                $allowCount  = @($sorted | Where-Object Action -eq 'accept').Count
                $denyCount   = @($sorted | Where-Object Action -eq 'deny').Count
                $maxSvcCount = if ($topServices.Count -gt 0) { ($topServices | Measure-Object Count -Maximum).Maximum } else { 1 }
                $totalCount  = [Math]::Max($allowCount + $denyCount, 1)

                $sb = [System.Text.StringBuilder]::new()
                [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiAnalyzer Traffic Analysis v$ver</title>
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
.detail-cell{padding:8px 13px 12px;background:#f9fafb;font-size:.8rem;color:#555;border-bottom:2px solid #e5e7eb}
@media print{
  .search-bar,.expand-btn{display:none!important}
  .hdr{background:#1a1a2e!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  tbody tr:hover{background:none}
  .tbl-wrap{box-shadow:none;border:1px solid #ddd}
  @page{margin:1cm}
}
</style>
</head>
<body>
<div class="hdr">
  <h1>FortiAnalyzer Network Traffic Analysis</h1>
  <div class="sub">v$ver-WPF - Generated $ts2</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><h3>Lines Read</h3><div class="val">$totalFlows</div></div>
    <div class="card"><h3>Excluded by Filters</h3><div class="val">$skippedStr</div></div>
    <div class="card"><h3>Policies Required</h3><div class="val">$uniqueCount</div></div>
  </div>
  <div class="filter-bar"><strong>Active Filters:</strong> $filterHtml</div>

  <div class="charts">
    <div class="chart-box">
      <h3>Top 10 Services</h3>
"@)

                foreach ($svc in $topServices) {
                    $pct2 = [Math]::Round(($svc.Count / $maxSvcCount) * 100)
                    $name2 = Encode-Html $svc.Name
                    [void]$sb.Append(@"
      <div class="bar-row">
        <div class="bar-label" title="$name2">$name2</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct2}%;background:#3B82F6"></div></div>
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
          <div class="donut-center">$($sorted.Count)</div>
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
                    $srcIP    = Encode-Html $item.SourceIP
                    $dstIP    = Encode-Html $item.DestinationIP

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
  <div class="footer">FortiAnalyzer Log Parser GUI v$ver-WPF - $lineNum lines processed</div>
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
    var dir=th.classList.contains('sort-asc')?'desc':'asc';
    document.querySelectorAll('#policyTable thead th').forEach(function(h){h.classList.remove('sort-asc','sort-desc')});
    th.classList.add('sort-'+dir);
    var getVal=function(r,c){
      var cell=r.cells[c];if(!cell)return'';
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
                [System.IO.File]::WriteAllText($out, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Write-UILog "HTML written: $out"
            }
        }

        # ── Done ──────────────────────────────────────────────────────────
        $UI.LastOutputPath.Value = $out
        $UI.Window.Dispatcher.Invoke([Action]{
            $UI.ProgressBar.Value        = 100
            $UI.Status.Text              = "Complete - $($filteredConns.Count) policies / $lineNum lines / $skippedFilter excluded"
            $UI.BtnRun.IsEnabled         = $true
            $UI.BtnRun.Content           = '>  START ANALYSIS'
            $UI.BtnCancel.IsEnabled      = $false
            $UI.BtnOpenFolder.Visibility = 'Visible'

            $ts3 = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
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

# ── Show Window ───────────────────────────────────────────────────────────────
$window.ShowDialog() | Out-Null

if ($script:activePS) { try { $script:activePS.Stop() }  catch {} }
if ($script:activeRS) { try { $script:activeRS.Close(); $script:activeRS.Dispose() } catch {} }
