$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'FortiAnalyzerParser.psm1'
Import-Module $modulePath -Force

Describe 'Get-FAServiceName' {
    It 'returns service hint when provided and not unknown' {
        $result = Get-FAServiceName -Port '443' -Protocol '6' -ServiceHint 'HTTPS'
        $result | Should Be 'HTTPS'
    }

    It 'returns mapped service name for known port' {
        $result = Get-FAServiceName -Port '22' -Protocol '6' -ServiceHint ''
        $result | Should Be 'SSH'
    }

    It 'returns TCP/port for unknown port with protocol 6' {
        $result = Get-FAServiceName -Port '9999' -Protocol '6' -ServiceHint ''
        $result | Should Be 'TCP/9999'
    }

    It 'returns UDP/port for unknown port with protocol 17' {
        $result = Get-FAServiceName -Port '9999' -Protocol '17' -ServiceHint ''
        $result | Should Be 'UDP/9999'
    }

    It 'returns PROTO/port for unknown protocol' {
        $result = Get-FAServiceName -Port '9999' -Protocol '1' -ServiceHint ''
        $result | Should Be 'PROTO1/9999'
    }

    It 'ignores hint when hint is unknown' {
        $result = Get-FAServiceName -Port '80' -Protocol '6' -ServiceHint 'unknown'
        $result | Should Be 'HTTP'
    }
}

Describe 'Convert-FASubnet' {
    It 'converts IP to /24 subnet' {
        $result = Convert-FASubnet -IPAddress '192.168.1.150' -MaskBits 24
        $result | Should Be '192.168.1.0/24'
    }

    It 'converts IP to /16 subnet' {
        $result = Convert-FASubnet -IPAddress '10.20.30.40' -MaskBits 16
        $result | Should Be '10.20.0.0/16'
    }

    It 'converts IP to /32 subnet (host)' {
        $result = Convert-FASubnet -IPAddress '10.1.1.1' -MaskBits 32
        $result | Should Be '10.1.1.1/32'
    }

    It 'converts IP to /8 subnet' {
        $result = Convert-FASubnet -IPAddress '172.16.5.99' -MaskBits 8
        $result | Should Be '172.0.0.0/8'
    }

    It 'returns original IP for invalid input' {
        $result = Convert-FASubnet -IPAddress 'not-an-ip' -MaskBits 24
        $result | Should Be 'not-an-ip'
    }
}

Describe 'Get-FAPolicyName' {
    It 'generates short policy name under 35 chars' {
        $conn = @{
            Action          = 'accept'
            SourceInterface = 'internal'
            DestInterface   = 'wan1'
            ServiceName     = 'HTTPS'
        }
        $result = Get-FAPolicyName $conn
        $result | Should Be 'ALLOW_INTERNAL_TO_WAN1_HTTPS'
    }

    It 'truncates long names with hash suffix' {
        $conn = @{
            Action          = 'deny'
            SourceInterface = 'very-long-interface-name-source'
            DestInterface   = 'very-long-interface-name-dest'
            ServiceName     = 'VERY-LONG-SERVICE-NAME-THAT-EXCEEDS-LIMIT'
        }
        $result = Get-FAPolicyName $conn
        $result.Length -le 35 | Should Be $true
        $result | Should Match '^DENY_'
    }
}

Describe 'Test-FAServiceAction' {
    It 'passes when no filters are set' {
        $result = Test-FAServiceAction -RawService 'HTTPS' -DstPort '443' -SvcName 'HTTPS' -Action 'accept' -FilterService '' -FilterAction ''
        $result | Should Be $true
    }

    It 'passes exact port match' {
        $result = Test-FAServiceAction -RawService '' -DstPort '443' -SvcName 'HTTPS' -Action 'accept' -FilterService '443' -FilterAction ''
        $result | Should Be $true
    }

    It 'fails wrong port' {
        $result = Test-FAServiceAction -RawService '' -DstPort '80' -SvcName 'HTTP' -Action 'accept' -FilterService '443' -FilterAction ''
        $result | Should Be $false
    }

    It 'passes partial service name match' {
        $result = Test-FAServiceAction -RawService 'HTTPS' -DstPort '443' -SvcName 'HTTPS' -Action 'accept' -FilterService 'HTTP' -FilterAction ''
        $result | Should Be $true
    }

    It 'fails action filter mismatch' {
        $result = Test-FAServiceAction -RawService '' -DstPort '443' -SvcName 'HTTPS' -Action 'accept' -FilterService '' -FilterAction 'deny'
        $result | Should Be $false
    }

    It 'passes action filter match' {
        $result = Test-FAServiceAction -RawService '' -DstPort '443' -SvcName 'HTTPS' -Action 'accept' -FilterService '' -FilterAction 'accept'
        $result | Should Be $true
    }
}

Describe 'Select-FAByIPFilter' {
    $script:testConns = @{}
    $script:testConns['k1'] = @{ Count=10; Connection=@{ SourceIP='10.1.1.1'; DestIP='8.8.8.8'; SourceSubnet='10.1.1.0/24'; DestSubnet='8.8.8.0/24' } }
    $script:testConns['k2'] = @{ Count=5; Connection=@{ SourceIP='192.168.1.1'; DestIP='8.8.4.4'; SourceSubnet='192.168.1.0/24'; DestSubnet='8.8.4.0/24' } }

    It 'returns all when no filters' {
        $result = Select-FAByIPFilter -UniqueConnections $script:testConns -FilterSrcIP '' -FilterDstIP ''
        $result.Count | Should Be 2
    }

    It 'filters by exact source IP' {
        $result = Select-FAByIPFilter -UniqueConnections $script:testConns -FilterSrcIP '10.1.1.1' -FilterDstIP ''
        $result.Count | Should Be 1
        $result.ContainsKey('k1') | Should Be $true
    }

    It 'falls back to subnet prefix match' {
        $result = Select-FAByIPFilter -UniqueConnections $script:testConns -FilterSrcIP '10.1.1' -FilterDstIP ''
        $result.Count | Should Be 1
        $result.ContainsKey('k1') | Should Be $true
    }
}

Describe 'Find-FAShadowRules' {
    It 'detects shadow rules' {
        $pols = @(
            @{ PolicyName='ALLOW_ALL'; Source='0.0.0.0/0'; Destination='0.0.0.0/0'; Service='HTTPS'; Action='accept'; TrafficCount=100 }
            @{ PolicyName='ALLOW_SPECIFIC'; Source='10.0.0.0/8'; Destination='10.0.0.0/8'; Service='HTTPS'; Action='accept'; TrafficCount=50 }
        )
        $result = @(Find-FAShadowRules -Policies $pols)
        $result.Count | Should Be 1
        $result[0].Type | Should Be 'Shadow Rule'
    }

    It 'returns empty when no shadows' {
        $pols = @(
            @{ PolicyName='ALLOW_HTTP'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; TrafficCount=100 }
            @{ PolicyName='DENY_ALL'; Source='0.0.0.0/0'; Destination='0.0.0.0/0'; Service='any'; Action='deny'; TrafficCount=50 }
        )
        $result = @(Find-FAShadowRules -Policies $pols)
        $result.Count | Should Be 0
    }
}

Describe 'Test-FACompliance' {
    It 'flags overly broad source' {
        $pols = @(
            @{ PolicyName='RULE1'; Source='0.0.0.0/0'; Destination='10.0.0.0/8'; Service='HTTPS'; Action='accept'; TrafficCount=100 }
        )
        $result = Test-FACompliance -Policies $pols
        $found = $result | Where-Object { $_.Type -eq 'Overly Broad Source' }
        $found | Should Not BeNullOrEmpty
    }

    It 'flags high-risk services' {
        $pols = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='RDP'; Action='accept'; TrafficCount=100 }
        )
        $result = Test-FACompliance -Policies $pols
        $found = $result | Where-Object { $_.Type -eq 'High-Risk Service' }
        $found | Should Not BeNullOrEmpty
    }

    It 'flags missing deny-all' {
        $pols = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTPS'; Action='accept'; TrafficCount=100 }
        )
        $result = Test-FACompliance -Policies $pols
        $found = $result | Where-Object { $_.Type -eq 'Missing Deny-All' }
        $found | Should Not BeNullOrEmpty
    }

    It 'passes clean policy set' {
        $pols = @(
            @{ PolicyName='ALLOW_HTTP'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTPS'; Action='accept'; TrafficCount=100 }
            @{ PolicyName='DENY_ALL'; Source='0.0.0.0/0'; Destination='0.0.0.0/0'; Service='ANY'; Action='deny'; TrafficCount=0 }
        )
        $result = Test-FACompliance -Policies $pols
        $critical = $result | Where-Object { $_.Severity -eq 'Critical' }
        $critical | Should BeNullOrEmpty
    }
}

Describe 'Compare-FARules' {
    It 'detects added rules' {
        $baseline = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; IncomingInterface='internal'; OutgoingInterface='wan1' }
        )
        $current = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; IncomingInterface='internal'; OutgoingInterface='wan1' }
            @{ PolicyName='RULE2'; Source='192.168.0.0/16'; Destination='0.0.0.0/0'; Service='HTTPS'; Action='accept'; IncomingInterface='dmz'; OutgoingInterface='wan1' }
        )
        $result = Compare-FARules -Baseline $baseline -Current $current
        $result.Added.Count | Should Be 1
    }

    It 'detects removed rules' {
        $baseline = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; IncomingInterface='internal'; OutgoingInterface='wan1' }
            @{ PolicyName='RULE2'; Source='192.168.0.0/16'; Destination='0.0.0.0/0'; Service='HTTPS'; Action='accept'; IncomingInterface='dmz'; OutgoingInterface='wan1' }
        )
        $current = @(
            @{ PolicyName='RULE1'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; IncomingInterface='internal'; OutgoingInterface='wan1' }
        )
        $result = Compare-FARules -Baseline $baseline -Current $current
        $result.Removed.Count | Should Be 1
    }
}

Describe 'Export-FAFortiGateCLI' {
    It 'generates valid CLI output' {
        $pols = @(
            @{ PolicyName='ALLOW_HTTP'; Source='10.0.0.0/8'; Destination='0.0.0.0/0'; Service='HTTP'; Action='accept'; IncomingInterface='internal'; OutgoingInterface='wan1'; NatEnabled='Disabled'; DestinationPort='80' }
        )
        $result = Export-FAFortiGateCLI -Policies $pols
        $result | Should Match 'config firewall policy'
        $result | Should Match 'edit 1'
        $result | Should Match 'set name "ALLOW_HTTP"'
        $result | Should Match 'set action accept'
        $result | Should Match 'end'
    }
}

Describe 'Initialize-FAMetrics' {
    It 'returns metrics object with correct defaults' {
        $m = Initialize-FAMetrics
        $m.ProcessedLines | Should Be 0
        $m.SkippedLines | Should Be 0
        $m.ErrorCount | Should Be 0
        $m.WarningCount | Should Be 0
    }
}
