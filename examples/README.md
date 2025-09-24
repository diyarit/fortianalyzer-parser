# Examples

This directory contains example usage scenarios and sample outputs.

## Sample Log Format

FortiAnalyzer logs should contain entries like:
```
date=2024-01-15 time=10:30:45 srcip=192.168.1.10 dstip=10.0.0.5 srcport=54321 dstport=80 service="HTTP" srcintf="internal" dstintf="wan1" action="accept" proto=6
date=2024-01-15 time=10:30:46 srcip=192.168.1.15 dstip=8.8.8.8 srcport=12345 dstport=53 service="DNS" srcintf="internal" dstintf="wan1" action="accept" proto=17
```

## Usage Examples

### Basic Parsing
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "sample-traffic.log"
```

### With Progress Tracking
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "large-traffic.log" -ShowProgress
```

### Generate FortiGate Config
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -GenerateFortiGateConfig -OutputFile "network-rules.csv"
```

## Expected Output

The script will generate a CSV file with consolidated network rules:

```csv
Number,Name,Source,SourceInterface,Destinations,DestInterface,Services,Action,Description
1,Rule_1,192.168.1.0/24,internal,10.0.0.0/24,wan1,HTTP,Allow,Auto-generated from traffic analysis
2,Rule_2,192.168.1.0/24,internal,8.8.8.0/24,wan1,DNS,Allow,Auto-generated from traffic analysis
```

## Performance Notes

- Small files (< 1MB): Process in seconds
- Medium files (1-100MB): Process in minutes with progress tracking
- Large files (> 100MB): Use `-ShowProgress` for monitoring

## Troubleshooting

If you encounter issues:
1. Ensure log file format matches expected FortiAnalyzer format
2. Check PowerShell execution policy
3. Verify file permissions
4. Use `-ShowProgress` to monitor processing