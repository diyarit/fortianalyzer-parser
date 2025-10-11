# FortiAnalyzer Log Parser

Ever stared at thousands of lines of FortiAnalyzer logs wondering what's actually happening on your network? This PowerShell script does the heavy lifting for you. It chews through those logs and spits out clean, organized data about who's talking to whom on your network.

## What it does

- Parses FortiAnalyzer logs and pulls out the important network stuff
- Groups IP addresses into subnets (because who wants to see 192.168.1.1, 192.168.1.2, 192.168.1.3... when you can just see 192.168.1.0/24)
- Figures out which interfaces traffic is coming from and going to
- Translates port numbers into actual service names (port 80 = HTTP, etc.)
- Shows you a progress bar so you know it's not frozen on big files
- Supports multiple output formats (CSV, JSON, HTML) for flexible data analysis
- Offers parallel processing for faster analysis of large log files
- Won't crash your computer even with massive log files

## What you need

- PowerShell 5.1 or newer (pretty much any Windows machine from the last few years)
- PowerShell Core 6.0+ if you're on Linux/Mac
- Access to your FortiAnalyzer log files (obviously)

## Getting started

1. Download the script (or clone if you're into that):
```bash
git clone https://github.com/diyarit/fortianalyzer-parser.git
cd fortianalyzer-parser
```

2. If PowerShell complains about execution policies:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## How to use it

### Just the basics
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log"
```

### Want to see progress? (recommended for big files)
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -ShowProgress
```

### With detailed logging and debugging
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -DebugMode
```

### Custom output filename
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -OutputFile "my-network-data.csv"
```

### Using different output formats (CSV, JSON, HTML)
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -OutputFormat "JSON" -OutputFile "network-data.json"
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -OutputFormat "HTML" -OutputFile "network-report.html"
```

### Enable parallel processing for faster analysis
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -UseParallel -MaxThreads 4
```

### Full featured run (recommended for production)
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log" -ShowProgress -DebugMode -OutputFile "detailed-analysis.html" -OutputFormat "HTML" -UseParallel
```

## 📊 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `LogFilePath` | String | Yes | - | Path to the FortiAnalyzer log file |
| `OutputFile` | String | No | "NetworkTraffic.csv" | Output file name |
| `OutputFormat` | String | No | "CSV" | Output format (CSV, JSON, or HTML) |
| `ShowProgress` | Switch | No | False | Display progress bar during processing |
| `DebugMode` | Switch | No | False | Enable detailed logging and debugging information |
| `UseParallel` | Switch | No | False | Enable parallel processing for faster analysis |
| `MaxThreads` | Int | No | 4 | Maximum number of threads to use for parallel processing (1-16) |

## 📈 Output

The script generates output files in your chosen format (CSV, JSON, or HTML) with network communication details:

- **SourceIP**: Original source IP address
- **DestIP**: Original destination IP address  
- **SourcePort**: Source port number
- **DestPort**: Destination port number
- **Service**: Service name or port designation
- **SourceInterface**: Interface where traffic originated
- **DestInterface**: Outgoing interface
- **Protocol**: Network protocol (e.g., TCP, UDP)
- **Action**: Traffic action (e.g., accept, deny)
- **SourceSubnet**: Source IP consolidated into CIDR notation
- **DestSubnet**: Destination IP consolidated into CIDR notation
- **Count**: Number of occurrences of this connection pattern
- **FirstSeen**: Timestamp of first occurrence
- **LastSeen**: Timestamp of last occurrence

### Example CSV Output
```
SourceIP,DestIP,SourcePort,DestPort,Service,SourceInterface,DestInterface,Protocol,Action,SourceSubnet,DestSubnet,Count,FirstSeen,LastSeen
192.168.1.10,10.0.0.5,54321,80,HTTP,internal,wan1,6,accept,192.168.1.0/24,10.0.0.0/24,15,2024-01-15 08:12:34,2024-01-15 09:45:22
192.168.1.15,8.8.8.8,12345,53,DNS,internal,wan1,17,accept,192.168.1.0/24,8.8.8.0/24,42,2024-01-15 08:10:12,2024-01-15 10:30:45
```

### HTML Output
The HTML output includes the same data in a formatted table with basic styling and a summary section showing statistics about the processed data.

## 🔍 Log Format Support

The script supports FortiAnalyzer logs with the following fields:
- `srcip=` - Source IP address
- `dstip=` - Destination IP address  
- `srcport=` - Source port
- `dstport=` - Destination port
- `service=` - Service name
- `srcintf=` - Source interface
- `dstintf=` - Destination interface
- `action=` - Traffic action
- `proto=` - Protocol number

## Why you'd want this

- **Figure out what's actually happening** on your network instead of guessing
- **Document your network traffic** for compliance or just because your boss asked
- **Security reviews** - see what ports and services are actually being used
- **Network planning** - understand how your subnets and interfaces are connected
- **Troubleshooting** - "What was talking to what when everything broke last Tuesday?"

## The smart stuff it does

### Groups IPs into subnets
Instead of seeing every single IP, it groups them logically:
- `192.168.1.10`, `192.168.1.20`, `192.168.1.30` becomes `192.168.1.0/24`
- Still keeps the original IPs so you don't lose detail

### Translates ports to services
Because remembering port numbers is for robots:
- Port 80 → HTTP
- Port 443 → HTTPS  
- Port 53 → DNS
- Port 3389 → RDP
- Everything else → tcp/XXXX

### Won't kill your computer
- Handles huge files without eating all your RAM
- Processes stuff in chunks so it stays responsive
- Shows progress so you know it's working
- Parallel processing for even faster analysis of large files

### v2.2 New Features & Improvements
- **Multiple output formats** - export to CSV, JSON, or HTML
- **Parallel processing** - analyze logs faster with multi-threading
- **Enhanced HTML reports** - formatted tables with styling and summary statistics
- **Graceful fallback** - automatically switches to sequential processing if parallel processing isn't available

### v2.1 Performance & Reliability Improvements
- **3-5x faster processing** with pre-compiled regex patterns
- **Comprehensive error handling** - won't crash on malformed logs
- **Input validation** - catches problems before they cause issues
- **Memory monitoring** - tracks and optimizes memory usage
- **Detailed logging** - see exactly what's happening with `-DebugMode`
- **Robust recovery** - continues processing even when individual lines fail
- **Enhanced progress tracking** - shows memory usage and processing stats

## 📝 Example

```powershell
# Process a FortiAnalyzer log with progress tracking
PS> .\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic-2024-01-15.log" -ShowProgress

=== FortiAnalyzer Log Parser ===
Total lines to process: 50000
Parsing log file: traffic-2024-01-15.log
Grouping by subnets...

=== Network Communication Summary ===
SourceIP        DestIP          Service SourceInterface DestInterface SourceSubnet    DestSubnet
--------        ------          ------- --------------- ------------- ------------    ----------
192.168.1.10    10.0.0.5        HTTP    internal        wan1          192.168.1.0/24  10.0.0.0/24
192.168.1.15    8.8.8.8         DNS     internal        wan1          192.168.1.0/24  8.8.8.0/24

Results exported to: NetworkTraffic.csv

=== Summary ===
Total connections parsed: 15000
Unique connection patterns: 250
Unique networks identified: 12
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Something broken?

If it's not working right:
1. Check the [Issues](https://github.com/diyarit/fortianalyzer-parser/issues) page first
2. If your problem isn't there, create a new issue
3. Include some sample log lines (scrub out any sensitive stuff first)

## 🔄 Version History

- **v1.0.0** - Initial release with core parsing functionality
- **v1.1.0** - Added progress tracking and memory optimization
- **v1.2.0** - Enhanced subnet consolidation and service mapping
- **v2.1.0** - **MAJOR UPDATE**: Enhanced error handling, performance optimization, and input validation
  - Pre-compiled regex patterns for 3-5x performance improvement
  - Comprehensive error handling with detailed logging
  - Input validation for files, IP addresses, and port numbers
  - Memory usage monitoring and optimization
  - Enhanced progress tracking with memory usage display
  - Debug mode for detailed logging and debugging
  - Robust error recovery and graceful failure handling


---

Built by someone who got tired of manually parsing FortiAnalyzer logs. Hope it saves you some time too.