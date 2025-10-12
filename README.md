# FortiAnalyzer Log Parser

Transform thousands of FortiAnalyzer log entries into actionable FortiGate firewall policies. This PowerShell script analyzes network traffic patterns and generates ready-to-implement firewall rules with standardized naming conventions.

## 🚀 What it does

- **Parses FortiAnalyzer logs** and extracts network traffic patterns
- **Groups IP addresses into subnets** for cleaner policy management (192.168.1.0/24 instead of individual IPs)
- **Identifies traffic flows** between interfaces with source/destination mapping
- **Translates ports to services** (100+ enterprise-grade mappings: HTTP, HTTPS, databases, virtualization, cloud services, etc.)
- **Generates FortiGate-ready policies** with standardized naming conventions
- **Multiple output formats** (CSV, JSON, HTML, TEXT) for different use cases
- **Parallel processing** for faster analysis of large log files
- **Professional HTML reports** with FortiGate-style interface
- **Clean TEXT output** with policy separators for easy reading

## 🎯 Key Features

### FortiGate Policy Generation
- **Standardized naming**: `ALLOW_INTERNAL_TO_WAN1_HTTP`, `DENY_WAN1_TO_INTERNAL_RDP`
- **Traffic flow analysis**: Clear source → destination interface mapping
- **Service identification**: Automatic port-to-service translation
- **Action recommendations**: Accept/Deny based on observed traffic

### Multiple Output Formats
- **CSV**: Spreadsheet-friendly data for analysis
- **JSON**: API integration and programmatic processing
- **HTML**: Professional dashboard with FortiGate styling
- **TEXT**: Clean, readable format with policy separators

### Performance & Reliability
- **Parallel processing** with configurable thread limits
- **Memory optimization** for large files (500MB+ logs)
- **Progress tracking** with real-time statistics
- **Error handling** with detailed logging and recovery

## 📋 Requirements

- **PowerShell 5.1+** (Windows) or **PowerShell Core 6.0+** (Linux/Mac)
- Access to FortiAnalyzer log files
- Optional: ThreadJob module for parallel processing

## 🚀 Quick Start

### 1. Download & Setup
```bash
git clone https://github.com/diyarit/fortianalyzer-parser.git
cd fortianalyzer-parser
```

### 2. Set Execution Policy (Windows)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Basic Usage
```powershell
.\FortiAnalyzer-Parser.ps1 -LogFilePath "your-log-file.log"
```

## 💡 Usage Examples

### Basic Analysis
```powershell
# Simple CSV output
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log"

# With progress tracking (recommended for large files)
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -ShowProgress
```

### Different Output Formats
```powershell
# Professional HTML report
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -OutputFormat HTML -OutputFile "firewall-report.html"

# Clean text format with policy separators
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -OutputFormat TEXT -OutputFile "policies.txt"

# JSON for API integration
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -OutputFormat JSON -OutputFile "policies.json"
```

### Performance Optimization
```powershell
# Enable parallel processing
.\FortiAnalyzer-Parser.ps1 -LogFilePath "large-file.log" -UseParallel -MaxThreads 8

# Full-featured analysis (recommended for production)
.\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic.log" -ShowProgress -DebugMode -OutputFormat HTML -UseParallel
```

## 📊 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `LogFilePath` | String | ✅ | - | Path to FortiAnalyzer log file |
| `OutputFile` | String | ❌ | "NetworkTraffic.csv" | Output file name |
| `OutputFormat` | String | ❌ | "CSV" | Output format (CSV, JSON, HTML, TEXT) |
| `ShowProgress` | Switch | ❌ | False | Display progress bar during processing |
| `DebugMode` | Switch | ❌ | False | Enable detailed logging and debugging |
| `UseParallel` | Switch | ❌ | False | Enable parallel processing |
| `MaxThreads` | Int | ❌ | 4 | Maximum threads for parallel processing (1-16) |

## 📈 Output Formats

### CSV Output
Perfect for spreadsheet analysis and data manipulation:
```csv
PolicyName,IncomingInterface,OutgoingInterface,Source,Destination,Service,Action,TrafficCount
ALLOW_INTERNAL_TO_WAN1_HTTP,internal,wan1,192.168.1.0/24,10.0.0.0/24,HTTP,accept,15
DENY_WAN1_TO_INTERNAL_RDP,wan1,internal,203.0.113.0/24,192.168.1.0/24,RDP,deny,3
```

### HTML Output
Professional FortiGate-style dashboard with:
- Summary cards showing key metrics
- Color-coded status badges and device icons
- Responsive design for mobile/desktop
- Professional styling matching FortiGate interface

### TEXT Output
Clean, readable format with policy separators:
```
=== FORTIGATE LOG ANALYSIS RESULTS ===

Policy: ALLOW_INTERNAL_TO_WAN1_HTTP
Source: 192.168.1.0/24
Source Interface: internal
Destination: 10.0.0.0/24
Outgoing Interface: wan1
Services: HTTP
Action: allow
Traffic Count: 15
============================
Policy: DENY_WAN1_TO_INTERNAL_RDP
Source: 203.0.113.0/24
Source Interface: wan1
Destination: 192.168.1.0/24
Outgoing Interface: internal
Services: TCP/3389
Action: deny
Traffic Count: 3
```

### JSON Output
Structured data for API integration and programmatic processing with complete metadata.

## 🏷️ Standardized Policy Naming Convention

### Naming Format
`[ACTION]_[SOURCE_INTERFACE]_TO_[DEST_INTERFACE]_[SERVICE]`

### Examples
- `ALLOW_INTERNAL_TO_WAN1_HTTP` - Allow HTTP from internal to wan1
- `DENY_WAN1_TO_INTERNAL_RDP` - Deny RDP from wan1 to internal
- `ALLOW_DMZ_TO_WAN1_HTTPS` - Allow HTTPS from DMZ to wan1

### Field Order (Consistent Across All Formats)
1. **Policy Name** - Descriptive and unique identifier
2. **Incoming Interface** - Source interface where traffic originates
3. **Outgoing Interface** - Destination interface where traffic exits
4. **Source** - Source IP addresses/networks (CIDR notation)
5. **Destination** - Destination IP addresses/networks (CIDR notation)
6. **Service/Services** - Protocols/ports used
7. **Action** - Accept/Deny recommendation
8. **Traffic Count** - Connection frequency

### Benefits
- **Clear traffic flow representation** for easy understanding
- **Efficient firewall implementation** with ready-to-use names
- **Easier policy maintenance** and troubleshooting
- **Consistent naming** across all network devices

## 🔍 Enterprise-Grade Service Recognition

The parser includes **100+ enterprise service mappings** for professional network analysis:

### Core Internet Services
- **Web**: HTTP (80), HTTPS (443), HTTP-ALT (8080), HTTPS-ALT (8443)
- **Email**: SMTP (25), POP3 (110), IMAP (143), SMTPS (465), IMAPS (993), POP3S (995)
- **File Transfer**: FTP (21), SFTP (22), FTPS (990), TFTP (69), RSYNC (873)
- **Network**: DNS (53), DHCP (67/68), NTP (123), SNMP (161/162), SYSLOG (514)

### Enterprise Services
- **Microsoft**: RDP (3389), SMB (445), MS-RPC (135), MSSQL (1433), WinRM (5985/5986)
- **Databases**: MySQL (3306), PostgreSQL (5432), Oracle (1521), Redis (6379), MongoDB (27017)
- **Virtualization**: VMware (902/903), vCenter (443/5480), Proxmox (8006), Libvirt (16509)
- **Backup**: Veeam (9392-9398), NFS (2049), iSCSI (3260)

### Security & VPN
- **VPN**: OpenVPN (1194), PPTP (1723), IPSec (500/4500), ISAKMP (500)
- **Authentication**: RADIUS (1812/1813), LDAP (389), LDAPS (636), Kerberos (88)
- **Monitoring**: Prometheus (9090), Grafana (3000), NRPE (5666), Check_MK (6556)

### Development & Cloud
- **Containers**: Docker (2375/2376), Kubernetes (6443), Registry (5000)
- **CI/CD**: Jenkins (8080), Nexus (8081), SonarQube (9000)
- **Cloud**: Elasticsearch (9200), Kibana (5601), Consul (8500), Vault (8200)

### Communication & VoIP
- **VoIP**: SIP (5060/5061), H.323 (1720), SCCP (2000), STUN (3478)
- **Messaging**: XMPP (5222/5269), IRC (194), Teams (8443)

**Unknown services** are automatically formatted as `TCP/port` or `UDP/port` for clear identification.

## 🔍 Supported Log Format

FortiAnalyzer logs with these fields:
- `srcip=` - Source IP address
- `dstip=` - Destination IP address
- `srcport=` - Source port
- `dstport=` - Destination port
- `service=` - Service name
- `srcintf=` - Source interface
- `dstintf=` - Destination interface
- `action=` - Traffic action
- `proto=` - Protocol number

## 🎯 Use Cases

### Network Security
- **Security audits** - Identify unauthorized traffic patterns
- **Compliance reporting** - Document network communications
- **Incident response** - Analyze traffic during security events
- **Policy optimization** - Streamline existing firewall rules

### Network Planning
- **Capacity planning** - Understand traffic volumes and patterns
- **Network segmentation** - Identify communication requirements
- **Service mapping** - Document application dependencies
- **Infrastructure changes** - Plan network modifications

### Operational Efficiency
- **Automated policy generation** - Reduce manual firewall configuration
- **Documentation** - Maintain current network communication maps
- **Troubleshooting** - Quickly identify communication issues
- **Change management** - Track network traffic evolution

## 🚀 Performance Features

### Smart Processing
- **Subnet consolidation** - Groups individual IPs into networks
- **Service translation** - Converts ports to service names
- **Memory optimization** - Handles large files efficiently
- **Parallel processing** - Multi-threaded analysis for speed

### Reliability
- **Error recovery** - Continues processing despite malformed entries
- **Input validation** - Catches issues before processing
- **Progress tracking** - Real-time status updates
- **Detailed logging** - Comprehensive debugging information

## 📝 Example Analysis

```powershell
PS> .\FortiAnalyzer-Parser.ps1 -LogFilePath "traffic-2024.log" -ShowProgress -OutputFormat HTML

=== FortiAnalyzer Log Parser v2.4 ===
Enhanced with comprehensive service recognition and FortiGate policy generation

[2024-01-15 10:30:45] Starting log file parsing: traffic-2024.log
[2024-01-15 10:30:47] Parsing completed successfully
[2024-01-15 10:30:47] Processing time: 2.3 seconds
[2024-01-15 10:30:47] Lines processed: 50,000
[2024-01-15 10:30:47] Connections parsed: 15,000
[2024-01-15 10:30:47] Unique patterns found: 250

=== Analysis Results ===
Total Policies Required: 250
Top Services: HTTP (45%), HTTPS (30%), DNS (15%), RDP (10%)
Network Segments: 12 unique subnets identified
Results exported to: firewall-report.html
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🐛 Issues & Support

If something's not working:
1. Check the [Issues](https://github.com/diyarit/fortianalyzer-parser/issues) page
2. Create a new issue with sample log lines (remove sensitive data)
3. Include error messages and system information

## 🔄 Version History

### v2.4.0 - Comprehensive Service Recognition (Latest)
- **🔍 100+ service mappings** - Enterprise-grade service identification
- **🎯 Smart service detection** - Automatic port-to-service translation
- **🏢 Enterprise services** - Microsoft, databases, virtualization, cloud
- **🔒 Security services** - VPN, authentication, monitoring tools
- **💻 Development tools** - Docker, Kubernetes, CI/CD platforms
- **📞 Communication** - VoIP, messaging, collaboration tools
- **⚡ Enhanced performance** - Optimized service lookup and formatting

### v2.3.0 - FortiGate Policy Generation
- **🎯 Standardized policy naming** with FortiGate conventions
- **📝 Clean TEXT output** with policy separators
- **🎨 Enhanced HTML reports** with FortiGate-style interface
- **🔄 Improved field ordering** across all output formats
- **⚡ Smart service formatting** (TCP/port, UDP/port)
- **🏷️ Action standardization** (accept → allow, deny → deny)

### v2.2.0 - Multi-Format Support
- **📊 Multiple output formats** - CSV, JSON, HTML, TEXT
- **⚡ Parallel processing** - Multi-threaded analysis
- **📱 Responsive HTML reports** - Mobile-friendly interface
- **🔄 Graceful fallback** - Auto-switches processing modes

### v2.1.0 - Performance & Reliability
- **🚀 3-5x faster processing** with pre-compiled regex
- **🛡️ Comprehensive error handling** - Won't crash on bad data
- **✅ Input validation** - Catches problems early
- **📊 Memory monitoring** - Tracks and optimizes usage
- **🔍 Debug mode** - Detailed logging and diagnostics
- **💪 Robust recovery** - Continues despite individual failures

### v1.x.x - Foundation
- Initial release with core parsing functionality
- Progress tracking and memory optimization
- Subnet consolidation and service mapping

---

**Built by someone who got tired of manually parsing FortiAnalyzer logs. Hope it saves you time too! 🚀**