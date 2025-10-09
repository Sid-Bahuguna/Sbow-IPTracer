# IP Finder - Advanced IP Discovery Tool for Security Research

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-Research%20Only-red.svg)

A production-ready, comprehensive IP address discovery tool designed for authorized security testing, penetration testing, bug bounty research, and defensive security operations.

---

## ⚠️ LEGAL & ETHICAL NOTICE


**You MUST have explicit written permission** to scan any target domain, organization, or infrastructure.
**When in doubt, get written permission first.**

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [Data Sources](#-data-sources)
- [Output Formats](#-output-formats)
- [Performance Tuning](#-performance-tuning)
- [Changelog](#-changelog)

---

## 🚀 Features

### Comprehensive Data Collection

- **Certificate Transparency Logs**: Queries crt.sh for SSL/TLS certificates
- **Premium Security APIs**: Integrates with Censys, Shodan, ZoomEye, VirusTotal
- **Passive DNS**: Historical DNS resolution data from multiple providers
- **Active DNS Resolution**: A, AAAA, CNAME, MX, NS record lookups
- **Reverse DNS**: PTR record enumeration for discovered IPs
- **ASN & Netblock Intelligence**: Team Cymru IP-to-ASN mapping
- **Service Detection**: Open port and service enumeration (where available)
- **GeoIP Enrichment**: Country and location data for discovered IPs

### Performance & Reliability

- ⚡ **Async I/O Architecture**: Concurrent API queries with configurable limits
- 🔄 **Intelligent Retry Logic**: Exponential backoff with jitter for rate limits
- 💾 **Smart Caching**: File-based HTTP cache with configurable TTL (24hr default)
- 🛡️ **Error Resilience**: Graceful handling of API failures and network issues
- 📊 **Progress Tracking**: Real-time progress indicators and logging

### Output & Reporting

- 📄 **JSON Export**: Structured data with full metadata
- 📊 **CSV Export**: Spreadsheet-compatible format
- 🔍 **Deduplication**: Automatic merging of results from multiple sources
- 📝 **Source Attribution**: Track which sources discovered each IP
- 🕐 **Timestamps**: First-seen timestamps for all discoveries
- 📋 **Rich Metadata**: ASN, netblock, country, PTR, ports, notes

### User Experience

- 🎯 **Multiple Input Methods**: Single domain, organization name, or file of subdomains
- 🔧 **Flexible Configuration**: Environment variables, .env file, or YAML config
- 📢 **Verbose Logging**: Debug mode with detailed operation logs
- 🎚️ **Source Filtering**: Limit to specific data sources
- 🧪 **Dry Run Mode**: Test without making actual API calls
- ✅ **Pre-flight Checks**: Verify API key configuration before scanning

---

## 🔍 How It Works

```
┌─────────────┐
│   Target    │ (example.com, org name, or subdomain list)
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│          IP Finder Discovery Engine                 │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  crt.sh  │  │ Censys   │  │ Shodan   │  ...    │
│  │  CT Logs │  │   API    │  │   API    │         │
│  └─────┬────┘  └────┬─────┘  └────┬─────┘         │
│        │            │             │                │
│        └────────────┴─────────────┘                │
│                     │                              │
│         ┌───────────▼──────────┐                   │
│         │  Result Aggregator   │                   │
│         │   (Deduplication)    │                   │
│         └───────────┬──────────┘                   │
│                     │                              │
│         ┌───────────▼──────────┐                   │
│         │  Enrichment Layer    │                   │
│         │  - PTR Lookups       │                   │
│         │  - ASN Resolution    │                   │
│         │  - GeoIP Data        │                   │
│         └───────────┬──────────┘                   │
└─────────────────────┼──────────────────────────────┘
                      │
                      ▼
              ┌───────────────┐
              │  JSON / CSV   │
              │    Output     │
              └───────────────┘
```

**Discovery Process:**

1. **Input Processing**: Parse target domain(s) or subdomain list
2. **Parallel Collection**: Query all configured data sources concurrently
3. **DNS Resolution**: Resolve discovered domains to IP addresses
4. **Deduplication**: Merge results and track source attribution
5. **Enrichment**: Add PTR records, ASN info, and geolocation
6. **Filtering**: Remove private/reserved IP addresses
7. **Export**: Generate JSON or CSV output with complete metadata

---

## 📦 Installation

### Prerequisites

- **Python 3.10 or higher**
- **pip** (Python package manager)
- Internet connection
- (Optional) API keys for premium data sources

### Step 1: Download the Tool

```bash
# Create project directory
mkdir ip_finder_project
cd ip_finder_project
git clone https://github.com/Sidharth-bahuguna/IP-Finder

# Download the script and requirements
# (Copy ip_finder.py and requirements.txt to this directory)
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Check version
python ip_finder.py --version

# View help
python ip_finder.py --help

# Check source configuration
python ip_finder.py --sources-only
```

---

## 🎯 Quick Start

### Example 1: Basic Scan (No API Keys Required)

Uses free sources: crt.sh and DNS resolution

```bash
python ip_finder.py --target example.com
```

**Output**: Results displayed in a table on screen, no file saved

### Example 2: Scan with API Keys

```bash
# Set API keys
export SHODAN_API_KEY="your_shodan_key_here"
export VT_API_KEY="your_virustotal_key_here"

# Run scan
python ip_finder.py --target example.com --verbose
```

### Example 3: Save Results to File

```bash
# JSON format (detailed metadata)
python ip_finder.py --target example.com --output results.json

# CSV format (spreadsheet-compatible)
python ip_finder.py --target example.com --output results.csv --format csv

# TXT format (IP addresses only, one per line)
python ip_finder.py --target example.com --output ips.txt --format txt
```

### Example 4: Scan Multiple Domains

Create `targets.txt`:
```
example.com
www.example.com
api.example.com
mail.example.com
```

Run scan:
```bash
# Display results on screen
python ip_finder.py --target-file targets.txt

# Or save to file
python ip_finder.py --target-file targets.txt --output multi_scan.json
```

### Example 5: Check Configuration

```bash
# See which sources are configured
python ip_finder.py --sources-only
```

---

## ⚙️ Configuration

### Method 1: Environment Variables (Recommended)

```bash
# Export directly in terminal (temporary)
export SHODAN_API_KEY="your_key_here"
export CENSYS_API_TOKEN="your-token-here"
export VT_API_KEY="your_virustotal_key"
export ZOOMEYE_API_KEY="your_zoomeye_key"
export FOFA_EMAIL="your_email@example.com"
export FOFA_KEY="your_fofa_key"
export BINARYEDGE_API_KEY="your_binaryedge_key"
export SECURITYTRAILS_API_KEY="your_securitytrails_key"

# Run script
python ip_finder.py --target example.com
```
### Method 2: .env File (Recommended for Persistence)

Create `.env` file in the same directory as `ip_finder.py`:

```bash
# .env file
SHODAN_API_KEY=abc123xyz789
CENSYS_API_TOKEN=your-token-here
VT_API_KEY=your-virustotal-api-key
ZOOMEYE_API_KEY=your-zoomeye-key
FOFA_EMAIL=yourname@example.com
FOFA_KEY=your-fofa-key
BINARYEDGE_API_KEY=your-binaryedge-key
SECURITYTRAILS_API_KEY=your-securitytrails-key

# Run script
python ip_finder.py --target example.com
```
---

## 📚 Usage Examples

### Basic Usage

```bash
# Scan and display results on screen
python ip_finder.py --target example.com

# Scan with verbose logging
python ip_finder.py --target example.com --verbose

# Scan and save to file
python ip_finder.py --target example.com --output results.json

# Quiet mode (show results table only, no progress messages)
python ip_finder.py --target example.com --quiet
```

### Advanced Scanning

```bash
# High-speed scan with increased concurrency
python ip_finder.py --target example.com --max-concurrency 50

# Save results in different formats
python ip_finder.py --target example.com --output results.json --format json
python ip_finder.py --target example.com --output results.csv --format csv
python ip_finder.py --target example.com --output ips.txt --format txt

# Scan with custom output location
python ip_finder.py --target example.com --output /path/to/results.json
```

### Bulk Scanning

```bash
# Scan from subdomain enumeration results
python ip_finder.py \
  --target-file subdomains.txt \
  --output bulk_results.json \
  --max-concurrency 20 \
  --verbose
```

### Testing & Debugging

```bash
# Dry run (mock data, no API calls)
python ip_finder.py --target test.com --dry-run

# Verbose debugging with logging
python ip_finder.py --target example.com --verbose

# Check what will be scanned without running
python ip_finder.py --sources-only
```
---

## 🌐 Data Sources

### Always Available (No API Key Required)

| Source | Description | Data Provided |
|--------|-------------|---------------|
| **crt.sh** | Certificate Transparency logs | Subdomains from SSL certs, resolved to IPs |
| **DNS Resolution** | Standard DNS queries | A, AAAA, MX, NS records |
| **PTR Lookups** | Reverse DNS | Hostnames for discovered IPs |
| **Team Cymru** | IP to ASN mapping | ASN numbers and netblocks |

### Premium Sources (API Key Required)

| Source | Free Tier | Data Provided | Rate Limits |
|--------|-----------|---------------|-------------|
| **Shodan** | ✅ 100 results/month | IPs, ports, services, banners | 1 req/sec |
| **Censys** | ✅ 250 queries/month | IPs from certificates, services | API-dependent |
| **VirusTotal** | ✅ 4 req/min | Passive DNS, historical A records | 4 req/min |
| **SecurityTrails** | ✅ 50 queries/month | Passive DNS, subdomains | 1 req/sec |
| **ZoomEye** | ✅ Limited | IPs, services, fingerprints | API-dependent |
| **BinaryEdge** | ✅ Limited | Subdomains, host discovery | API-dependent |
| **FOFA** | ❌ Paid only | IPs, ports, services | Paid tiers vary |

### Future/Placeholder Sources

| Source | Status | Notes |
|--------|--------|-------|
| **BGP.he.net** | Placeholder | Scraping-based; requires `--enable-scrape` |
| **RDAP/WHOIS** | Placeholder | Netblock enumeration by org name |

---

## 📊 Output Formats

### Console Output (Default - Always Shown)

When you run the tool, results are displayed in a formatted table on your screen:

```
====================================================================================================
IP ADDRESS                               SOURCES                        ASN            COUNTRY
====================================================================================================
93.184.216.34                            crt.sh, dns, shodan            AS15133        US
2606:2800:220:1:248:1893:25c8:1946      dns                            AS15133        US
====================================================================================================

Total IPs discovered: 2

IPs by source:
  dns                  2 IPs
  crt.sh               1 IPs
  shodan               1 IPs
```

**Note**: This output is shown regardless of whether you save to a file. Use `--quiet` to suppress progress messages but still show the results table.

### JSON Format (File Output)

**File**: `ip_results.json`

```json
[
  {
    "ip": "93.184.216.34",
    "sources": [
      "crt.sh",
      "dns",
      "shodan",
      "virustotal"
    ],
    "first_seen": "2025-10-08T14:32:15.123456",
    "asn": "AS15133",
    "netblock": "93.184.216.0/24",
    "country": "US",
    "ptr": "example.com",
    "ports": [
      80,
      443
    ],
    "notes": "A record; found in Censys certificate subjectAltName"
  },
  {
    "ip": "2606:2800:220:1:248:1893:25c8:1946",
    "sources": [
      "dns"
    ],
    "first_seen": "2025-10-08T14:32:18.456789",
    "asn": "AS15133",
    "netblock": "2606:2800:220::/48",
    "country": "US",
    "ptr": "example.com",
    "ports": [],
    "notes": "AAAA record"
  }
]
```

### CSV Format (File Output)

**Enabled with**: `--output results.csv --format csv`

**File**: `results.csv`

```csv
IP,Sources,First Seen,ASN,Netblock,Country,PTR,Ports,Notes
93.184.216.34,crt.sh;dns;shodan;virustotal,2025-10-08T14:32:15,AS15133,93.184.216.0/24,US,example.com,80;443,A record; Censys cert
2606:2800:220:1:248:1893:25c8:1946,dns,2025-10-08T14:32:18,AS15133,2606:2800:220::/48,US,example.com,,AAAA record
```

**Notes**:
- Arrays (sources, ports) are semicolon-separated
- Easy to import into Excel, Google Sheets, or databases
- Can be processed with standard CSV tools

### TXT Format (File Output)

**Enabled with**: `--output ips.txt --format txt`

**File**: `ips.txt` (one IP per line, sorted)

```
93.184.216.34
2606:2800:220:1:248:1893:25c8:1946
```

**Use cases**:
- Feed to other security tools (nmap, masscan, etc.)
- Simple IP lists for firewalls/blocklists
- Quick copy-paste into other applications

---

## ⚡ Performance Tuning

### Concurrency Settings

**Default**: 10 concurrent requests

**Low Rate Limits** (API errors):
```bash
python ip_finder.py --target example.com --max-concurrency 5
```

**High-Speed Scanning** (stable network + generous API limits):
```bash
python ip_finder.py --target example.com --max-concurrency 50
```

### Caching

**Cache Location**: `.cache/` directory (auto-created)

**Cache TTL**: 24 hours (hardcoded in script)

**Benefits**:
- Avoid redundant API calls during development/testing
- Faster re-runs for same targets
- Preserve API quota

**Clear Cache**:
```bash
rm -rf .cache/
```

**Disable Cache** (modify script):
```python
# In RateLimitedClient.get() method, comment out cache check
# if cache_key:
#     cached_data = get_cached(cache_key)
#     if cached_data is not None:
#         return cached_data
```

### Logging

**Log File**: `ip_finder.log` (auto-created)

**Log Levels**:
- `--verbose`: DEBUG level (all operations)
- Default: INFO level (progress and warnings)
- `--quiet`: WARNING level (errors only)

**Monitor Progress**:
```bash
# Run in background
python ip_finder.py --target example.com &

# Tail log file
tail -f ip_finder.log
```
---

## 📜 Changelog

### Version 1.0.0 (2025-10-08)

**Initial Release**

✅ **Features**:
- 10 data source collectors (crt.sh, Censys, Shodan, VirusTotal, ZoomEye, FOFA, BinaryEdge, SecurityTrails, DNS, Team Cymru)
- JSON and CSV export formats
- File-based caching (24hr TTL)
- Comprehensive logging
- Source filtering (`--limit-source`)
- Configuration status check (`--sources-only`)

🔧 **Configuration**:
- Environment variable support
- `.env` file support
- YAML config file support

⚠️ **Known Limitations**:
- BGP.he.net scraping not implemented (placeholder)
- RDAP/WHOIS netblock enumeration not implemented
- `--org` flag accepted but unused
- GeoIP limited to country codes from APIs
- No MaxMind GeoIP2 integration

---

## 🤝 Contributing

Contributions welcome! This is a single-file educational/research tool.

**How to contribute**:

1. **Report bugs**: Open issue with reproduction steps
2. **Suggest features**: Open issue with use case

---

## 📄 License

**For defensive security research and authorized testing only.**

This tool is provided as-is for educational and authorized security research purposes. Users are solely responsible for compliance with applicable laws and regulations.

**NO WARRANTY**: The authors provide no warranty and assume no liability for damages resulting from use or misuse of this tool.

**Third-party APIs**: Use of data sources (Shodan, Censys, etc.) is subject to their respective terms of service. Users must comply with all API provider terms.

---

**Created**: 2025-10-08
**Version**: 1.0.0
**Author**: Sidharth Bahuguna
**Purpose**: Authorized security testing and reconnaissance

---