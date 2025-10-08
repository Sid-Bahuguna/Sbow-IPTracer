# IP Finder - Advanced IP Discovery Tool for Security Research

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-Research%20Only-red.svg)

A production-ready, comprehensive IP address discovery tool designed for authorized security testing, penetration testing, bug bounty research, and defensive security operations.

---

## ⚠️ LEGAL & ETHICAL NOTICE

**READ THIS BEFORE USING THE TOOL**

This tool is designed **exclusively** for:
- Authorized security testing and penetration testing
- Defensive security research and threat intelligence
- Bug bounty programs with proper scope authorization
- Network inventory for systems you own or have permission to scan
- Educational purposes in controlled lab environments

**You MUST have explicit written permission** to scan any target domain, organization, or infrastructure.

**Unauthorized use may violate:**
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- EU Cybersecurity Directive (NIS2)
- Terms of Service of data providers
- Other local, national, and international laws

**By using this tool, you agree that:**
- You have proper authorization for all targets
- You will comply with all applicable laws and regulations
- You accept full responsibility for your actions
- The authors assume NO liability for misuse

**When in doubt, get written permission first.**

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [Command-Line Options](#-command-line-options)
- [Data Sources](#-data-sources)
- [API Key Setup](#-api-key-setup)
- [Output Formats](#-output-formats)
- [Performance Tuning](#-performance-tuning)
- [Troubleshooting](#-troubleshooting)
- [Advanced Usage](#-advanced-usage)
- [Architecture](#-architecture)
- [FAQ](#-faq)
- [Contributing](#-contributing)
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

**Sample Output**:
```
=== Data Sources Status ===

crt.sh               ✓ CONFIGURED         (Always available)
DNS                  ✓ CONFIGURED         (Always available)
Censys               ✗ NOT CONFIGURED     (CENSYS_API_ID, CENSYS_API_SECRET)
Shodan               ✓ CONFIGURED         (SHODAN_API_KEY)
ZoomEye              ✗ NOT CONFIGURED     (ZOOMEYE_API_KEY)
VirusTotal           ✓ CONFIGURED         (VT_API_KEY)
FOFA                 ✗ NOT CONFIGURED     (FOFA_EMAIL, FOFA_KEY)
BinaryEdge           ✗ NOT CONFIGURED     (BINARYEDGE_API_KEY)
SecurityTrails       ✗ NOT CONFIGURED     (SECURITYTRAILS_API_KEY)
Team Cymru ASN       ✓ CONFIGURED         (Always available)
```

---

## ⚙️ Configuration

### Method 1: Environment Variables (Recommended)

```bash
# Export directly in terminal (temporary)
export SHODAN_API_KEY="your_key_here"
export CENSYS_API_ID="your_id_here"
export CENSYS_API_SECRET="your_secret_here"
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
CENSYS_API_ID=your-censys-id
CENSYS_API_SECRET=your-censys-secret
VT_API_KEY=your-virustotal-api-key
ZOOMEYE_API_KEY=your-zoomeye-key
FOFA_EMAIL=yourname@example.com
FOFA_KEY=your-fofa-key
BINARYEDGE_API_KEY=your-binaryedge-key
SECURITYTRAILS_API_KEY=your-securitytrails-key
```

**Security Note**: Add `.env` to `.gitignore` to prevent accidental commits!

```bash
echo ".env" >> .gitignore
```

Then run:
```bash
python ip_finder.py --target example.com
```

### Method 3: YAML Configuration File

Create `config.yml`:

```yaml
# config.yml
SHODAN_API_KEY: abc123xyz789
CENSYS_API_ID: your-censys-id
CENSYS_API_SECRET: your-censys-secret
VT_API_KEY: your-virustotal-api-key
ZOOMEYE_API_KEY: your-zoomeye-key
FOFA_EMAIL: yourname@example.com
FOFA_KEY: your-fofa-key
BINARYEDGE_API_KEY: your-binaryedge-key
SECURITYTRAILS_API_KEY: your-securitytrails-key
```

Run with config file:
```bash
python ip_finder.py --target example.com --apikey-config config.yml
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

### Source Filtering

```bash
# Use only Shodan and Censys
python ip_finder.py --target example.com \
  --limit-source shodan \
  --limit-source censys

# Use only free sources (no API keys needed)
python ip_finder.py --target example.com \
  --limit-source dns \
  --limit-source crtsh
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

**subdomains.txt format** (one domain per line):
```
www.example.com
api.example.com
mail.example.com
cdn.example.com
dev.example.com
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

### Organization-Based Discovery (Future Feature)

```bash
# Placeholder for WHOIS-based netblock discovery
python ip_finder.py --target example.com --org "Example Inc"
```

**Note**: `--org` flag is accepted but not yet implemented in v1.0. Future versions will use organization names to query RDAP/WHOIS for netblock enumeration.

---

## 🎛️ Command-Line Options

### Full Help Output

```bash
python ip_finder.py --help
```

```
usage: ip_finder.py [-h] [--target TARGET] [--org ORG]
                    [--target-file TARGET_FILE] [--output OUTPUT]
                    [--format {json,csv}] [--apikey-config APIKEY_CONFIG]
                    [--max-concurrency MAX_CONCURRENCY] [--verbose] [--quiet]
                    [--sources-only] [--limit-source LIMIT_SOURCES]
                    [--dry-run] [--enable-scrape] [--version]

IP Finder - Advanced IP Discovery Tool for Security Research

optional arguments:
  -h, --help            show this help message and exit

  --target TARGET       Target domain (e.g., example.com)

  --org ORG             Organization name (for WHOIS/RDAP queries)
                        [NOT YET IMPLEMENTED]

  --target-file TARGET_FILE
                        File containing list of domains/subdomains
                        (one per line)

  --output OUTPUT       Output file path (optional - if not specified,
                        results are only displayed on screen)

  --format {json,csv,txt}
                        Output format (default: json)
                        json: Structured JSON with all metadata
                        csv: Spreadsheet-compatible CSV
                        txt: Plain text, one IP per line

  --apikey-config APIKEY_CONFIG
                        Path to YAML config file with API keys

  --max-concurrency MAX_CONCURRENCY
                        Maximum concurrent requests (default: 10)
                        Increase for faster scans, decrease if rate limited

  --verbose, -v         Verbose output (debug logging to console)

  --quiet, -q           Minimal output (errors/warnings only)

  --sources-only        Show available sources and configuration status,
                        then exit (useful for checking API key setup)

  --limit-source LIMIT_SOURCES
                        Limit to specific sources (can be used multiple times)
                        Example: --limit-source shodan --limit-source censys

  --dry-run             Dry run with mock data (for testing, no API calls)

  --enable-scrape       Enable web scraping sources (bgp.he.net)
                        [NOT IMPLEMENTED - placeholder for future use]
                        Use responsibly and respect robots.txt

  --version             Show program version and exit

Environment Variables:
  SHODAN_API_KEY              Shodan API key
  CENSYS_API_ID               Censys API ID
  CENSYS_API_SECRET           Censys API secret
  VT_API_KEY                  VirusTotal API key
  ZOOMEYE_API_KEY             ZoomEye API key
  FOFA_EMAIL                  FOFA account email
  FOFA_KEY                    FOFA API key
  BINARYEDGE_API_KEY          BinaryEdge API key
  SECURITYTRAILS_API_KEY      SecurityTrails API key

Examples:
  ip_finder.py --target example.com --output results.json
  ip_finder.py --target example.com --org "Example Inc" --format csv
  ip_finder.py --target example.com --sources-only
  ip_finder.py --target-file subdomains.txt --max-concurrency 20

For detailed documentation, see README.md
```

### Options Reference Table

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--help` | `-h` | flag | - | Show help message and exit |
| `--target` | - | string | - | Target domain to scan |
| `--org` | - | string | - | Organization name (future use) |
| `--target-file` | - | path | - | File with domain list (one per line) |
| `--output` | - | path | None | Output file path (optional) |
| `--format` | - | choice | `json` | Output format: `json`, `csv`, or `txt` |
| `--apikey-config` | - | path | - | YAML file with API keys |
| `--max-concurrency` | - | integer | `10` | Max concurrent requests |
| `--verbose` | `-v` | flag | - | Enable debug logging |
| `--quiet` | `-q` | flag | - | Suppress info messages |
| `--sources-only` | - | flag | - | Show source status and exit |
| `--limit-source` | - | string | - | Restrict to specific sources (repeatable) |
| `--dry-run` | - | flag | - | Test mode with mock data |
| `--enable-scrape` | - | flag | - | Enable scraping (not implemented) |
| `--version` | - | flag | - | Show version and exit |

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

## 🔑 API Key Setup

### Step-by-Step Guide

#### 1. Shodan (Highly Recommended)

**Free Tier**: 100 results/month, perfect for occasional scans

1. Go to https://account.shodan.io/
2. Sign up for free account
3. Navigate to "Account" → "API Key"
4. Copy your API key
5. Set environment variable:
   ```bash
   export SHODAN_API_KEY="your_key_here"
   ```

**Verify**:
```bash
python ip_finder.py --sources-only | grep Shodan
# Should show: ✓ CONFIGURED
```

#### 2. VirusTotal (Highly Recommended)

**Free Tier**: 4 requests/minute, great for passive DNS

1. Go to https://www.virustotal.com/
2. Sign up for free account
3. Navigate to Profile → API Key
4. Copy your API key
5. Set environment variable:
   ```bash
   export VT_API_KEY="your_key_here"
   ```

#### 3. Censys (Recommended)

**Free Tier**: 250 queries/month, excellent certificate data

1. Go to https://search.censys.io/
2. Create free account
3. Navigate to Account → API
4. Generate API credentials (ID + Secret)
5. Set environment variables:
   ```bash
   export CENSYS_API_ID="your_id_here"
   export CENSYS_API_SECRET="your_secret_here"
   ```

#### 4. SecurityTrails (Recommended)

**Free Tier**: 50 API calls/month, strong passive DNS

1. Go to https://securitytrails.com/
2. Sign up for free account
3. Navigate to Account → API
4. Copy API key
5. Set environment variable:
   ```bash
   export SECURITYTRAILS_API_KEY="your_key_here"
   ```

#### 5. ZoomEye (Optional)

1. Go to https://www.zoomeye.org/
2. Register account
3. Navigate to Profile → API Key
4. Set environment variable:
   ```bash
   export ZOOMEYE_API_KEY="your_key_here"
   ```

#### 6. BinaryEdge (Optional)

1. Go to https://app.binaryedge.io/
2. Create account
3. Navigate to Account → API
4. Set environment variable:
   ```bash
   export BINARYEDGE_API_KEY="your_key_here"
   ```

#### 7. FOFA (Optional - Paid Service)

1. Go to https://fofa.info/
2. Purchase subscription
3. Get email and API key
4. Set environment variables:
   ```bash
   export FOFA_EMAIL="your_email@example.com"
   export FOFA_KEY="your_key_here"
   ```

### Recommended Starter Configuration

For best results without cost:

```bash
# Minimum recommended setup (all free)
export SHODAN_API_KEY="..."        # Best coverage
export VT_API_KEY="..."            # Best passive DNS
export CENSYS_API_ID="..."         # Best certificates
export CENSYS_API_SECRET="..."
export SECURITYTRAILS_API_KEY="..." # Additional passive DNS
```

This gives you **5 data sources** plus the 4 always-available sources (crt.sh, DNS, PTR, Team Cymru) = **9 total sources**.

### API Key Security Best Practices

✅ **DO:**
- Use `.env` file (add to `.gitignore`)
- Use environment variables
- Rotate keys periodically
- Use separate keys for different projects
- Check key permissions/scopes

❌ **DON'T:**
- Commit keys to Git repositories
- Share keys in screenshots/logs
- Use production keys for testing
- Hardcode keys in scripts
- Post keys in public forums

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

**Field Descriptions**:

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | IPv4 or IPv6 address |
| `sources` | array | List of sources that discovered this IP |
| `first_seen` | string | ISO 8601 timestamp of first discovery |
| `asn` | string | Autonomous System Number (e.g., AS15133) |
| `netblock` | string | CIDR netblock (e.g., 93.184.216.0/24) |
| `country` | string | ISO country code (e.g., US, GB, CN) |
| `ptr` | string | Reverse DNS hostname |
| `ports` | array | List of open ports (if detected) |
| `notes` | string | Additional context/metadata |

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

### Parsing Output

#### Python Example

```python
import json

# Load JSON results
with open('ip_results.json', 'r') as f:
    results = json.load(f)

# Filter IPs from specific ASN
for ip_data in results:
    if ip_data['asn'] == 'AS15133':
        print(f"{ip_data['ip']} - {ip_data['ptr']}")

# Get all IPs found by Shodan
shodan_ips = [
    ip_data['ip']
    for ip_data in results
    if 'shodan' in ip_data['sources']
]
print(f"Shodan found: {len(shodan_ips)} IPs")
```

#### Bash/jq Example

```bash
# Extract just IP addresses
jq -r '.[].ip' ip_results.json

# Filter by country
jq -r '.[] | select(.country == "US") | .ip' ip_results.json

# Get IPs with open ports
jq -r '.[] | select(.ports | length > 0) | .ip' ip_results.json

# Count IPs by source
jq -r '.[].sources[]' ip_results.json | sort | uniq -c
```

#### CSV Processing (Excel)

1. Open CSV in Excel/Google Sheets
2. Use "Text to Columns" for semicolon-separated fields
3. Apply filters to columns
4. Create pivot tables for source analysis

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

**Guidelines**:
- Start with default (10)
- Increase if no rate limit errors
- Decrease if seeing HTTP 429 errors
- Free API tiers: 5-10 recommended
- Paid API tiers: 20-50 possible

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

### Resource Usage

**Memory**: ~50-200 MB (depends on result count)

**Network**: Varies by sources enabled
- Typical scan: 100-500 KB
- Large target: 1-10 MB

**Disk Space**:
- Cache: 1-50 MB (grows over time)
- Log file: 1-10 MB per run

---

## 🔧 Troubleshooting

### Common Issues

#### Issue: "No targets specified"

**Error**:
```
ERROR: No targets specified. Use --target or --target-file
```

**Solution**:
```bash
# Provide target domain
python ip_finder.py --target example.com

# Or provide file
python ip_finder.py --target-file domains.txt
```

---

#### Issue: "Skipping unconfigured sources"

**Warning**:
```
WARNING: Skipping unconfigured sources: Censys, Shodan, VirusTotal
```

**Solution**:
```bash
# Check configuration status
python ip_finder.py --sources-only

# Add missing API keys to .env or environment
export SHODAN_API_KEY="your_key"
export VT_API_KEY="your_key"
```

**Note**: This is not an error; tool will still work with available sources.

---

#### Issue: Rate Limit Errors (HTTP 429)

**Error in log**:
```
WARNING: Rate limited on https://api.shodan.io/..., waiting...
```

**Solutions**:

1. **Reduce concurrency**:
   ```bash
   python ip_finder.py --target example.com --max-concurrency 5
   ```

2. **Wait and retry**: Script auto-retries with backoff

3. **Check API tier limits**: Free tiers have strict limits

4. **Use fewer sources**:
   ```bash
   python ip_finder.py --target example.com --limit-source dns --limit-source crtsh
   ```

---

#### Issue: "Auth failed for ..." (HTTP 401/403)

**Error**:
```
WARNING: Auth failed for https://api.censys.io/...: 401
```

**Solutions**:

1. **Verify API key**:
   ```bash
   echo $SHODAN_API_KEY
   # Should show your key
   ```

2. **Check key format**:
   - Shodan: Single key string
   - Censys: Needs both ID and SECRET
   - FOFA: Needs both EMAIL and KEY

3. **Regenerate key**: Key may be invalid/expired

4. **Check account status**: Ensure account is active

---

#### Issue: DNS Resolution Failures

**Symptom**: No IPs found for known-good domains

**Solutions**:

1. **Check network**:
   ```bash
   ping 8.8.8.8
   nslookup example.com
   ```

2. **Use custom DNS resolver** (modify script):
   ```python
   resolver = dns.resolver.Resolver()
   resolver.nameservers = ['8.8.8.8', '1.1.1.1']
   ```

3. **Firewall blocking DNS**: Check firewall rules

---

#### Issue: "No IP addresses discovered"

**Possible Causes**:

1. **Target has no public infrastructure**
2. **All IPs are private** (filtered out automatically)
3. **API keys not configured**
4. **Network connectivity issues**

**Solutions**:

1. **Use verbose mode**:
   ```bash
   python ip_finder.py --target example.com --verbose
   ```

2. **Check logs**:
   ```bash
   grep ERROR ip_finder.log
   ```

3. **Try known-good target**:
   ```bash
   python ip_finder.py --target google.com --dry-run
   ```

---

#### Issue: Slow Performance

**Solutions**:

1. **Increase concurrency**:
   ```bash
   python ip_finder.py --target example.com --max-concurrency 20
   ```

2. **Limit sources**:
   ```bash
   python ip_finder.py --target example.com \
     --limit-source shodan \
     --limit-source censys
   ```

3. **Check cache**:
   - Cache may be disabled
   - Clear stale cache: `rm -rf .cache/`

4. **Network latency**: Use faster DNS resolver

---

### Debug Mode

**Enable maximum verbosity**:

```bash
python ip_finder.py --target example.com --verbose 2>&1 | tee debug.log
```

This captures:
- All HTTP requests
- API responses
- DNS queries
- Cache hits/misses
- Errors with stack traces

**Analyze logs**:
```bash
# Find all errors
grep -i error debug.log

# Find rate limits
grep -i "rate limit" debug.log

# Find successful discoveries
grep -i "found" debug.log
```

---

### Getting Help

1. **Check logs**: `ip_finder.log` contains detailed operation info
2. **Use verbose mode**: `--verbose` shows real-time debugging
3. **Verify configuration**: `--sources-only` checks API key setup
4. **Test with dry run**: `--dry-run` tests without API calls
5. **Check API provider status**: APIs may have outages

---

## 🎓 Advanced Usage

### Integrating with Other Tools

#### Example 1: Pipe to Nmap

```bash
# Extract IPs and scan ports
jq -r '.[].ip' ip_results.json | sudo nmap -iL - -p- -oA nmap_scan
```

#### Example 2: Feed to Subfinder

```bash
# Discover subdomains first
subfinder -d example.com -o subdomains.txt

# Then find IPs
python ip_finder.py --target-file subdomains.txt --output ips.json
```

#### Example 3: ASN Enumeration

```bash
# Get all unique ASNs
jq -r '.[].asn' ip_results.json | sort -u

# Filter by specific ASN
jq '.[] | select(.asn == "AS15133")' ip_results.json
```

#### Example 4: GeoIP Analysis

```bash
# Count IPs by country
jq -r '.[].country' ip_results.json | sort | uniq -c | sort -rn

# Filter US-only IPs
jq '.[] | select(.country == "US")' ip_results.json
```

### Automation Scripts

#### Bash Wrapper for Multiple Targets

```bash
#!/bin/bash
# bulk_scan.sh

TARGETS_FILE="$1"
OUTPUT_DIR="results"

mkdir -p "$OUTPUT_DIR"

while IFS= read -r domain; do
    echo "[+] Scanning $domain..."
    python ip_finder.py \
        --target "$domain" \
        --output "$OUTPUT_DIR/${domain}.json" \
        --quiet
done < "$TARGETS_FILE"

echo "[+] Merging results..."
jq -s 'add' "$OUTPUT_DIR"/*.json > "$OUTPUT_DIR/all_results.json"
```

Usage:
```bash
chmod +x bulk_scan.sh
./bulk_scan.sh domains.txt
```

#### Python Automation Script

```python
#!/usr/bin/env python3
import subprocess
import json
from pathlib import Path

targets = ["example.com", "example.org", "example.net"]
output_dir = Path("results")
output_dir.mkdir(exist_ok=True)

all_results = []

for target in targets:
    print(f"[+] Scanning {target}...")
    output_file = output_dir / f"{target}.json"

    subprocess.run([
        "python", "ip_finder.py",
        "--target", target,
        "--output", str(output_file),
        "--quiet"
    ])

    with open(output_file) as f:
        results = json.load(f)
        all_results.extend(results)

# Deduplicate and save
unique_ips = {r['ip']: r for r in all_results}
with open(output_dir / "merged.json", "w") as f:
    json.dump(list(unique_ips.values()), f, indent=2)

print(f"[+] Total unique IPs: {len(unique_ips)}")
```

### Continuous Monitoring

#### Cron Job for Daily Scans

```bash
# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * cd /path/to/ip_finder && python ip_finder.py --target example.com --output daily_$(date +\%Y\%m\%d).json >> cron.log 2>&1
```

#### Diff Detection Script

```bash
#!/bin/bash
# detect_changes.sh

PREVIOUS="results/previous.json"
CURRENT="results/current.json"

python ip_finder.py --target example.com --output "$CURRENT"

if [ -f "$PREVIOUS" ]; then
    # Extract IPs and find new ones
    comm -13 \
        <(jq -r '.[].ip' "$PREVIOUS" | sort) \
        <(jq -r '.[].ip' "$CURRENT" | sort) \
        > new_ips.txt

    if [ -s new_ips.txt ]; then
        echo "[!] New IPs detected:"
        cat new_ips.txt
        # Send alert email/Slack notification here
    fi
fi

cp "$CURRENT" "$PREVIOUS"
```

---

## 🏗️ Architecture

### Code Structure

```
ip_finder.py
├── Configuration & Constants
│   ├── API_CONFIGS: Endpoint URLs
│   └── Environment variable names
│
├── Utilities
│   ├── setup_logging()
│   ├── load_config()
│   ├── Cache management (get_cached, set_cache)
│   └── IP validation helpers
│
├── RateLimitedClient (HTTP Client)
│   ├── Async aiohttp session
│   ├── Semaphore-based concurrency
│   ├── Retry logic with exponential backoff
│   └── Integrated caching
│
├── IPResult (Data Model)
│   ├── IP metadata storage
│   └── Merge logic for deduplication
│
├── Collectors (Data Sources)
│   ├── CrtShCollector
│   ├── CensysCollector
│   ├── ShodanCollector
│   ├── ZoomEyeCollector
│   ├── VirusTotalCollector
│   ├── FOFACollector
│   ├── BinaryEdgeCollector
│   ├── SecurityTrailsCollector
│   ├── DNSCollector
│   ├── PTRCollector
│   └── ASNCollector
│
├── IPFinder (Orchestrator)
│   ├── discover(): Main entry point
│   ├── _collect_with_progress()
│   ├── _merge_result()
│   └── _enrich_results()
│
├── Output Handlers
│   ├── export_json()
│   └── export_csv()
│
└── CLI & Main
    ├── parse_args()
    ├── main_async()
    └── main()
```

### Data Flow

```
User Input (CLI)
    ↓
Configuration Loading (.env / YAML / env vars)
    ↓
IPFinder.discover()
    ↓
┌─────────────────────────────────────┐
│  Parallel Collector Execution       │
│  (async gather with concurrency)    │
│                                     │
│  ┌──────────────┐  ┌─────────────┐ │
│  │ CrtSh        │  │ Shodan      │ │
│  │ - Query API  │  │ - Query API │ │
│  │ - Resolve    │  │ - Parse     │ │
│  │   domains    │  │   results   │ │
│  └──────┬───────┘  └──────┬──────┘ │
│         │                 │        │
│         └────────┬────────┘        │
│                  ▼                 │
│          IPResult objects          │
└─────────────────┬───────────────────┘
                  ▼
        Result Aggregation
        (deduplication by IP)
                  ▼
        Enrichment Phase
        (PTR, ASN lookups)
                  ▼
        Filter Private IPs
                  ▼
        Export (JSON/CSV)
                  ▼
        User Output
```

### Async Execution Model

```python
# Simplified pseudocode

async def discover(targets):
    collectors = [Shodan(), Censys(), DNS(), ...]
    tasks = []

    # Create task for each collector × target combination
    for target in targets:
        for collector in collectors:
            tasks.append(collector.collect(target))

    # Execute all tasks concurrently (respecting semaphore limit)
    results = await asyncio.gather(*tasks)

    # Merge and deduplicate
    merged = {}
    for result_list in results:
        for ip_result in result_list:
            if ip_result.ip in merged:
                merged[ip_result.ip].merge(ip_result)
            else:
                merged[ip_result.ip] = ip_result

    # Enrich
    await enrich(merged)

    return merged
```

### Adding New Collectors

To add a new data source:

1. **Create collector class**:

```python
class MyNewCollector(IPCollector):
    def is_configured(self) -> bool:
        return "MYNEW_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        api_key = self.config["MYNEW_API_KEY"]
        url = f"https://api.mynew.com/search?q={target}"
        headers = {"Authorization": f"Bearer {api_key}"}

        data = await self.client.get(url, headers=headers)
        if not data:
            return results

        for item in data.get("results", []):
            ip = item.get("ip")
            if ip and is_valid_ip(ip):
                result = IPResult(ip, "mynew")
                result.ports = item.get("ports", [])
                results.append(result)

        return results
```

2. **Register in IPFinder**:

```python
# In IPFinder.discover() method
collectors = [
    CrtShCollector(...),
    # ... existing collectors ...
    MyNewCollector(client, self.config, self.logger),  # Add here
]
```

3. **Update documentation**: Add to README and `--sources-only` output

---

## ❓ FAQ

### General Questions

**Q: Do I need API keys to use this tool?**

A: No. The tool works with crt.sh and DNS resolution (no keys required). API keys unlock additional data sources for better coverage.

---

**Q: Is this tool legal to use?**

A: Yes, *if* you have authorization to scan your targets. Always get written permission before scanning domains you don't own. Unauthorized scanning may violate laws.

---

**Q: Will this tool perform active scanning (port scanning, vulnerability testing)?**

A: No. IP Finder only performs passive reconnaissance using public APIs and DNS queries. It does not send packets directly to target infrastructure (except DNS queries).

---

**Q: How is this different from subdomain enumeration tools?**

A: Subdomain tools (like Subfinder) find domain names. IP Finder focuses on discovering IP addresses from multiple sources, including historical/passive DNS data.

---

### Technical Questions

**Q: Why am I seeing private IPs in the logs but not in results?**

A: Private IPs (10.x.x.x, 192.168.x.x, 127.x.x.x, etc.) are automatically filtered from final output. They're shown in debug logs but excluded from exports.

---

**Q: Can I scan IPv6 addresses?**

A: Yes. The tool discovers both IPv4 and IPv6 addresses via AAAA records and API sources that support IPv6.

---

**Q: How accurate is the ASN/netblock data?**

A: ASN data comes from Team Cymru's public whois service, which is generally accurate but may lag behind recent IP allocations by a few days.

---

**Q: What's the difference between passive DNS sources?**

A:
- **VirusTotal**: Large database, includes malware-related domains
- **SecurityTrails**: Historical DNS with longer retention
- **Censys**: Certificate-based discovery (subjectAltName fields)

---

**Q: Why do some IPs have empty PTR records?**

A: Not all IPs have reverse DNS (PTR) configured. This is normal, especially for cloud infrastructure and CDNs.

---

**Q: Can I use this behind a corporate proxy?**

A: Modify the script to add proxy support:

```python
# In RateLimitedClient.__aenter__()
connector = aiohttp.TCPConnector()
self.session = aiohttp.ClientSession(
    timeout=timeout,
    headers={"User-Agent": USER_AGENT},
    connector=connector,
    trust_env=True  # Use HTTP_PROXY/HTTPS_PROXY env vars
)
```

Then set proxy:
```bash
export HTTP_PROXY=http://proxy.corp.com:8080
export HTTPS_PROXY=http://proxy.corp.com:8080
python ip_finder.py --target example.com
```

---

### API Questions

**Q: I'm getting rate limited. What should I do?**

A:
1. Decrease `--max-concurrency` to 5 or lower
2. Wait between scans (rate limits reset hourly/daily)
3. Upgrade to paid API tier if needed
4. Use `--limit-source` to exclude rate-limited APIs

---

**Q: Which API is best for bug bounty?**

A: Recommended priority:
1. **Shodan** (good coverage, identifies services)
2. **Censys** (excellent for certificates)
3. **VirusTotal** (passive DNS history)
4. **SecurityTrails** (historical data)

---

**Q: Are API keys stored or transmitted?**

A: Keys are only stored locally (in `.env` or environment variables). They're transmitted only to their respective API providers via HTTPS. The script does not phone home or share keys.

---

### Output Questions

**Q: How do I find IPs unique to Shodan?**

A:
```bash
jq '.[] | select(.sources == ["shodan"])' ip_results.json
```

---

**Q: Can I export to other formats (XML, HTML)?**

A: Not built-in. Parse JSON output with custom scripts:

```python
import json
with open('ip_results.json') as f:
    data = json.load(f)

# Convert to your format
# ...
```

---

**Q: How do I merge results from multiple scans?**

A:
```bash
# Merge JSON files
jq -s 'add | unique_by(.ip)' scan1.json scan2.json > merged.json
```

---

### Troubleshooting Questions

**Q: Script hangs at "Enriching X IPs..."**

A: This is the PTR/ASN lookup phase. It can take time for large result sets. Be patient or interrupt (Ctrl+C) - partial results will be saved.

---

**Q: Getting "SSL certificate verify failed" errors?**

A: Some networks/proxies interfere with SSL. Quick fix (not recommended for production):

```python
# In RateLimitedClient.get()
async with self.session.get(url, ..., ssl=False) as response:
```

Better: Install/update CA certificates:
```bash
pip install --upgrade certifi
```

---

## 📜 Changelog

### Version 1.0.0 (2025-10-08)

**Initial Release**

✅ **Features**:
- 10 data source collectors (crt.sh, Censys, Shodan, VirusTotal, ZoomEye, FOFA, BinaryEdge, SecurityTrails, DNS, Team Cymru)
- Async I/O with configurable concurrency
- JSON and CSV export formats
- PTR and ASN enrichment
- File-based caching (24hr TTL)
- Retry logic with exponential backoff
- Comprehensive logging
- Source filtering (`--limit-source`)
- Dry run mode (`--dry-run`)
- Configuration status check (`--sources-only`)

🔧 **Configuration**:
- Environment variable support
- `.env` file support
- YAML config file support

📝 **Documentation**:
- Complete README with examples
- Inline code documentation
- Legal/ethical notice
- API key acquisition guide

⚠️ **Known Limitations**:
- BGP.he.net scraping not implemented (placeholder)
- RDAP/WHOIS netblock enumeration not implemented
- `--org` flag accepted but unused
- GeoIP limited to country codes from APIs
- No MaxMind GeoIP2 integration

---

### Planned Features (Future Versions)

**v1.1.0** (Planned):
- [ ] RDAP/WHOIS netblock enumeration by organization
- [ ] MaxMind GeoIP2 database support
- [ ] HTML report output
- [ ] Progress bar during collection
- [ ] Resume interrupted scans

**v1.2.0** (Planned):
- [ ] BGP.he.net scraper implementation
- [ ] AS-to-IP enumeration (small netblocks)
- [ ] Cloud provider detection (AWS, GCP, Azure IP ranges)
- [ ] Subdomain enumeration integration

**v2.0.0** (Planned):
- [ ] GUI web interface
- [ ] Database backend (SQLite/PostgreSQL)
- [ ] Multi-user support
- [ ] Scheduled/recurring scans
- [ ] Diff alerts (email/Slack)

---

## 🤝 Contributing

Contributions welcome! This is a single-file educational/research tool.

**How to contribute**:

1. **Report bugs**: Open issue with reproduction steps
2. **Suggest features**: Open issue with use case
3. **Submit PRs**:
   - Fork repo
   - Create feature branch
   - Add tests/examples
   - Update documentation
   - Submit PR

**Contribution guidelines**:
- Maintain single-file structure (where possible)
- Add docstrings for new functions
- Follow existing code style
- Update README for new features
- Test with multiple API sources

---

## 📄 License

**For defensive security research and authorized testing only.**

This tool is provided as-is for educational and authorized security research purposes. Users are solely responsible for compliance with applicable laws and regulations.

**NO WARRANTY**: The authors provide no warranty and assume no liability for damages resulting from use or misuse of this tool.

**Third-party APIs**: Use of data sources (Shodan, Censys, etc.) is subject to their respective terms of service. Users must comply with all API provider terms.

---

## 🙏 Acknowledgments

**Data Providers**:
- Certificate Transparency (crt.sh)
- Censys, Inc.
- Shodan (Binary Edge)
- VirusTotal (Google Chronicle)
- ZoomEye (Knownsec)
- FOFA
- BinaryEdge
- SecurityTrails
- Team Cymru

**Dependencies**:
- aiohttp (async HTTP client)
- dnspython (DNS toolkit)
- python-dotenv (config management)
- PyYAML (YAML parsing)
- tenacity (retry logic)
- tqdm (progress bars)

---

## 📞 Support & Contact

**Issues**: Check troubleshooting section and logs first

**Documentation**: This README + inline code comments

**Security Issues**: If you discover a security issue in the tool itself, please report responsibly.

---

## 🎯 Use Cases

### 1. Penetration Testing

**Scenario**: Authorized pentest of example.com

```bash
# Phase 1: Subdomain enumeration (external tool)
subfinder -d example.com -o subs.txt

# Phase 2: IP discovery
python ip_finder.py --target-file subs.txt --output ips.json

# Phase 3: Port scanning (external tool)
jq -r '.[].ip' ips.json | sudo nmap -iL - -oA scan_results
```

### 2. Bug Bounty Reconnaissance

**Scenario**: Scope expansion for bug bounty program

```bash
# Find all IPs for target
python ip_finder.py --target bugcrowd-target.com --verbose

# Filter by ASN (if scope is ASN-limited)
jq '.[] | select(.asn == "AS12345")' ip_results.json

# Export IP list for further testing
jq -r '.[].ip' ip_results.json > in_scope_ips.txt
```

### 3. Asset Discovery

**Scenario**: Inventory your organization's public infrastructure

```bash
# Discover IPs
python ip_finder.py --target mycompany.com --output inventory.json

# Generate CSV report for management
python ip_finder.py --target mycompany.com --format csv --output inventory.csv

# Track changes over time
diff <(jq -r '.[].ip' inventory_old.json | sort) \
     <(jq -r '.[].ip' inventory.json | sort)
```

### 4. Threat Intelligence

**Scenario**: Map infrastructure of a domain flagged in threat intel

```bash
# Discover infrastructure
python ip_finder.py --target suspicious-domain.com --output threat_intel.json

# Get ASN and netblock for blocking
jq -r '.[] | "\(.ip),\(.asn),\(.netblock)"' threat_intel.json > blocklist.csv

# Cross-reference with IOC feeds
# (use external tools)
```

### 5. Cloud Migration Audit

**Scenario**: Verify all assets migrated from on-prem to cloud

```bash
# Before migration
python ip_finder.py --target company.com --output pre_migration.json

# After migration
python ip_finder.py --target company.com --output post_migration.json

# Compare ASNs (should change from on-prem to cloud provider)
diff <(jq -r '.[].asn' pre_migration.json | sort -u) \
     <(jq -r '.[].asn' post_migration.json | sort -u)
```

---

## 📚 Further Reading

**Related Tools**:
- [Amass](https://github.com/OWASP/Amass) - Subdomain enumeration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery
- [Shodan CLI](https://cli.shodan.io/) - Shodan command-line interface
- [Censys CLI](https://github.com/censys/censys-python) - Censys Python library

**Learning Resources**:
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Reconnaissance techniques
- [Bug Bounty Bootcamp](https://nostarch.com/bug-bounty-bootcamp) - Asset discovery methods
- [Awesome Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery) - Curated resources

**API Documentation**:
- [Shodan API Docs](https://developer.shodan.io/)
- [Censys Search API](https://search.censys.io/api)
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- [SecurityTrails API](https://docs.securitytrails.com/)

---

**Created**: 2025-10-08
**Version**: 1.0.0
**Author**: Defensive Security Research
**Purpose**: Authorized security testing and reconnaissance

---

*Remember: With great power comes great responsibility. Always get permission before scanning.*