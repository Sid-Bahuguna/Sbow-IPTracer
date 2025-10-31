# IP Finder - Quick Usage Guide

## Installation

```bash
pip install -r requirements.txt
```

## Basic Usage

### 1. View Help
```bash
python RootIP-Finder.py --help
```

### 2. Check Which Sources Are Configured
```bash
python RootIP-Finder.py --sources-only
```

### 3. Simple Scan (Display Results on Screen)
```bash
python RootIP-Finder.py --target example.com
```

**Output**: Results displayed in a table on your terminal

### 4. Scan and Save to File
```bash
# Save as JSON (full details)
python RootIP-Finder.py --target example.com --output results.json

# Save as CSV (spreadsheet)
python RootIP-Finder.py --target example.com --output results.csv --format csv

# Save as TXT (IP list only)
python RootIP-Finder.py --target example.com --output ips.txt --format txt
```

### 5. Scan Multiple Domains
```bash
# Create a file with domains (one per line)
echo "example.com" > targets.txt
echo "example.org" >> targets.txt

# Scan all targets
python RootIP-Finder.py --target-file targets.txt
```

### 6. Scan with API Keys

Create `.env` file:
```bash
cp .env.example .env
# Edit .env and add your API keys
```

Then run:
```bash
python RootIP-Finder.py --target example.com --verbose
```

## Output Behavior

### Screen Output (Always Shown)
- Results are **always** displayed on screen in a formatted table
- Shows IP addresses, sources, ASN, and country
- Includes summary statistics

### File Output (Optional)
- Only saves to file if you specify `--output filename`
- Choose format with `--format` (json, csv, or txt)
- Three format options:
  - **json**: Full metadata (default)
  - **csv**: Spreadsheet-compatible
  - **txt**: Plain IP list (one per line)

## Common Commands

```bash
# Just see results, don't save
python RootIP-Finder.py --target example.com

# See results AND save to JSON
python RootIP-Finder.py --target example.com --output results.json

# See results AND save to CSV
python RootIP-Finder.py --target example.com --output results.csv --format csv

# Quiet mode (only show results table, no progress messages)
python RootIP-Finder.py --target example.com --quiet

# Verbose mode (show detailed logging)
python RootIP-Finder.py --target example.com --verbose

# Limit to specific sources
python RootIP-Finder.py --target example.com --limit-source shodan --limit-source censys

# High-speed scanning
python RootIP-Finder.py --target example.com --max-concurrency 25
```

## API Keys (Optional but Recommended)

The tool works **without** API keys using free sources:
- crt.sh (Certificate Transparency)
- DNS resolution
- Team Cymru ASN lookups

For better results, get free API keys from:

### Priority 1 (Best Free Coverage)
1. **Shodan** - https://account.shodan.io/
2. **VirusTotal** - https://www.virustotal.com/gui/my-apikey
3. **Censys** - https://search.censys.io/account/api

### Priority 2 (Additional Coverage)
4. **SecurityTrails** - https://securitytrails.com/app/account/credentials
5. **ZoomEye** - https://www.zoomeye.org/profile
6. **BinaryEdge** - https://app.binaryedge.io/account/api

### Optional (Paid)
7. **FOFA** - https://fofa.info/api

## Configuration Methods

### Method 1: Environment Variables
```bash
export SHODAN_API_KEY="abc123"
export VT_API_KEY="xyz789"
python RootIP-Finder.py --target example.com
```

### Method 2: .env File (Recommended)
```bash
# Create .env file
cat > .env << EOF
SHODAN_API_KEY=abc123
VT_API_KEY=xyz789
CENSYS_API_TOKEN=your-token
EOF

# Run tool (automatically loads .env)
python RootIP-Finder.py --target example.com
```

### Method 3: YAML Config File
```bash
# Create config.yml
cat > config.yml << EOF
SHODAN_API_KEY: abc123
VT_API_KEY: xyz789
EOF

# Run with config file
python RootIP-Finder.py --target example.com --apikey-config config.yml
```

## Integration with Other Tools

### Feed to Nmap
```bash
# Scan and save IPs to text file
python RootIP-Finder.py --target example.com --output ips.txt --format txt

# Use with nmap
sudo nmap -iL ips.txt -p- -oA scan_results
```

### Use with Masscan
```bash
python RootIP-Finder.py --target example.com --output ips.txt --format txt
sudo masscan -iL ips.txt -p0-65535 --rate 10000
```

### Extract from JSON with jq
```bash
# Get all IPs
jq -r '.[].ip' results.json

# Get IPs from specific source
jq -r '.[] | select(.sources[] | contains("shodan")) | .ip' results.json

# Get IPs by country
jq -r '.[] | select(.country == "US") | .ip' results.json

# Get IPs with open ports
jq -r '.[] | select(.ports | length > 0) | .ip' results.json
```

## Troubleshooting

### No Results Found
```bash
# Check if sources are configured
python RootIP-Finder.py --sources-only

# Try verbose mode to see what's happening
python RootIP-Finder.py --target example.com --verbose

# Try with a known-good domain
python RootIP-Finder.py --target google.com
```

### Rate Limit Errors
```bash
# Reduce concurrency
python RootIP-Finder.py --target example.com --max-concurrency 5

# Limit to fewer sources
python RootIP-Finder.py --target example.com --limit-source dns --limit-source crtsh
```

### API Authentication Errors
```bash
# Verify API keys are set
echo $SHODAN_API_KEY
echo $VT_API_KEY

# Check which sources are configured
python RootIP-Finder.py --sources-only

# Check logs for details
tail -f ip_finder.log
```

## Example Workflow

```bash
# 1. Check configuration
python RootIP-Finder.py --sources-only

# 2. Quick scan to see what's found
python RootIP-Finder.py --target example.com

# 3. If results look good, save them
python RootIP-Finder.py --target example.com --output example_ips.json

# 4. Also save as simple IP list for other tools
python RootIP-Finder.py --target example.com --output example_ips.txt --format txt

# 5. Use results with other tools
sudo nmap -iL example_ips.txt -p- -A -oA nmap_scan
```

## Tips

- **Start simple**: Run without API keys first to test
- **Add keys gradually**: Start with Shodan and VirusTotal
- **Use verbose mode**: When troubleshooting, add `--verbose`
- **Check logs**: `ip_finder.log` has detailed operation info
- **Save results**: Use `--output` to keep results for later analysis
- **Pick format wisely**:
  - JSON for complete data
  - CSV for spreadsheets
  - TXT for tool integration

## Legal Reminder

⚠️ **Always get authorization before scanning targets you don't own!**

This tool is for:
- Authorized penetration testing
- Bug bounty programs (within scope)
- Your own infrastructure
- Educational purposes in labs

Unauthorized scanning may violate laws and terms of service.
