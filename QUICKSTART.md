# IP Finder - Quick Start Guide

## 🚀 Get Started in 3 Steps

### Note: Make sure to create a Virtual Environment to install dependencies if using a linux host : Please Refer to the Virtual_Environments.txt file

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Run Your First Scan

```bash
python ip_finder.py --target example.com
```

**That's it!** Results will be displayed on your screen in a formatted table.

### Step 3 (Optional): Save Results to File

```bash
python ip_finder.py --target example.com --output results.json
```

---

## 📋 What You Need to Know

### Default Behavior

✅ **Results always displayed on screen**
- Formatted table showing IPs, sources, ASN, country
- Summary statistics
- No file created unless you specify `--output`

### Output Options

| Command | What Happens |
|---------|-------------|
| `--target example.com` | Shows results on screen only |
| `--target example.com --output file.json` | Shows results + saves JSON |
| `--target example.com --output file.csv --format csv` | Shows results + saves CSV |
| `--target example.com --output file.txt --format txt` | Shows results + saves TXT (IPs only) |

### Three Output Formats

1. **JSON** (default) - Full metadata, best for analysis
2. **CSV** - Spreadsheet-compatible, great for Excel
3. **TXT** - Plain IP list, perfect for piping to other tools

---

## 🔑 API Keys (Optional)

The tool works **without any API keys** using free sources:
- Certificate Transparency (crt.sh)
- DNS resolution
- Team Cymru ASN lookups

### For Better Results: Add Free API Keys

**Recommended Setup** (all free tier):

1. **Shodan** → https://account.shodan.io/
   ```bash
   export SHODAN_API_KEY="your_key_here"
   ```

2. **VirusTotal** → https://www.virustotal.com/gui/my-apikey
   ```bash
   export VT_API_KEY="your_key_here"
   ```

3. **Censys** → https://search.censys.io/account/api
   ```bash
   export CENSYS_API_ID="your_id"
   export CENSYS_API_SECRET="your_secret"
   ```

Or create a `.env` file:

```bash
# Copy template
cp .env.example .env

# Edit .env and add your keys
nano .env
```

---

## 📝 Common Commands

```bash
# View all options
python ip_finder.py --help

# Check which sources are configured
python ip_finder.py --sources-only

# Basic scan (display only)
python ip_finder.py --target example.com

# Save as JSON
python ip_finder.py --target example.com --output results.json

# Save as CSV
python ip_finder.py --target example.com --output results.csv --format csv

# Save as TXT (IP list)
python ip_finder.py --target example.com --output ips.txt --format txt

# Scan multiple domains
python ip_finder.py --target-file domains.txt

# Verbose mode (see what's happening)
python ip_finder.py --target example.com --verbose

# Quiet mode (results table only)
python ip_finder.py --target example.com --quiet

# Limit to specific sources
python ip_finder.py --target example.com --limit-source shodan --limit-source censys

# Speed up with more concurrency
python ip_finder.py --target example.com --max-concurrency 25
```

---

## 🔄 Integration with Other Tools

### Feed IPs to Nmap

```bash
# Get IPs and scan ports
python ip_finder.py --target example.com --output ips.txt --format txt
sudo nmap -iL ips.txt -p- -oA scan_results
```

### Use with Masscan

```bash
python ip_finder.py --target example.com --output ips.txt --format txt
sudo masscan -iL ips.txt -p0-65535 --rate 10000
```

### Extract Data with jq (from JSON)

```bash
# Save as JSON first
python ip_finder.py --target example.com --output results.json

# Extract all IPs
jq -r '.[].ip' results.json

# Get IPs from Shodan only
jq -r '.[] | select(.sources[] | contains("shodan")) | .ip' results.json

# Get US IPs only
jq -r '.[] | select(.country == "US") | .ip' results.json
```

---

## 📊 Example Output

### Console (Always Shown)

```
====================================================================================================
IP ADDRESS                               SOURCES                        ASN            COUNTRY
====================================================================================================
93.184.216.34                            crt.sh, dns, shodan            AS15133        US
2606:2800:220:1:248:1893:25c8:1946      dns                            AS15133        US
104.244.42.65                            shodan, virustotal             AS13335        US
====================================================================================================

Total IPs discovered: 3

IPs by source:
  dns                  2 IPs
  shodan               2 IPs
  crt.sh               1 IPs
  virustotal           1 IPs
```

### JSON File (if --output specified)

```json
[
  {
    "ip": "93.184.216.34",
    "sources": ["crt.sh", "dns", "shodan"],
    "first_seen": "2025-10-08T14:32:15.123456",
    "asn": "AS15133",
    "netblock": "93.184.216.0/24",
    "country": "US",
    "ptr": "example.com",
    "ports": [80, 443],
    "notes": "A record"
  }
]
```

### TXT File (if --format txt)

```
93.184.216.34
104.244.42.65
2606:2800:220:1:248:1893:25c8:1946
```

---

## 🛠️ Troubleshooting

### Issue: "No targets specified"

**Solution**: Add `--target domain.com` or `--target-file file.txt`

```bash
python ip_finder.py --target example.com
```

---

### Issue: "No IP addresses discovered"

**Possible causes**:
1. Domain has no public IP infrastructure
2. All sources failing (check with `--verbose`)
3. Network connectivity issues

**Solutions**:
```bash
# Check sources
python ip_finder.py --sources-only

# Try verbose mode
python ip_finder.py --target example.com --verbose

# Try known-good domain
python ip_finder.py --target google.com
```

---

### Issue: Rate limit errors

**Solution**: Reduce concurrency

```bash
python ip_finder.py --target example.com --max-concurrency 5
```

---

### Issue: API authentication failed

**Solution**: Check API keys

```bash
# Verify keys are set
echo $SHODAN_API_KEY
echo $VT_API_KEY

# Check which sources are working
python ip_finder.py --sources-only
```

---

## ⚖️ Legal Notice

**⚠️ IMPORTANT**: This tool is for authorized use only!

**Allowed uses**:
✅ Your own infrastructure
✅ Authorized penetration testing (with written permission)
✅ Bug bounty programs (within scope)
✅ Educational purposes in controlled labs

**NOT allowed**:
❌ Unauthorized scanning of third-party domains
❌ Violating API terms of service
❌ Any illegal or malicious activities

**Get written permission before scanning any domain you don't own!**

---

## 📚 More Information

- **Full Documentation**: See `README.md`
- **Detailed Usage**: See `USAGE.md`
- **API Setup**: See `.env.example`
- **Recent Changes**: See `CHANGES.md`

---

## 💡 Pro Tips

1. **Start without API keys** - Test basic functionality first
2. **Add Shodan + VirusTotal** - Best free coverage
3. **Use verbose mode** - See what's happening: `--verbose`
4. **Save important results** - Use `--output results.json`
5. **Pick the right format**:
   - JSON for analysis
   - CSV for spreadsheets
   - TXT for tool integration
6. **Check logs** - File `ip_finder.log` has detailed info

---

## 🎯 Workflow Example

```bash
# 1. Check configuration
python ip_finder.py --sources-only

# 2. Quick test scan
python ip_finder.py --target example.com

# 3. If results look good, save them
python ip_finder.py --target example.com --output example.json

# 4. Also get simple IP list for nmap
python ip_finder.py --target example.com --output example_ips.txt --format txt

# 5. Scan the IPs
sudo nmap -iL example_ips.txt -p- -A -oA nmap_full_scan
```

---

**Ready to start?** Run your first scan now:

```bash
python ip_finder.py --target example.com
```

🎉 **Happy hunting!** (Authorized targets only!)