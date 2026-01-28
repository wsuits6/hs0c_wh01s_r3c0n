# HSOCIETY Reconnaissance Framework

## Overview
An enhanced reconnaissance tool with the iconic HSOCIETY ASCII banner, designed for ethical security research and domain intelligence gathering.

## What's New in This Version

### 🎨 Enhanced User Experience
- **Colored output** with consistent formatting
- **Section headers** for better organization
- **Progress indicators** for long operations
- **Verbose mode** for detailed output
- **Error handling** that doesn't crash the script

### 🔧 New Features
1. **Command-line options** (-s, -v, -t, -o, -h)
2. **Report saving** to timestamped files
3. **Technology detection** from HTTP headers
4. **SSL/TLS certificate analysis**
5. **IPv6 (AAAA) record lookup**
6. **TXT and CNAME record enumeration**
7. **Security header checking**
8. **Configurable timeouts**
9. **Domain validation**
10. **Better subdomain deduplication**

### 🛡️ Improved Reliability
- Timeout protection on all network operations
- Graceful error handling (warns, doesn't crash)
- Dependency checking before execution
- Input validation
- Temporary file cleanup

## Installation

### Required Dependencies
```bash
# Ubuntu/Debian
sudo apt install whois dnsutils curl jq openssl

# macOS
brew install whois bind curl jq openssl

# Fedora/RHEL
sudo dnf install whois bind-utils curl jq openssl
```

### Optional (for enhanced features)
```bash
# For better subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# For HTTP technology detection
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Make Executable
```bash
chmod +x hsociety_recon.sh
```

## Usage

### Basic Usage
```bash
./hsociety_recon.sh example.com
```

### With Options
```bash
# Save output to file
./hsociety_recon.sh --save example.com

# Verbose mode with file saving
./hsociety_recon.sh -s -v example.com

# Custom timeout and output directory
./hsociety_recon.sh --timeout 15 --output ./reports example.com

# All options combined
./hsociety_recon.sh -s -v -t 20 -o ./my_scans example.com
```

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--save` | `-s` | Save output to timestamped file |
| `--verbose` | `-v` | Show detailed output |
| `--timeout N` | `-t N` | Set timeout in seconds (default: 10) |
| `--output DIR` | `-o DIR` | Set output directory (default: ./hsociety_recon) |
| `--help` | `-h` | Show help message |

## Reconnaissance Modules

### 1. WHOIS Information
Retrieves domain registration details:
- Registrar information
- Registration dates (creation, expiry, last update)
- Name servers
- Registrant contact (verbose mode only)

**Output Example:**
```
Registrar Information:
  → Registrar: Example Registrar, Inc.

Registration Dates:
  → Created: 2020-01-15
  → Expires: 2025-01-15
  → Updated: 2024-11-20

Name Servers:
  → ns1.example.com
  → ns2.example.com
```

### 2. DNS Records
Comprehensive DNS enumeration:
- **A Records** (IPv4 addresses)
- **AAAA Records** (IPv6 addresses)
- **NS Records** (name servers)
- **MX Records** (mail servers with priority)
- **TXT Records** (SPF, DKIM, verification records)
- **CNAME Records** (canonical names)

**Output Example:**
```
A Records (IPv4):
  → 93.184.216.34

MX Records:
  → [Priority: 10] mail.example.com

TXT Records:
  → "v=spf1 include:_spf.example.com ~all"
```

### 3. Subdomain Discovery
Uses Certificate Transparency logs (crt.sh):
- Queries public certificate logs
- Finds subdomains from SSL certificates
- Removes wildcard entries
- Deduplicates results

**Output Example:**
```
Found 25 unique subdomain(s)

Discovered Subdomains:
  → www.example.com
  → mail.example.com
  → api.example.com
  → blog.example.com
```

### 4. Subdomain Resolution
Resolves discovered subdomains to IPs:
- Validates subdomain accessibility
- Maps subdomains to IP addresses
- Shows resolution failures in verbose mode
- Saves IPs for further analysis

**Output Example:**
```
  www.example.com → 93.184.216.34
  mail.example.com → 93.184.216.35
  api.example.com → 93.184.216.36
```

### 5. IP WHOIS Lookup
Investigates IP ownership:
- Organization/owner information
- Country/location
- IP range/CIDR blocks
- Additional details in verbose mode

**Output Example:**
```
93.184.216.34:
  → Organization: Example Cloud Services
  → Country: US
  → NetRange: 93.184.216.0 - 93.184.216.255
```

### 6. Technology Detection
Identifies web technologies:
- Server type (Apache, nginx, IIS)
- Programming languages/frameworks
- CMS detection (WordPress, Joomla, Drupal)
- JavaScript frameworks (React, Angular, Vue)
- Security headers analysis

**Output Example:**
```
HTTP Headers:
  → Server: nginx/1.21.0
  → X-Powered-By: PHP/8.1.0

Security Headers:
  → Strict-Transport-Security: max-age=31536000
  → X-Frame-Options: DENY

Technology Indicators:
  → WordPress detected
  → React detected
```

### 7. SSL/TLS Certificate Info
Analyzes SSL certificates:
- Certificate subject
- Issuer information
- Validity dates
- Subject Alternative Names (SANs)
- Additional domains covered

**Output Example:**
```
Certificate Details:
  → Subject: CN=example.com
  → Issuer: CN=Let's Encrypt Authority X3
  → Not Before: 2024-01-01
  → Not After: 2024-04-01

Subject Alternative Names:
  → example.com
  → www.example.com
  → api.example.com
```

## Output Files

When using `--save` option:
```
hsociety_recon/
└── example.com_20260128_143022.txt
```

File naming format: `{domain}_{YYYYMMDD}_{HHMMSS}.txt`

## Comparison: Original vs Improved

| Feature | Original | Improved |
|---------|----------|----------|
| **Options** | None | 5 command-line options |
| **Output** | Console only | Console + file |
| **DNS Records** | A, NS, MX | A, AAAA, NS, MX, TXT, CNAME |
| **Error Handling** | Basic | Comprehensive |
| **Timeouts** | None | Configurable |
| **SSL Info** | No | Yes |
| **Tech Detection** | No | Yes |
| **Security Headers** | No | Yes |
| **IPv6 Support** | No | Yes |
| **Formatting** | Basic | Colored, structured |
| **Validation** | None | Domain validation |
| **Dependencies** | No check | Pre-flight check |
| **Verbose Mode** | No | Yes |
| **Help System** | No | Yes |

## Advanced Usage

### Automation
```bash
# Scan multiple domains
for domain in $(cat domains.txt); do
    ./hsociety_recon.sh -s "$domain"
    sleep 5  # Be respectful
done
```

### Integration with Other Tools
```bash
# Export subdomains for further scanning
./hsociety_recon.sh -s example.com
grep "→" hsociety_recon/example.com_*.txt | grep -oP '[a-z0-9.-]+\.example\.com' > subdomains.txt

# Feed to other tools
cat subdomains.txt | httpx -title -tech-detect
cat subdomains.txt | nuclei -t cves/
```

### Scheduled Monitoring
```bash
# Add to crontab for daily monitoring
0 2 * * * /path/to/hsociety_recon.sh -s example.com
```

## Troubleshooting

### "Missing dependencies" error
```bash
# Install all required tools
sudo apt install whois dnsutils curl jq openssl

# Verify installation
whois --version
dig -v
curl --version
jq --version
```

### "Domain may not resolve" warning
This means the domain doesn't respond to DNS queries. Reasons:
- Domain doesn't exist
- DNS servers are down
- Network issues
- Domain recently registered/expired

You can choose to continue anyway if you're checking historical data.

### Timeout errors
If operations are timing out:
```bash
# Increase timeout
./hsociety_recon.sh --timeout 30 example.com

# Or edit the script default timeout
TIMEOUT=30  # Line 15 in the script
```

### No subdomains found
crt.sh may not have data for:
- Brand new domains
- Domains without SSL certificates
- Private/internal domains

Try alternative tools:
```bash
subfinder -d example.com
amass enum -passive -d example.com
```

### SSL certificate errors
Some domains may not have HTTPS configured. The script will:
- Warn about missing SSL
- Continue with other modules
- Not crash the entire scan

## Security & Ethics

### ⚠️ CRITICAL REMINDERS

1. **Authorization Required**: Only scan domains you own or have written permission to test
2. **Legal Compliance**: Unauthorized reconnaissance may violate:
   - Computer Fraud and Abuse Act (CFAA) in the US
   - Computer Misuse Act in the UK
   - Local cybersecurity laws in your jurisdiction
3. **Rate Limiting**: Be respectful of target servers
4. **Data Privacy**: Handle discovered information responsibly
5. **Bug Bounty Rules**: Follow program scope and rules

### Ethical Guidelines

```
✓ DO:
  - Get written authorization
  - Stay within scope
  - Report responsibly
  - Respect rate limits
  - Document your testing

✗ DON'T:
  - Scan without permission
  - Use for malicious purposes
  - Overwhelm target systems
  - Share private data
  - Ignore terms of service
```

## Tips & Best Practices

1. **Start with non-intrusive modules**: DNS and WHOIS are passive
2. **Use verbose mode for research**: `-v` shows additional details
3. **Save important scans**: Use `-s` to create audit trails
4. **Monitor changes over time**: Compare historical reports
5. **Combine with other tools**: Export data for deeper analysis
6. **Respect target resources**: Don't run aggressive scans
7. **Keep tools updated**: Ensure dependencies are current

## Performance Notes

**Typical scan times:**
- Small domain (< 10 subdomains): 15-30 seconds
- Medium domain (10-50 subdomains): 30-90 seconds
- Large domain (50+ subdomains): 2-5 minutes

**Factors affecting speed:**
- Number of subdomains
- Network latency
- DNS response times
- Target server response
- Timeout settings

## Customization

### Modify Timeout Values
Edit line 15:
```bash
TIMEOUT=10  # Change to your preference
```

### Change Default Output Directory
Edit line 14:
```bash
OUTPUT_DIR="./my_custom_dir"
```

### Add Custom Modules
Follow the module pattern:
```bash
module_custom() {
  section_header "My Custom Module"
  log_info "Running custom checks..."
  
  # Your code here
  
  log_success "Custom module complete"
}
```

Then call it in the `main()` function.

## Known Limitations

1. **crt.sh dependency**: Subdomain discovery relies on certificate transparency
2. **Network dependency**: All modules require internet access
3. **Rate limiting**: Some services may rate-limit requests
4. **No authentication**: Doesn't handle authenticated endpoints
5. **Passive only**: No active scanning or exploitation

## Future Enhancements

Potential additions:
- [ ] Alternative subdomain sources (VirusTotal, SecurityTrails)
- [ ] Port scanning integration
- [ ] Web application fingerprinting
- [ ] API endpoint discovery
- [ ] Email harvesting
- [ ] Social media profile discovery
- [ ] Historical DNS records
- [ ] JSON/CSV output format
- [ ] Diff mode for change detection
- [ ] Multi-threading for faster scans

## FAQ

**Q: Is this tool safe to use?**
A: Yes, when used ethically and legally on domains you're authorized to scan.

**Q: Will this trigger IDS/IPS?**
A: Basic reconnaissance is usually passive, but always get permission first.

**Q: Can I use this for bug bounties?**
A: Yes, but always follow the program's scope and rules.

**Q: Why are some modules skipped?**
A: If dependencies are missing or data is unavailable, modules fail gracefully.

**Q: How do I contribute?**
A: Fork the script, add features, test thoroughly, and submit improvements.

## Support

For issues or questions:
1. Check this documentation
2. Verify dependencies are installed
3. Test with a known-good domain
4. Review error messages carefully
5. Check network connectivity

## Credits

- **HSOCIETY** for the awesome ASCII banner
- Built on excellent open-source tools: whois, dig, curl, jq, openssl
- Certificate Transparency (crt.sh) for subdomain data
- Community feedback and contributions

---

**Remember: This tool is for ethical security research and authorized testing only.**
**Always obtain proper authorization before scanning any domain.**
**Respect privacy, follow laws, and use responsibly.**