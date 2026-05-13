# Bug Bounty Automated Scanner

A powerful automated reconnaissance tool for bug bounty hunting that scans wildcard domains for subdomains and discovers endpoints.

## Features

- ✅ **Subdomain Enumeration** - Automatically discovers subdomains from wildcard patterns (*.example.com)
- ✅ **Endpoint Discovery** - Finds API endpoints, admin panels, config files, and more
- ✅ **Concurrent Scanning** - Fast async scanning with configurable concurrency
- ✅ **Multiple Input Formats** - Supports wildcards and direct URLs
- ✅ **Multiple Output Formats** - Export to JSON, CSV, or TXT
- ✅ **Rate Limiting** - Built-in semaphore to avoid overwhelming targets
- ✅ **Smart Crawling** - Discovers links from pages automatically
- ✅ **Common Path Testing** - Tests 40+ common endpoints (API, admin, config, etc.)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python3 bug_bounty_scanner.py -i target.com -w my_endpoints.txt -c 80 -t 10 -f json -o professional_recon.json
```

### Advanced Options

```bash
# Export to CSV format
python bug_bounty_scanner.py -i targets.txt -o results.csv -f csv

# Increase concurrency for faster scanning
python bug_bounty_scanner.py -i targets.txt -o results.json -c 20

# Custom timeout and user-agent
python bug_bounty_scanner.py -i targets.txt -o results.json -t 15 -u "MyScanner/1.0"

# Export to text file for easy reading
python bug_bounty_scanner.py -i targets.txt -o results.txt -f txt
```

### Command-Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| --input | -i | Yes | Input file with wildcard domains/URLs (one per line) |
|--WORDLISTS |-w| adding your own wordlists
| --output | -o | Yes | Output file for results |
| --format | -f | No | Output format: json, csv, or txt (default: json) |
| --concurrent | -c | No | Max concurrent requests (default: 10) |
| --timeout | -t | No | Request timeout in seconds (default: 10) |
| --user-agent | -u | No | Custom User-Agent string |

## Input File Format

Create a `targets.txt` file with one target per line:

```txt
# Wildcard domains (will enumerate subdomains)
*.example.com
*.bugcrowd.com
*.hackerone.com

# Direct URLs (will scan for endpoints)
https://api.example.com
https://admin.example.com
portal.example.com

# Comments start with #
# Blank lines are ignored
```

## Output Formats

### JSON Output
```json
{
  "scan_time": "2024-01-15T10:30:00",
  "total_endpoints": 156,
  "total_urls": 12,
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "admin.example.com"
  ],
  "endpoints": {
    "https://api.example.com": [
      "https://api.example.com/v1",
      "https://api.example.com/v2",
      "https://api.example.com/docs"
    ]
  }
}
```

### CSV Output
```csv
Base URL,Endpoint,Discovered At
https://api.example.com,https://api.example.com/v1,2024-01-15T10:30:00
https://api.example.com,https://api.example.com/v2,2024-01-15T10:30:00
```

### TXT Output
```txt
# Bug Bounty Scan Results
# Scan Time: 2024-01-15T10:30:00
# Total Endpoints: 156

## https://api.example.com
https://api.example.com/v1
https://api.example.com/v2
https://api.example.com/docs
```

## What Gets Scanned

### Subdomain Enumeration
When you provide a wildcard (*.example.com), the tool tests common subdomains:
- Web: www, m, blog, shop, store
- Infrastructure: api, cdn, static, media, assets
- Admin: admin, portal, dashboard, panel, control
- Development: dev, staging, beta, test, qa
- Services: mail, smtp, webmail, vpn, git
- And 30+ more common patterns

### Endpoint Discovery
For each discovered domain/URL, the tool finds:
- **API endpoints**: /api, /api/v1, /api/v2, /graphql
- **Authentication**: /login, /signin, /auth, /oauth, /token
- **Admin panels**: /admin, /dashboard, /panel, /manage
- **User areas**: /user, /profile, /account, /settings
- **Documentation**: /docs, /swagger, /api-docs
- **Configuration**: /config, /.env, /robots.txt, /sitemap.xml
- **Development**: /debug, /test, /.git, /backup
- **And 40+ other common patterns**

## Performance Tips

1. **Adjust Concurrency**: Start with `-c 10` and increase if your network can handle it
2. **Timeout Settings**: Use `-t 5` for faster scanning, `-t 15` for more reliability
3. **Large Scans**: For 100+ targets, consider splitting into multiple files
4. **Rate Limiting**: The built-in semaphore prevents overwhelming targets

## Example Workflow

```bash
# 1. Create your targets file
echo "*.example.com" > targets.txt
echo "*.testsite.org" >> targets.txt
echo "https://api.bugbounty.com" >> targets.txt

# 2. Run the scanner
python bug_bounty_scanner.py -i targets.txt -o results.json -c 15

# 3. Review results
cat results.json | jq '.total_endpoints'

# 4. Export to CSV for spreadsheet analysis
python bug_bounty_scanner.py -i targets.txt -o results.csv -f csv

# 5. Generate readable report
python bug_bounty_scanner.py -i targets.txt -o report.txt -f txt
```

## Important Notes

⚠️ **Legal Disclaimer**: Only scan targets you have permission to test. Unauthorized scanning may be illegal.

⚠️ **Rate Limiting**: Be respectful of target servers. Use appropriate concurrency settings.

⚠️ **False Positives**: Always verify discovered endpoints manually.

## Extending the Tool

### Add More Subdomains
Edit the `common_subdomains` list in the code to add more subdomain patterns.

### Add More Endpoints
Edit the `common_paths` list to test additional endpoint patterns.

### Integration with Other Tools
The JSON output can be easily parsed by other tools:

```bash
# Extract all endpoints
cat results.json | jq -r '.endpoints[][] | select(contains("/api"))'

# Feed to other tools
cat results.json | jq -r '.endpoints[][]' | httpx -silent
```

## Troubleshooting

**No subdomains found?**
- Check if DNS is resolving correctly
- Try increasing timeout with `-t 15`
- Some domains may have firewall rules blocking enumeration

**Scan is too slow?**
- Increase concurrency: `-c 20` or higher
- Decrease timeout: `-t 5`
- Reduce the number of targets

**Getting timeout errors?**
- Increase timeout: `-t 20`
- Decrease concurrency: `-c 5`
- Check your network connection

## Contributing

Feel free to:
- Add more subdomain patterns
- Add more endpoint patterns
- Improve crawling logic
- Add new output formats
- Optimize performance

## License

This tool is for educational and authorized security testing only.
MIT License

Copyright (c) 2026 redraggit

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
