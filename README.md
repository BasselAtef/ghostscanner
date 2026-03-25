# GhostScanner 👻

**AI-Powered Web Vulnerability Scanner**

GhostScanner is a fast, modular, open-source vulnerability scanner written in Python. It detects common misconfigurations, open ports, software versions, probes for OWASP Top 10 vulnerabilities, looks up active CVEs via the NIST NVD API, and securely routes the findings to the Gemini 2.0 Flash AI model for prioritized, plain-English remediation reports.

⚠️ **Disclaimer:** This tool is for educational purposes and authorized penetration testing only. Do not scan systems, IP addresses, or domains you do not own or have explicit permission to test. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Features
- **TCP Port Scanning**: Scans top 1000 ports via raw sockets with `python-nmap` fallback.
- **Banner Grabbing**: Fetches HTTP server headers, socket banners, and TLS configurations.
- **OWASP Probes**: Checks for directory traversal, basic SQLi/XSS, missing HTTPS, and exposed admin/debug endpoints.
- **CVE Lookups**: Automatically maps identified software to the National Vulnerability Database (NVD) to fetch the latest CVSS scores.
- **AI Analyst**: Formats findings and sends them to Gemini 2.0 Flash to generate an executive report with remediation steps.
- **Rich Output**: Generates live terminal tables, JSON dumps, and self-contained HTML reports.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/BasselAtef/ghostscanner.git
   cd ghostscanner
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your Gemini API key (Required for AI Analysis):
   ```bash
   # Windows
   set GEMINI_API_KEY="your_api_key_here"
   
   # Linux/macOS
   export GEMINI_API_KEY="your_api_key_here"
   ```

## Usage
Run the script passing your target domain or IP. 

```bash
python ghostscanner.py --target example.com
```

### Advanced Usage Examples
```bash
# Export the report as a beautiful HTML file and run verbose mode
python ghostscanner.py --target example.com --output html -v

# Scan a specific port range
python ghostscanner.py --target example.com --ports 1-100

# Skip AI analysis and OWASP checks (for a faster, passive scan)
python ghostscanner.py --target example.com --skip ai,owasp
```

### Available Arguments
- `--target` (Required): The domain or IP address to scan.
- `--ports` (Optional): Port range to scan (e.g., `80-443`). Defaults to `1-1000`.
- `--output` (Optional): `terminal`, `json`, or `html`. Defaults to `terminal`.
- `--skip` (Optional): Comma-separated list of modules to skip (`ports`, `banners`, `owasp`, `cve`, `ai`).
- `-v, --verbose`: Enable verbose mode to track internal module scanning.

## License
[MIT](LICENSE)
