# rprobe

A powerful tool for web reconnaissance that probes for HTTP and HTTPS services, identifies web technologies, analyzes content for sensitive information, examines TLS certificates, and provides comprehensive scan reports.

**Always scan your own assets, or the assets you are allowed to scan.**

## Features

- **HTTP/HTTPS Probing**: Test for active web servers on target hosts
- **Technology Detection**: Identify web servers, CMS platforms, frameworks, and more
- **Content Analysis**: Scan for sensitive information, security issues, and configuration problems
- **TLS Certificate Analysis**: Examine certificate details, detect vulnerabilities, and identify expiring certificates
- **Concurrency Control**: Configure workers and rate limits to optimize scanning
- **Screenshot Capability**: Capture visual snapshots of responsive websites
- **Multi-Format Reporting**: Export results as TXT, JSON, CSV, or HTML
- **Resume Support**: Save and resume scan progress
- **Robots.txt Analysis**: Download and analyze robots.txt files
- **Organized Output**: Store results in a structured directory format

## Installation

### From crates.io

```
cargo install rprobe
```

### From Source

```
git clone https://github.com/vschwaberow/rprobe.git
cd rprobe
cargo build --release
```

The binary will be available at `target/release/rprobe`.

## Usage

### Basic Usage

```bash
# Scan from stdin (one URL per line)
cat domains.txt | rprobe

# Scan from a file with 10 concurrent workers
rprobe -i domains.txt -w 10

# Scan with technology detection enabled
rprobe -i domains.txt -d
```

### Advanced Usage

```bash
# Full reconnaissance with content analysis, TLS analysis and screenshots
rprobe -i targets.txt -d --content-analysis --tls-analysis --screenshot -w 20 -r 5

# Perform comprehensive TLS analysis (requires testssl.sh or nmap)
rprobe -i targets.txt --comprehensive-tls

# Security focused scan with output to all formats
rprobe -i sensitive_targets.txt -d --content-analysis --tls-analysis --html --csv
```

### Command Line Options

```
rprobe --help

rprobe (c) 2022-2025 by Volker Schwaberow <volker@schwaberow.de>
A simple tool to probe a remote host http or https connection

Usage: rprobe [OPTIONS]

Options:
  -t, --timeout <TIMEOUT>                  [default: 10]
  -n, --nohttp                             Disable HTTP probing
  -N, --nohttps                            Disable HTTPS probing
  -S, --show-unresponsive                  Show unresponsive hosts in output
  -s, --suppress-stats                     Don't show statistics at the end
  -d, --detect-all                         Detect technologies on all hosts
  -p, --plugins                            List available detection plugins
  -r, --rate-limit <RATE_LIMIT>            Requests per second [default: 10]
  -w, --workers <WORKERS>                  Number of concurrent workers [default: 10]
      --plugin <PLUGIN>                    Specify a plugin to use
      --report-format <REPORT_FORMAT>      Format for main report [default: text]
      --report-filename <REPORT_FILENAME>  Custom filename for main report
      --download-robots                    Download robots.txt files
  -i, --input-file <INPUT_FILE>            Read targets from file instead of stdin
  -o, --output-dir <OUTPUT_DIR>            Directory to store scan results [default: scan]
      --log-level <LOG_LEVEL>              Set log level (error, warn, info, debug, trace) [default: info]
      --screenshot                         Take screenshots of responsive sites
      --resume-file <RESUME_FILE>          Save/resume scan state to/from this file
      --csv                                Export results to CSV format
      --html                               Export results to HTML report
      --content-analysis                   Analyze page content for sensitive information
      --tls-analysis                       Analyze TLS certificates for HTTPS sites
      --comprehensive-tls                  Perform comprehensive TLS analysis (requires external tools)
  -h, --help                               Print help
  -V, --version                            Print version
```

## Output Structure

By default, rprobe creates a `scan` directory with the following structure:

```
scan/
├── headers/                # HTTP response headers
├── html/                   # Response body content
├── robots/                 # robots.txt files (if enabled)
├── screenshots/            # Screenshots (if enabled)
├── content_analysis/       # Content analysis reports
│   ├── content_findings.html  # Detailed HTML report of content findings
│   └── content_findings.csv   # CSV export of all findings
├── tls_analysis/           # TLS certificate analysis
│   ├── certificate_analysis.html  # Detailed certificate information
│   └── certificate_analysis.csv   # CSV export of certificate data
├── index.txt               # Index of all scanned sites
├── report_output.txt       # Main report
├── report_output.csv       # CSV report (if enabled)
└── report_output.html      # HTML report (if enabled)
```

## Content Analysis

The content analysis feature scans webpage content for:

- **Sensitive Information**: API keys, credentials, tokens, email addresses, internal IPs
- **Security Issues**: Error messages, debug comments, directory listings
- **Configuration Problems**: Default credentials, debug mode settings
- **Form Security**: CSRF protection, password field configurations
- **JavaScript Issues**: Eval usage, inline scripts, document.write calls

Findings are classified by severity level:
- **Critical**: Highly sensitive information that requires immediate attention
- **High**: Serious security issues that should be addressed promptly
- **Medium**: Notable concerns that should be reviewed
- **Low**: Minor issues that represent best practice violations
- **Info**: Informational findings

## TLS Certificate Analysis

The TLS analysis examines HTTPS certificates for security issues:

- **Certificate Validity**: Expiration dates and validity periods
- **Public Key Details**: Algorithm, key size, and potential weaknesses
- **TLS Versions**: Detection of outdated or insecure TLS implementations
- **Cipher Suites**: Identifies vulnerable or weak ciphers
- **Extended Validation**: Checks for enhanced validation status
- **Self-Signed Certificates**: Detection of untrusted certificates

The comprehensive TLS analysis (requires external tools like testssl.sh or nmap) can detect:
- Heartbleed vulnerability
- POODLE vulnerability
- DROWN vulnerability
- BEAST attack vulnerability
- Logjam vulnerability
- Support for weak protocols

## Plugins

rprobe includes several technology detection plugins:

- Apache Basic: Detects Apache web servers
- Nginx Basic: Detects Nginx web servers
- Cloudflare Basic: Detects Cloudflare-protected sites
- WordPress Basic: Detects WordPress installations
- PHP Basic: Detects PHP-based sites
- Laravel: Detects Laravel framework

List all available plugins with:
```bash
rprobe -p
```

## External Tool Dependencies

For full functionality, rprobe can leverage these external tools if available:

- **Chrome/Chromium**: For taking screenshots (with `--screenshot`)
- **wkhtmltoimage**: Alternative for screenshots if Chrome/Chromium isn't available
- **OpenSSL**: For TLS certificate analysis (with `--tls-analysis`)
- **testssl.sh**: For comprehensive TLS security checks (with `--comprehensive-tls`)
- **nmap**: For additional TLS vulnerability scanning (with `--comprehensive-tls`)

None of these are required for basic operation - rprobe will gracefully handle their absence.

## Examples

**Basic scan with HTML report:**
```bash
cat domains.txt | rprobe --html
```

**Security assessment scan:**
```bash
rprobe -i targets.txt -d --content-analysis --tls-analysis -w 20 -r 5
```

**Full reconnaissance with all features:**
```bash
rprobe -i targets.txt -d --content-analysis --tls-analysis --comprehensive-tls --screenshot --html --csv
```

**Resume a previous scan:**
```bash
rprobe -i large_target_list.txt --resume-file myscan.state --content-analysis
```

**Specific technology detection:**
```bash
rprobe -i domains.txt --plugin "WordPress" 
```

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

### Adding New Plugins

1. Create a new file in `src/plugins/`
2. Implement the `Plugin` trait
3. Register your plugin in `src/plugins/mod.rs`

### Adding New Content Analysis Patterns

To add new detection patterns for sensitive content:
1. Edit `src/content_analyzer.rs`
2. Add your regex patterns to the appropriate section
3. Include a meaningful description and severity level

## License

This project is licensed under either the MIT License or Apache License 2.0, at your option.