# rprobe

A comprehensive web reconnaissance tool designed for security professionals and system administrators. rprobe efficiently probes HTTP and HTTPS services, identifies web technologies, analyzes content for sensitive information, examines TLS certificates, and generates detailed scan reports.

**Important**: Only scan systems you own or have explicit permission to test. Unauthorized scanning may violate terms of service or local laws.

## Legal Disclaimer

**WARNING**: This tool is designed for authorized security testing and research purposes only.

### Authorization Requirements

- **Explicit Written Permission**: Only use this tool on systems where you have explicit written authorization from the system owner
- **Own Systems Only**: Limit testing to systems you personally own or operate
- **Corporate Environment**: Obtain proper authorization from IT management and legal departments before conducting security assessments
- **Third-Party Testing**: Never use this tool against third-party systems without explicit written consent and proper legal agreements

### Scope Limitations

- **Define Clear Boundaries**: Establish specific IP ranges, domains, and testing windows before conducting assessments
- **Approved Domains Only**: Restrict testing to pre-approved target lists and never exceed authorized scope
- **Production Systems**: Exercise extreme caution when testing production systems - consider safe mode options
- **Rate Limiting**: Use appropriate rate limiting to avoid service disruption

### Legal Considerations by Jurisdiction

**This tool may violate computer crime laws in many jurisdictions:**

- **Germany**: §202c StGB (Vorbereitung des Ausspähens und Abfangens von Daten) - Unauthorized network scanning and vulnerability testing may constitute criminal preparation of data interception
- **United Kingdom**: Computer Misuse Act 1990 - Unauthorized access to computer systems is illegal and may result in criminal prosecution
- **United States**: Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030 - Unauthorized access to protected computers may result in federal criminal charges and civil liability
- **European Union**: GDPR Article 32 - Security testing must comply with data protection regulations and may require data protection impact assessments

### Professional Responsibility

- **Due Diligence**: Verify authorization and legal compliance before using this tool
- **Documentation**: Maintain proper documentation of authorization and testing scope
- **Incident Response**: Be prepared to immediately cease testing if unauthorized access is detected
- **Responsible Disclosure**: Follow responsible disclosure practices for any vulnerabilities discovered

### No Liability

The authors and contributors of this tool accept no responsibility for misuse, legal violations, or damages resulting from unauthorized or improper use. Users assume full legal responsibility for their actions.

**By using this tool, you acknowledge that you have read, understood, and agree to comply with all applicable laws and ethical guidelines.**

## Features

- **HTTP/HTTPS Probing**: Test for active web servers on target hosts
- **Advanced Pattern Matching Optimization**: High-performance pattern matching with Aho-Corasick algorithm for 5-10x faster technology detection
- **Technology Detection**: Identify web servers, CMS platforms, frameworks, and more with optimized hybrid pattern matching
- **Enhanced Output Formatting**: Improved readable output with visual separators and color-coded indicators
- **Smart Compact Mode**: `-c/--short` flag with intelligent summary display (shows summary only for multiple targets)
- **Content Analysis**: Scan for sensitive information, security issues, and configuration problems with RegexSet optimization
- **TLS Certificate Analysis**: Examine certificate details, detect vulnerabilities, and identify expiring certificates
- **DEF CON HTTP-Must-Die Desync Scanner**: Advanced HTTP request smuggling vulnerability detection
  - Raw TCP socket implementation for precise HTTP parsing control
  - Detection of CL.0, 0.CL, TE.CL, Double-Desync, and other request smuggling attacks
  - Comprehensive safety mechanisms with authorization prompts and target validation
  - Support for both HTTP and HTTPS with proper TLS certificate validation
- **Enhanced X-Headers Infrastructure Detection**: Advanced proxy and infrastructure analysis
  - Unified X-Forwarded-For, X-Backend, and X-Cache header analysis
  - Enhanced X-Frame-Options analysis with clickjacking protection assessment
  - Cloud provider detection (AWS, Google Cloud, Azure, Cloudflare, Fastly)
  - Infrastructure component classification (Load Balancer, CDN, Cache, Reverse Proxy)
  - Proxy chain analysis with security insights and hop counting
- **Concurrency Control**: Configure workers and rate limits to optimize scanning
- **Screenshot Capability**: Capture visual snapshots of responsive websites
- **Multi-Format Reporting**: Export results as TXT, JSON, CSV, or HTML
- **Resume Support**: Save and resume scan progress
- **Robots.txt Analysis**: Download and analyze robots.txt files
- **Organized Output**: Store results in a structured directory format

## Performance Optimizations

rprobe implements advanced optimization techniques for maximum scanning performance:

### Advanced Pattern Matching System
- **Aho-Corasick Algorithm Integration**: 5-10x faster literal pattern matching for common detection strings
- **Hybrid Pattern Matching**: Combines fast literal matching with flexible regex patterns for optimal performance
- **OptimizedPatternMatcher**: Unified pattern matching infrastructure supporting both literal and regex patterns with automatic optimization

### Content Analysis Optimization
- **RegexSet Implementation**: Parallel pattern matching instead of sequential regex iteration for 3-5x improvement
- **PatternMatcher**: Optimized workflow for sensitive data detection patterns
- **Efficient Classification**: Performance-optimized detection of sensitive patterns, security issues, and configuration problems

### Technology Detection Performance
- **Plugin System Optimization**: All technology detection plugins use optimized pattern matching
- **Literal Pattern Fast-Path**: Common detection strings use Aho-Corasick for maximum speed
- **Smart Pattern Classification**: Automatic separation of literal and regex patterns for optimal performance
- **Shared Utilities**: Consistent optimization patterns across all plugins

### Implementation Details
- **once_cell::sync::Lazy**: Efficient one-time pattern compilation
- **Pattern Separation**: Literal patterns for speed, regex patterns for flexibility
- **Confidence Scoring**: HashMap-based scoring system for accurate detection confidence

These optimizations provide significant performance improvements while maintaining full detection accuracy and backward compatibility.

## Installation

### From crates.io

```bash
cargo install rprobe
```

### From Source

```bash
git clone https://github.com/vschwaberow/rprobe.git
cd rprobe
cargo build --release
```

The compiled binary will be available at `target/release/rprobe`.

## Usage

### Basic Usage

```bash
# Scan targets from stdin (default scan)
echo "https://example.com" | rprobe scan

# Compact one-line output format
echo "https://example.com" | rprobe scan -c

# Scan from file with 10 concurrent workers
rprobe -t 10 -w 10 scan -i domains.txt

# Enable technology detection
rprobe scan -i domains.txt -d
```

### Advanced Usage

```bash
# Comprehensive reconnaissance scan
rprobe -t 10 -w 20 -r 5 scan -i targets.txt -d --content-analysis --tls-analysis --screenshot

# Comprehensive TLS analysis (requires external tools)
rprobe scan -i targets.txt --comprehensive-tls

# Security-focused scan with multiple output formats
rprobe scan -i targets.txt -d --content-analysis --tls-analysis --html --csv

# Compact output for bulk scanning (smart summary display)
rprobe scan -i targets.txt -d -c
```

### DEF CON HTTP-Must-Die Desync Scanner

**WARNING**: The desync scanner performs HTTP request smuggling attacks and should only be used on systems you own or have explicit written authorization to test.

```bash
# Basic desync vulnerability scan (safe mode)
rprobe scan --desync --desync-safe-mode --desync-target https://example.com

# Scan multiple targets from file
rprobe scan --desync --desync-safe-mode -i desync_targets.txt

# Advanced desync scan with custom output directory
rprobe -o custom_results scan --desync --desync-target https://target.com
```

The desync scanner includes:
- **Authorization prompts**: Interactive confirmation before testing (the old `--i-have-authorization` flag has been removed)
- **Target validation**: Automatic detection of major infrastructure domains
- **Safe mode**: Conservative limits and timeouts for production testing
- **Multiple attack vectors**: CL.0, 0.CL, TE.CL, Double-Desync, and more
- **Detailed reporting**: Vulnerability evidence with raw requests/responses

### CLI Overview

The CLI now uses subcommands. Global options must appear before the subcommand. Scan-specific options follow the `scan` subcommand.

- Top-level usage: `rprobe [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]`
- Important: top-level options like `-t/--timeout`, `-s/--suppress-stats`, `-w/--workers`, `-o/--output-dir` must be placed before `scan`.

Subcommands:
- `scan`: perform scans (HTTP/HTTPS probing, tech detection, content/TLS analysis, desync)
- `output`: render stored results to reports
- `history`: show stored scan history
- `compare`: diff two scan results
- `clean`: clean up stored data
- `stats`: database statistics

Examples:
```bash
# Global options before subcommand
rprobe -t 10 -w 20 -s scan -i targets.txt -d --content-analysis --tls-analysis

# From stdin
echo "https://example.com" | rprobe scan -d -c
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
├── desync/                 # DEF CON HTTP-Must-Die desync scanner results
│   ├── desync_results_TIMESTAMP.jsonl  # Detailed vulnerability findings (JSONL format)
│   ├── desync_summary_TIMESTAMP.txt    # Human-readable summary report
│   ├── desync_results_TIMESTAMP.html   # HTML report with vulnerability details
│   └── desync_results_TIMESTAMP.json   # JSON export of all findings
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

## DEF CON HTTP-Must-Die Desync Scanner

The desync scanner is a specialized tool for detecting HTTP request smuggling vulnerabilities based on James Kettle's DEF CON research. It performs low-level TCP socket communication to send carefully crafted malformed HTTP requests.

### Vulnerability Detection

The scanner tests for various HTTP request smuggling attack vectors:

- **CL.0 (Content-Length Zero)**: Tests server handling of zero-length bodies
- **0.CL (Zero Content-Length)**: Tests conflicting Content-Length headers
- **TE.CL (Transfer-Encoding vs Content-Length)**: Tests discrepancies between TE and CL headers
- **Double-Desync**: Advanced attacks using multiple request smuggling techniques
- **TE Obfuscation**: Tests for Transfer-Encoding header parsing inconsistencies
- **Duplicate Content-Length**: Tests server behavior with multiple CL headers

### Safety Features

The desync scanner includes comprehensive safety mechanisms:

- **Interactive Authorization**: Requires explicit user confirmation before testing
- **Target Validation**: Automatic detection and warnings for major infrastructure domains
- **Safe Mode**: Conservative timeout and rate limiting for production environments
- **Rate Limiting**: Built-in protections against overwhelming target servers
- **Comprehensive Logging**: Detailed evidence collection with raw request/response data

### Security Warning

**CRITICAL**: This scanner performs actual HTTP request smuggling attacks that can:
- Cause service disruption and downtime
- Interfere with legitimate user traffic
- Trigger security alerts and incident response
- Potentially violate computer fraud laws

Only use on systems you own or have explicit written authorization to test. Unauthorized security testing is illegal in most jurisdictions.

## Plugins

rprobe includes several technology detection plugins:

**Technology Detection:**
- Apache Basic: Detects Apache web servers
- Nginx Basic: Detects Nginx web servers
- Cloudflare Basic: Detects Cloudflare-protected sites
- WordPress Basic: Detects WordPress installations
- PHP Basic: Detects PHP-based sites
- Laravel: Detects Laravel framework

**Infrastructure Analysis:**
- X-Headers: Unified analysis of X-Forwarded-For, X-Backend, X-Cache, and X-Frame-Options headers with infrastructure classification
  - Enhanced X-Frame-Options analysis with clickjacking protection assessment and policy validation
- X-Forwarded-For: Enhanced proxy chain analysis with cloud provider detection and security insights
- X-Backend: Backend server detection through X-Backend headers
- X-Cache: Cache infrastructure analysis through X-Cache headers

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

**Built-in Dependencies:**
- **tokio-rustls**: Integrated TLS 1.2/1.3 support for the desync scanner
- **webpki-roots**: Root certificate store for TLS certificate validation

None of the external tools are required for basic operation - rprobe will gracefully handle their absence. The desync scanner uses built-in TLS implementations and does not require external dependencies.

## History Storage

- Default: history storage is enabled. Scan results and sessions are written to a local embedded database (sled).
- Opt-out: pass `--no-store-history` at the top level to disable storage for a run.
- Location: defaults to platform data dir, or use `--data-dir DIR` (data is stored under `DIR/rprobe_history`).

### Screenshots

- Set `RPROBE_BROWSER` to the preferred Chrome/Chromium binary path to control which browser is used for headless screenshots.
- Fallback order without the env var: `chromium` → `google-chrome` → `chromium-browser` → `google-chrome-stable` → `wkhtmltoimage`.
- Screenshots save to `scan/screenshots/` (or your `-o` dir) and the absolute path is stored in history records when `--store-history` is enabled.

## Examples

**Basic scan with HTML report:**
```bash
cat domains.txt | rprobe --html
```

**Security assessment scan:**
```bash
rprobe -i targets.txt -d --content-analysis --tls-analysis -w 20 -r 5
```

**Complete reconnaissance scan:**
```bash
rprobe -i targets.txt -d --content-analysis --tls-analysis --comprehensive-tls --screenshot --html --csv
```

**Resume interrupted scan:**
```bash
rprobe -i large_target_list.txt --resume-file myscan.state --content-analysis
```

**Target specific technology:**
```bash
rprobe -i domains.txt --plugin "WordPress" 
```

**DEF CON 33 aligned desync vulnerability scan (authorized):**
```bash
rprobe --desync --i-have-authorization --desync-safe-mode --desync-target https://target.com
```

**Advanced desync scan with comprehensive attack vectors:**
```bash
rprobe --desync --i-have-authorization --desync-advanced-vectors --desync-target https://target.com
```

## Contributing

Contributions are welcome! Please submit pull requests with improvements, bug fixes, or new features.

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
