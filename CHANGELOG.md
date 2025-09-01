# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note: Version headings intentionally omit release dates. Refer to Git history or tagged releases for timestamps.

## [0.9.0]

### Added
- **Advanced Pattern Matching Optimization**: Major performance improvements for technology detection plugins
  - **Aho-Corasick Algorithm Integration**: Integrating Aho-Corasick for faster literal pattern matching in common detection strings
  - **Hybrid Pattern Matching System**: Combines fast literal matching with flexible regex patterns for optimal performance
  - **OptimizedPatternMatcher**: New pattern matching infrastructure supporting both literal and regex patterns with automatic optimization
  - **Enhanced Plugin Performance**: Significant speed improvements across all technology detection plugins
- **DEF CON 33 Aligned HTTP Desync Scanner**: State-of-the-art HTTP request smuggling vulnerability detection
  - **Advanced Attack Vectors**: TE.0 attacks, bare semicolon chunk extensions, V-H/H-V visibility-flip testing
  - **Two-Hop Oracle System**: Advanced detection mechanism for complex desynchronization scenarios
  - **Timing-Based Anomaly Detection**: Sophisticated timing analysis for vulnerability identification
  - **Parser Discrepancy Testing**: Comprehensive testing for HTTP parser inconsistencies
  - **Cross-Protocol Testing**: H2.CL/H2.TE attack vectors for HTTP/2 downgrade scenarios
  - **Cache Poisoning Detection**: Identification of cache contamination vulnerabilities
  - **Connection Reuse Exploitation**: Advanced techniques for persistent connection attacks
  - Raw TCP socket implementation for precise HTTP parsing control with tokio-rustls TLS support
  - Detection of CL.0, 0.CL, TE.CL, Double-Desync, and cutting-edge request smuggling variants
  - Multiple output formats (JSON, JSONL, HTML, TXT) with comprehensive vulnerability evidence
- **Enhanced Safety and Authorization**: Enterprise-ready security controls for production environments
  - **--i-have-authorization Flag**: Explicit authorization mechanism for responsible security testing
  - **Circuit Breaker Patterns**: Automatic protection against service disruption with intelligent backoff
  - **Enhanced Input Validation**: Comprehensive target validation with domain reputation checks
  - Interactive authorization prompts with detailed risk warnings
  - Target safety validation with automatic detection of major infrastructure domains
  - Production-safe scanning modes with conservative rate limiting and timeouts
- **Enhanced Output Formatting**: Improved readable output with visual separators and color-coded status indicators
  - Visual dividers between scan results for better readability
  - Color-coded status indicators (`[OK]`, `[ERR]`, `[!]`, `[X]`, etc.)
  - Hierarchical technology detection display with clear organization
  - Enhanced scan summary with comprehensive detection summary line
- **Smart Compact Mode**: New `-c/--short` flag with intelligent summary display
  - Compact one-line output format for cleaner terminal display
  - Smart summary logic: shows summary only for multiple targets in short mode
  - Backward compatible `--compact` flag maintained for existing workflows
- **Enhanced X-Frame-Options Analysis**: Comprehensive clickjacking protection assessment
  - Parse and validate X-Frame-Options policies (DENY, SAMEORIGIN, ALLOW-FROM)
  - Security risk assessment with clickjacking protection scoring
  - Detection of invalid/misconfigured policies with security recommendations
  - Integration with existing X-Headers infrastructure analysis
- **Enhanced X-Headers Infrastructure Detection**: Unified analysis of X-Forwarded-For, X-Backend, and X-Cache headers
  - Cloud provider detection (AWS, Google Cloud, Azure, Cloudflare, Fastly)
  - Infrastructure component classification (Load Balancer, CDN, Cache, Reverse Proxy)
  - Proxy chain analysis with security insights and hop counting
  - IP type classification (IPv4/IPv6, public/private/loopback, cloud provider ranges)
- **Advanced Plugin System Enhancements**:
  - X-Headers unified infrastructure detection plugin
  - Enhanced X-Forwarded-For plugin with comprehensive proxy analysis
  - Individual X-Backend and X-Cache detection plugins
- **Raw TCP/TLS Networking**: Low-level socket implementation for security testing
  - Direct TCP connection handling with timeout management
  - TLS 1.2/1.3 support with proper certificate validation using tokio-rustls
  - Raw HTTP request/response parsing for vulnerability detection
- Binary and library configuration in Cargo.toml
- Development dependencies for enhanced testing capabilities

### Changed
- CLI refactor to subcommands (BREAKING):
  - New `scan`, `output`, `history`, `compare`, `clean`, and `stats` subcommands
  - Scan-related flags (`-d/--detect-all`, `--content-analysis`, `--tls-analysis`, `--comprehensive-tls`, `--desync`, `--desync-safe-mode`, `--desync-target`, etc.) now live under `scan`
  - Top-level options (e.g., `-t/--timeout`, `-s/--suppress-stats`, `-w/--workers`, `-o/--output-dir`) must be placed before the subcommand
  - Deprecated `--i-have-authorization` flag removed; interactive authorization prompt is always shown in desync mode
- **Code Quality Improvements**: Fixed all clippy warnings for production-ready code quality
- **Error Handling Enhancement**: Improved error handling throughout the application with comprehensive error types
- **Performance Optimization**: Optimized request processing and memory usage for large-scale scanning
- **Security Enhancements**: Removed all source code comments for production deployment
- **CLI Interface**: Enhanced command-line options and help text
- **Network Stack**: Upgraded from high-level HTTP client to raw socket implementation
- **Plugin System Optimization**: All technology detection plugins updated to use optimized pattern matching
  - **Cloudflare Detection**: Optimized header and body pattern matching with Aho-Corasick for common strings
  - **PHP Detection**: Hybrid literal and regex matching for PHP code markers and error messages  
  - **Apache Tomcat Detection**: Separated literal patterns for Java package names and content strings
  - **WordPress Advanced Detection**: Optimized theme and content pattern detection with multi-level pattern analysis
  - **WordPress Basic Detection**: Complete plugin restructure with optimized pattern matching and enhanced test coverage
- Updated project documentation with comprehensive security warnings and usage guidelines

### Security
- **Research-Grade Security Testing**: DEF CON 33 aligned vulnerability detection capabilities
- **Enhanced Authorization Controls**: Multi-layer authorization prompts with --i-have-authorization flag for dangerous security testing
- **Target Safety Validation**: Automatic detection and warnings for major infrastructure domains with reputation checks
- **Rate Limiting**: Built-in protections against overwhelming target servers with conservative limits and circuit breaker patterns
- **Safe Mode Operation**: Production-safe scanning modes with reduced impact and intelligent timeout management
- **Legal Compliance**: Enhanced legal disclaimers and authorization requirements for responsible security testing

### Fixed
- Added 'scan' directory to .gitignore to prevent accidental commits
- Improved error handling for edge cases in HTTP parsing and TLS connections

## [0.8.0]

### Added
- Comprehensive test suite for TlsAnalyzer and HTTP integration
- Enhanced reporting capabilities with multiple output formats
- Screenshot functionality for visual reconnaissance
- Configuration improvements for better user experience

### Changed
- Updated dependencies to latest versions
- Improved error handling throughout the application

### Security
- Updated OpenSSL dependency from 0.10.70 to 0.10.72
- Updated ring dependency from 0.17.8 to 0.17.13
- Updated tokio dependency from 1.43.0 to 1.43.1

## [0.7.3]

### Added
- Robots.txt file download and analysis functionality
- Enhanced plugin system with additional detection capabilities

### Changed
- Updated package dependencies
- Improved documentation with new command options and plugin details

### Fixed
- Removed unused imports to improve code quality

## [0.7.1]

### Added
- New technology detection plugins for enhanced reconnaissance
- GitHub Actions workflow for automated build and release process

### Changed
- Updated crate dependencies for better performance and security

### Security
- Updated OpenSSL dependency from 0.10.68 to 0.10.70

## [0.7.0]

### Added
- Rate limiting functionality to control request frequency
- Enhanced plugin system with improved error handling
- Content analysis capabilities for sensitive information detection
- TLS certificate analysis features

### Changed
- Improved plugin architecture for better extensibility
- Enhanced error handling across all modules

### Fixed
- Various bug fixes and performance improvements

## [0.6.0]

### Added
- Advanced configuration options
- Multi-threaded scanning capabilities
- Progress tracking and statistics

### Changed
- Refactored HTTP functionality for better performance
- Improved command-line argument parsing

## [0.5.x]

### Added
- Plugin system for technology detection
- Statistics collection and reporting
- Progress bar for scan tracking
- Support for suppressing HTTP or HTTPS probes
- Option to suppress statistics output

### Changed
- Major refactor of HTTP functionality
- Enhanced timeout management
- Improved helper functions throughout codebase

### Fixed
- Fixed probe count calculations
- Reduced unnecessary clone operations
- Improved format macro usage

## [0.4.x]

### Added
- Simple argument parsing functionality
- Timeout management options
- Help switch and command-line option collection

### Changed
- Refactored multiple core functions
- Improved code organization and structure

## [0.3.x]

### Added
- Regular expression support for enhanced pattern matching
- Statistics structure and end-of-scan reporting

### Changed
- License updated in Cargo.toml
- Keywords updated for better discoverability
- File renaming for better organization

### Fixed
- Code cleanup and comment removal

## [0.2.0]

### Added
- Enhanced HTTP/HTTPS probing capabilities
- Basic reconnaissance features

### Changed
- Improved core functionality

## [0.1.0]

### Added
- Initial release
- Basic HTTP/HTTPS connection probing
- Simple target scanning capabilities
- Command-line interface

### Security
- Basic security considerations implemented
