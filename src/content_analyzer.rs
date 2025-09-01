// File: content_analyzer.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use log::{debug, info, trace};
use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentFinding {
    pub category: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub matched_text: Option<String>,
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "Info"),
            FindingSeverity::Low => write!(f, "Low"),
            FindingSeverity::Medium => write!(f, "Medium"),
            FindingSeverity::High => write!(f, "High"),
            FindingSeverity::Critical => write!(f, "Critical"),
        }
    }
}

struct PatternMatcher {
    pattern_set: RegexSet,
    patterns: Vec<(Regex, &'static str, &'static str, FindingSeverity)>,
}

impl PatternMatcher {
    fn new(pattern_data: &[(&'static str, &'static str, &'static str, FindingSeverity)]) -> Self {
        let pattern_strings: Vec<&str> = pattern_data.iter().map(|(pattern, _, _, _)| *pattern).collect();
        let pattern_set = RegexSet::new(&pattern_strings).unwrap();
        let patterns = pattern_data
            .iter()
            .map(|(pattern, category, description, severity)| {
                (Regex::new(pattern).unwrap(), *category, *description, severity.clone())
            })
            .collect();
        
        Self { pattern_set, patterns }
    }
}


static SENSITIVE_PATTERNS: Lazy<PatternMatcher> = Lazy::new(|| {
    PatternMatcher::new(&[
        (
            r#"(?i)api[_\s-]*key[_\s-]*[:=]\s*['"](\w-]{10,})['"]\\b"#,
            "API Key",
            "Potential API key found in page content",
            FindingSeverity::High,
        ),
        (
            r"(?i)AKIA[0-9A-Z]{16}",
            "AWS Access Key",
            "Potential AWS access key found",
            FindingSeverity::Critical,
        ),
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Email Address",
            "Email address found",
            FindingSeverity::Low,
        ),
        (
            r#"(?i)auth[_\-\s]*token[_\-\s]*[:=]\s*(?:'|")([\\w\-\\.]+)(?:'|")"#,
            "Auth Token",
            "Authentication token found in page content",
            FindingSeverity::High,
        ),
        (
            r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
            "Private Key",
            "Private key found in page content",
            FindingSeverity::Critical,
        ),
        (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "SSN",
            "Potential US Social Security Number found",
            FindingSeverity::Critical,
        ),
        (
            r"\b(?:\d{4}[- ]?){3}\d{4}\b",
            "Credit Card",
            "Potential credit card number found",
            FindingSeverity::Critical,
        ),
        (
            r"(?i)(?:mongodb|mysql|postgresql|jdbc)://\S+",
            "DB Connection String",
            "Database connection string found",
            FindingSeverity::High,
        ),
        (
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "Internal IP",
            "Internal IP address found",
            FindingSeverity::Medium,
        ),
        (
            r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            "JWT Token",
            "JSON Web Token found",
            FindingSeverity::High,
        ),
        (
            r"github_pat_[a-zA-Z0-9_]{59}",
            "GitHub PAT",
            "GitHub Personal Access Token found",
            FindingSeverity::Critical,
        ),
    ])
});

static SECURITY_ISSUES: Lazy<PatternMatcher> = Lazy::new(|| {
    PatternMatcher::new(&[
        (
            r"(?i)(sql\s+syntax|sql\s+error|ORA-\d{5}|mysql_fetch|pg_exec|Uncaught\s+exception)",
            "Error Disclosure",
            "Application error message found that may disclose sensitive information",
            FindingSeverity::Medium,
        ),
        (
            r"(?i)<meta.*Content-Security-Policy", 
            "CSP Header",
            "Content Security Policy header found in HTML meta tag",
            FindingSeverity::Info,
        ),
        (
            r"(?i)<!--\s*(todo|fixme|xxx|debug|remove\s+in\s+prod|to\sbe\sremoved)",
            "Debug Comment",
            "Developer comment found that may reveal implementation details",
            FindingSeverity::Low,
        ),
        (
            r"<title>Index of /",
            "Directory Listing",
            "Directory listing is enabled",
            FindingSeverity::Medium,
        ),
    ])
});

static CONFIG_ISSUES: Lazy<PatternMatcher> = Lazy::new(|| {
    PatternMatcher::new(&[
        (
            r"(?i)(default\s+username|default\s+password|admin/admin|username\s*[:=]\s*admin|password\s*[:=]\s*admin)",
            "Default Credentials",
            "Reference to default credentials found",
            FindingSeverity::High,
        ),
        (
            r"(?i)(debug\s*[:=]\s*true|development\s*[:=]\s*true|env\s*[:=]\s*dev)",
            "Debug Mode",
            "Application may be running in debug or development mode",
            FindingSeverity::Medium,
        ),
    ])
});

fn extract_context(content: &str, start: usize, end: usize, context_size: usize) -> String {
    let content_len = content.len();

    let context_start = start.saturating_sub(context_size);

    let context_end = if end + context_size > content_len {
        content_len
    } else {
        end + context_size
    };

    if let Some(slice) = content.get(context_start..context_end) {
        let prefix = if context_start > 0 { "..." } else { "" };
        let suffix = if context_end < content_len { "..." } else { "" };
        format!("{prefix}{slice}{suffix}")
    } else {
        "Context extraction failed".to_string()
    }
}

pub struct ContentAnalyzer;

impl ContentAnalyzer {
    pub fn analyze(http_inner: &HttpInner) -> Vec<ContentFinding> {
        let mut findings = Vec::new();

        if !http_inner.success() {
            trace!(
                "Skipping content analysis for failed request: {}",
                http_inner.url()
            );
            return findings;
        }

        let content = http_inner.body();
        debug!(
            "Starting content analysis for {} ({} bytes)",
            http_inner.url(),
            content.len(),
        );

        if content.len() > 5_000_000 {
            debug!(
                "Content too large for analysis: {} bytes (limit: 5MB)",
                content.len()
            );
            findings.push(ContentFinding {
                category: "Analysis Limit".to_string(),
                description: format!(
                    "Content size ({} bytes) exceeds analysis limit",
                    content.len()
                ),
                severity: FindingSeverity::Info,
                matched_text: None,
                context: None,
            });
            return findings;
        }

        // Use RegexSet for parallel pattern matching
        let sensitive_matches = SENSITIVE_PATTERNS.pattern_set.matches(content);
        for match_idx in sensitive_matches {
            let (pattern, category, description, severity) = &SENSITIVE_PATTERNS.patterns[match_idx];
            trace!("Checking pattern for '{}' category", category);

            for capture in pattern.captures_iter(content) {
                if let Some(m) = capture.get(0) {
                    let match_text = m.as_str();
                    debug!(
                        "Found {} match: {} characters at position {}",
                        category,
                        match_text.len(),
                        m.start()
                    );

                    let matched_text = if severity == &FindingSeverity::Critical {
                        let text = m.as_str();
                        if text.len() > 8 {
                            let masked = format!("{}****{}", &text[0..4], &text[text.len() - 4..]);
                            trace!("Masked critical finding: {} -> {}", text, masked);
                            masked
                        } else {
                            "****".to_string()
                        }
                    } else {
                        match_text.to_string()
                    };

                    let context = extract_context(content, m.start(), m.end(), 30);
                    trace!("Context extracted: {}", context);

                    findings.push(ContentFinding {
                        category: category.to_string(),
                        description: description.to_string(),
                        severity: severity.clone(),
                        matched_text: Some(matched_text),
                        context: Some(context),
                    });

                    info!(
                        "Found {} in {}: {}",
                        category,
                        http_inner.url(),
                        description
                    );
                }
            }
        }

        // Use RegexSet for security issues
        debug!("Checking security issue patterns");
        let security_matches = SECURITY_ISSUES.pattern_set.matches(content);
        for match_idx in security_matches {
            let (pattern, category, description, severity) = &SECURITY_ISSUES.patterns[match_idx];
            trace!("Checking security issue pattern for '{}' category", category);

            for capture in pattern.captures_iter(content) {
                if let Some(m) = capture.get(0) {
                    debug!(
                        "Found security issue {}: {} characters at position {}",
                        category,
                        m.as_str().len(),
                        m.start()
                    );

                    let context = extract_context(content, m.start(), m.end(), 40);

                    findings.push(ContentFinding {
                        category: category.to_string(),
                        description: description.to_string(),
                        severity: severity.clone(),
                        matched_text: Some(m.as_str().to_string()),
                        context: Some(context),
                    });

                    info!(
                        "Found {} in {}: {}",
                        category,
                        http_inner.url(),
                        description
                    );
                }
            }
        }

        // Use RegexSet for configuration issues
        debug!("Checking configuration issue patterns");
        let config_matches = CONFIG_ISSUES.pattern_set.matches(content);
        for match_idx in config_matches {
            let (pattern, category, description, severity) = &CONFIG_ISSUES.patterns[match_idx];
            trace!("Checking configuration issue pattern for '{}' category", category);

            for capture in pattern.captures_iter(content) {
                if let Some(m) = capture.get(0) {
                    debug!(
                        "Found config issue {}: {} characters at position {}",
                        category,
                        m.as_str().len(),
                        m.start()
                    );

                    let context = extract_context(content, m.start(), m.end(), 40);

                    findings.push(ContentFinding {
                        category: category.to_string(),
                        description: description.to_string(),
                        severity: severity.clone(),
                        matched_text: Some(m.as_str().to_string()),
                        context: Some(context),
                    });

                    info!(
                        "Found {} in {}: {}",
                        category,
                        http_inner.url(),
                        description
                    );
                }
            }
        }

        debug!("Content analysis completed for {}: {} findings (Critical={}, High={}, Medium={}, Low={}, Info={})", 
               http_inner.url(),
               findings.len(),
               findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count(),
               findings.iter().filter(|f| f.severity == FindingSeverity::High).count(),
               findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count(),
               findings.iter().filter(|f| f.severity == FindingSeverity::Low).count(),
               findings.iter().filter(|f| f.severity == FindingSeverity::Info).count());

        findings
    }

    pub fn analyze_forms(http_inner: &HttpInner) -> Vec<ContentFinding> {
        debug!("Starting form analysis for: {}", http_inner.url());
        let mut findings = Vec::new();

        if !http_inner.success() {
            return findings;
        }

        let content = http_inner.body();

        let form_regex = Regex::new(r"<form[^>]*>(?s)(.*?)</form>").unwrap();
        let csrf_regex = Regex::new(r"(?i)(csrf|token|nonce)").unwrap();

        for capture in form_regex.captures_iter(content) {
            if let Some(form) = capture.get(0) {
                let form_content = form.as_str();

                if !form_content.contains("action=") {
                    findings.push(ContentFinding {
                        category: "Form Security".to_string(),
                        description: "Form missing action attribute".to_string(),
                        severity: FindingSeverity::Low,
                        matched_text: Some(form_content[0..50].to_string() + "..."),
                        context: None,
                    });
                }

                if !form_content.contains(r#"method="post""#)
                    && !form_content.contains(r#"method='post'"#)
                {
                    findings.push(ContentFinding {
                        category: "Form Security".to_string(),
                        description: "Form not using POST method".to_string(),
                        severity: FindingSeverity::Low,
                        matched_text: Some(form_content[0..50].to_string() + "..."),
                        context: None,
                    });
                }

                if !csrf_regex.is_match(form_content) {
                    findings.push(ContentFinding {
                        category: "Form Security".to_string(),
                        description: "Form may lack CSRF protection".to_string(),
                        severity: FindingSeverity::Medium,
                        matched_text: Some(form_content[0..50].to_string() + "..."),
                        context: None,
                    });
                }

                if form_content.contains("type=\"password\"")
                    && !form_content.contains("autocomplete=\"off\"")
                {
                    findings.push(ContentFinding {
                        category: "Form Security".to_string(),
                        description: "Password field without autocomplete protection".to_string(),
                        severity: FindingSeverity::Low,
                        matched_text: Some(form_content[0..50].to_string() + "..."),
                        context: None,
                    });
                }
            }
        }

        findings
    }

    pub fn analyze_javascript(http_inner: &HttpInner) -> Vec<ContentFinding> {
        debug!("Starting JavaScript analysis for: {}", http_inner.url());
        let mut findings = Vec::new();

        if !http_inner.success() {
            trace!(
                "Skipping JavaScript analysis for failed request: {}",
                http_inner.url()
            );
            return findings;
        }

        let content = http_inner.body();

        let js_regex = Regex::new(r"<script[^>]*>(?s)(.*?)</script>").unwrap();
        let mut js_content = String::new();
        let mut script_blocks = 0;

        for capture in js_regex.captures_iter(content) {
            if let Some(script) = capture.get(1) {
                script_blocks += 1;
                js_content.push_str(script.as_str());
                js_content.push('\n');
            }
        }

        if js_content.is_empty() {
            trace!("No JavaScript found in: {}", http_inner.url());
            return findings;
        }

        debug!(
            "Found {} script blocks with {} total characters",
            script_blocks,
            js_content.len()
        );

        let eval_regex = Regex::new(r"eval\s*\(").unwrap();
        if eval_regex.is_match(&js_content) {
            debug!("JavaScript security issue found: eval() usage detected");
            findings.push(ContentFinding {
                category: "JavaScript Security".to_string(),
                description: "Use of eval() detected, which may lead to code injection".to_string(),
                severity: FindingSeverity::Medium,
                matched_text: Some("eval(...)".to_string()),
                context: None,
            });
        }

        let event_regex = Regex::new(r"on(click|load|mouseover|error|keyup|change)=").unwrap();
        for capture in event_regex.captures_iter(content) {
            if let Some(m) = capture.get(0) {
                debug!(
                    "JavaScript security issue found: inline event handler {}",
                    m.as_str()
                );
                findings.push(ContentFinding {
                    category: "JavaScript Security".to_string(),
                    description:
                        "Inline event handler detected, consider separating JavaScript from HTML"
                            .to_string(),
                    severity: FindingSeverity::Low,
                    matched_text: Some(m.as_str().to_string()),
                    context: None,
                });
                break;
            }
        }

        let storage_regex = Regex::new(r"(localStorage|sessionStorage)\.setItem\s*\(").unwrap();
        if storage_regex.is_match(&js_content) {
            debug!("JavaScript security issue found: Web Storage usage detected");
            findings.push(ContentFinding {
                category: "JavaScript Security".to_string(),
                description: "Web Storage (localStorage/sessionStorage) usage detected, ensure sensitive data is not stored".to_string(),
                severity: FindingSeverity::Info,
                matched_text: None,
                context: None,
            });
        }

        let doc_write_regex = Regex::new(r"document\.write\s*\(").unwrap();
        if doc_write_regex.is_match(&js_content) {
            debug!("JavaScript security issue found: document.write() usage detected");
            findings.push(ContentFinding {
                category: "JavaScript Security".to_string(),
                description: "Use of document.write() detected, which can enable XSS attacks"
                    .to_string(),
                severity: FindingSeverity::Medium,
                matched_text: Some("document.write(...)".to_string()),
                context: None,
            });
        }

        debug!(
            "JavaScript analysis completed for {}: {} findings",
            http_inner.url(),
            findings.len()
        );
        findings
    }
}

#[cfg(test)]
#[path = "content_analyzer_tests.rs"]
mod tests;
