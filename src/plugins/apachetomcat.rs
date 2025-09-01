// File: apachetomcat.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

pub struct ApacheTomcatPlugin;

static VERSION_PATTERNS: Lazy<Vec<(Regex, &str, u8)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"Apache Tomcat Version ([0-9]+\.[0-9]+\.[0-9]+)").unwrap(),
            "Release Notes Version",
            1,
        ),
        (
            Regex::new(r"Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)").unwrap(),
            "Server Header Version",
            2,
        ),
        (
            Regex::new(r"Apache Tomcat\/([456]\.[0-9]+\.[0-9]+)").unwrap(),
            "Error Page Version",
            2,
        ),
        (
            Regex::new(r"Tomcat\/([0-9]+\.[0-9]+)").unwrap(),
            "Abbreviated Version",
            4,
        ),
        (
            Regex::new(r"\$Id: RELEASE-NOTES[^$]*Tomcat ([0-9]+\.[0-9]+\.[0-9]+)").unwrap(),
            "CVS Version Tag",
            5,
        ),
    ]
});

// Optimized literal patterns for common Tomcat strings
static CONTENT_LITERAL_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("<title>Apache Tomcat</title>", "Default Title"),
            ("CATALINA_HOME/webapps/ROOT/index.html", "CATALINA_HOME Reference"),
            ("/manager/html", "Manager Application"),
            ("/manager/status", "Manager Application"),
            ("/manager/text", "Manager Application"),
            ("Apache Tomcat Native library", "Native Library Reference"),
            ("successful, you have correctly installed Tomcat", "Installation Success Message"),
            ("If you're seeing this, you've successfully installed Tomcat", "Default Success Page"),
        ],
        &[],
    )
});

// Complex regex patterns that need flexibility
static CONTENT_REGEX_PATTERNS: Lazy<Vec<(Regex, &str, u8)>> = Lazy::new(|| {
    vec![
        (
            RegexBuilder::new(r"<title>[^<]*tomcat[^<]*</title>")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Tomcat in Title",
            3,
        ),
    ]
});

// Confidence mapping for literal patterns
static CONTENT_LITERAL_CONFIDENCE: Lazy<std::collections::HashMap<&'static str, u8>> = Lazy::new(|| {
    [
        ("Default Title", 1u8),
        ("CATALINA_HOME Reference", 2u8),
        ("Manager Application", 2u8),
        ("Native Library Reference", 3u8),
        ("Installation Success Message", 2u8),
        ("Default Success Page", 1u8),
    ]
    .iter()
    .cloned()
    .collect()
});

// Optimized stacktrace patterns
static STACKTRACE_LITERAL_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("org.apache.catalina.", "Catalina Component"),
            ("org.apache.jasper.", "Jasper JSP Engine"),
            ("org.apache.coyote.", "Coyote Connector"),
            ("StandardServer.await", "Tomcat Server Await"),
        ],
        &[
            (r"org\.apache\.tomcat\..*java\.lang\.Thread\.run", "Tomcat Stack Trace"),
        ],
    )
});

static HEADER_PATTERNS: Lazy<Vec<(Regex, &str, u8)>> = Lazy::new(|| {
    vec![
        (
            RegexBuilder::new(r"^Apache-Coyote/")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Coyote Connector",
            1,
        ),
        (
            RegexBuilder::new(r"Apache-Coyote/([0-9]+\.[0-9]+)")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Coyote Version",
            1,
        ),
        (
            RegexBuilder::new(r"^Apache/[0-9]+\.[0-9]+\.[0-9]+ \(.*Tomcat.*\)")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Apache with Tomcat",
            2,
        ),
        (
            RegexBuilder::new(r"Servlet/[0-9]+\.[0-9]+")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Servlet API Version",
            4,
        ),
    ]
});

static ERROR_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"HTTP Status [0-9]+ - .*type Status report").unwrap(),
            "Tomcat Error Page Format",
        ),
        (
            Regex::new(r"message.*description.*Apache Tomcat").unwrap(),
            "Tomcat Error Description",
        ),
        (
            Regex::new(r"<h3>Apache Tomcat/[0-9]+\.[0-9]+\.[0-9]+</h3>").unwrap(),
            "Error Page Footer",
        ),
    ]
});

#[derive(Debug, Clone)]
struct TomcatDetection {
    signature: String,
    confidence: u8,
    version: Option<String>,
    evidence_type: EvidenceType,
}

#[derive(Debug, Clone)]
enum EvidenceType {
    Version,
    Content,
    Header,
    StackTrace,
    ErrorPage,
}

impl ApacheTomcatPlugin {
    fn extract_version_info(&self, content: &str) -> Vec<TomcatDetection> {
        let mut detections = Vec::new();

        for (pattern, signature, confidence) in VERSION_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(content) {
                if let Some(version_match) = captures.get(1) {
                    debug!(
                        "Version detected: {} via {}",
                        version_match.as_str(),
                        signature
                    );
                    detections.push(TomcatDetection {
                        signature: signature.to_string(),
                        confidence: *confidence,
                        version: Some(version_match.as_str().to_string()),
                        evidence_type: EvidenceType::Version,
                    });
                }
            }
        }

        detections
    }

    fn analyze_content(&self, content: &str) -> Vec<TomcatDetection> {
        let mut detections = Vec::new();

        // Check literal patterns first (fast Aho-Corasick)
        let literal_matches = CONTENT_LITERAL_PATTERNS.find_matches(content);
        for signature in literal_matches {
            debug!("Content literal pattern matched: {}", signature);
            let confidence = CONTENT_LITERAL_CONFIDENCE.get(signature).copied().unwrap_or(1);
            detections.push(TomcatDetection {
                signature: signature.to_string(),
                confidence,
                version: None,
                evidence_type: EvidenceType::Content,
            });
        }

        // Check complex regex patterns
        for (pattern, signature, confidence) in CONTENT_REGEX_PATTERNS.iter() {
            if pattern.is_match(content) {
                debug!("Content regex pattern matched: {}", signature);
                detections.push(TomcatDetection {
                    signature: signature.to_string(),
                    confidence: *confidence,
                    version: None,
                    evidence_type: EvidenceType::Content,
                });
            }
        }

        detections
    }

    fn analyze_stack_traces(&self, content: &str) -> Vec<TomcatDetection> {
        let mut detections = Vec::new();

        // Use optimized pattern matcher for stack traces
        let matches = STACKTRACE_LITERAL_PATTERNS.find_matches(content);
        for signature in matches {
            debug!("Stack trace pattern matched: {}", signature);
            detections.push(TomcatDetection {
                signature: signature.to_string(),
                confidence: 3,
                version: None,
                evidence_type: EvidenceType::StackTrace,
            });
        }

        detections
    }

    fn analyze_headers(&self, headers: &reqwest::header::HeaderMap) -> Vec<TomcatDetection> {
        let mut detections = Vec::new();

        if let Some(server_value) = headers.get("server") {
            if let Ok(server_str) = server_value.to_str() {
                for (pattern, signature, confidence) in HEADER_PATTERNS.iter() {
                    if pattern.is_match(server_str) {
                        debug!("Header pattern matched: {} in {}", signature, server_str);
                        detections.push(TomcatDetection {
                            signature: signature.to_string(),
                            confidence: *confidence,
                            version: None,
                            evidence_type: EvidenceType::Header,
                        });
                    }
                }
            }
        }

        if let Some(powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("servlet")
                    || powered_str.to_lowercase().contains("jsp")
                {
                    debug!(
                        "X-Powered-By indicates Java servlet environment: {}",
                        powered_str
                    );
                    detections.push(TomcatDetection {
                        signature: "X-Powered-By Servlet/JSP".to_string(),
                        confidence: 4,
                        version: None,
                        evidence_type: EvidenceType::Header,
                    });
                }
            }
        }

        detections
    }

    fn analyze_error_patterns(&self, content: &str, status: u16) -> Vec<TomcatDetection> {
        let mut detections = Vec::new();

        if status >= 400 {
            for (pattern, signature) in ERROR_PATTERNS.iter() {
                if pattern.is_match(content) {
                    debug!("Error page pattern matched: {}", signature);
                    detections.push(TomcatDetection {
                        signature: signature.to_string(),
                        confidence: 2,
                        version: None,
                        evidence_type: EvidenceType::ErrorPage,
                    });
                }
            }
        }

        detections
    }

    fn calculate_confidence(&self, detections: &[TomcatDetection]) -> u8 {
        if detections.is_empty() {
            return 0;
        }

        let weighted_sum: f32 = detections
            .iter()
            .map(|d| {
                let type_weight = match d.evidence_type {
                    EvidenceType::Version => 2.0,
                    EvidenceType::Header => 1.5,
                    EvidenceType::Content => 1.2,
                    EvidenceType::ErrorPage => 1.0,
                    EvidenceType::StackTrace => 0.8,
                };
                (10 - d.confidence) as f32 * type_weight
            })
            .sum();

        let max_possible = detections.len() as f32 * 10.0 * 2.0;
        let confidence_ratio = weighted_sum / max_possible;

        ((confidence_ratio * 9.0) + 1.0).round() as u8
    }

    fn format_detection_result(
        &self,
        detections: Vec<TomcatDetection>,
    ) -> (String, u8, Option<String>) {
        let confidence = self.calculate_confidence(&detections);

        let version = detections
            .iter()
            .filter_map(|d| d.version.as_ref())
            .min_by_key(|version_str| {
                detections
                    .iter()
                    .find(|det| det.version.as_ref() == Some(version_str))
                    .map(|det| det.confidence)
                    .unwrap_or(10)
            })
            .cloned();

        let content_sigs: Vec<_> = detections
            .iter()
            .filter(|d| matches!(d.evidence_type, EvidenceType::Content))
            .map(|d| d.signature.as_str())
            .collect();

        let header_sigs: Vec<_> = detections
            .iter()
            .filter(|d| matches!(d.evidence_type, EvidenceType::Header))
            .map(|d| d.signature.as_str())
            .collect();

        let mut result_parts = Vec::new();

        if let Some(ref ver) = version {
            result_parts.push(format!("v{}", ver));
        }

        if !content_sigs.is_empty() {
            result_parts.push(format!("Content[{}]", content_sigs.join(", ")));
        }

        if !header_sigs.is_empty() {
            result_parts.push(format!("Headers[{}]", header_sigs.join(", ")));
        }

        let evidence_count = detections.len();
        let detection_info = format!(
            "Apache Tomcat ({} evidence points) - {}",
            evidence_count,
            result_parts.join(" | ")
        );

        info!(
            "Tomcat detection completed: {} (confidence: {}/10)",
            detection_info, confidence
        );
        (detection_info, confidence, version)
    }
}

impl Plugin for ApacheTomcatPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Apache Tomcat",
            version: "2.1.0",
            description: "Apache Tomcat Java application server detection with version identification and comprehensive fingerprinting",
            category: PluginCategory::JavaApplicationServer,
            author: "rprobe team",
            priority: 2,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        let headers = http_inner.headers();

        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                let server_lower = server_str.to_lowercase();
                if server_lower.contains("apache-coyote") || server_lower.contains("tomcat") {
                    return true;
                }
            }
        }

        if let Some(powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                let powered_lower = powered_str.to_lowercase();
                if powered_lower.contains("servlet") || powered_lower.contains("jsp") {
                    return true;
                }
            }
        }

        let status = http_inner.status();
        if (400..600).contains(&status) {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!(
            "Starting Apache Tomcat detection for URL: {}",
            http_inner.url()
        );

        let mut all_detections = Vec::new();
        let headers = http_inner.headers();
        let body = http_inner.body();
        let status = http_inner.status();

        all_detections.extend(self.extract_version_info(body));
        all_detections.extend(self.analyze_content(body));
        all_detections.extend(self.analyze_stack_traces(body));
        all_detections.extend(self.analyze_headers(headers));
        all_detections.extend(self.analyze_error_patterns(body, status));

        if all_detections.is_empty() {
            debug!("No Tomcat detection for URL: {}", http_inner.url());
            return Ok(None);
        }

        let (detection_info, confidence, _version) = self.format_detection_result(all_detections);

        if confidence < 3 {
            debug!(
                "Tomcat detection confidence too low ({}/10) for URL: {}",
                confidence,
                http_inner.url()
            );
            return Ok(None);
        }

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence,
            execution_time_ms: 0,
            category: PluginCategory::JavaApplicationServer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn create_test_http_inner(body: &str, headers: HeaderMap, status: u16) -> HttpInner {
        HttpInner::new_with_all(
            headers,
            body.to_string(),
            status,
            "https://example.com".to_string(),
            status < 400,
        )
    }

    #[test]
    fn test_version_extraction() {
        let plugin = ApacheTomcatPlugin;
        let content = "Apache Tomcat Version 9.0.65";
        let detections = plugin.extract_version_info(content);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].version, Some("9.0.65".to_string()));
        assert_eq!(detections[0].signature, "Release Notes Version");
    }

    #[test]
    fn test_content_analysis() {
        let plugin = ApacheTomcatPlugin;
        let content = "<title>Apache Tomcat</title>";
        let detections = plugin.analyze_content(content);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].signature, "Default Title");
        assert_eq!(detections[0].confidence, 1);
    }

    #[test]
    fn test_header_analysis() {
        let plugin = ApacheTomcatPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Apache-Coyote/1.1"));

        let detections = plugin.analyze_headers(&headers);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.signature.contains("Coyote")));
    }

    #[test]
    fn test_stack_trace_analysis() {
        let plugin = ApacheTomcatPlugin;
        let content = "org.apache.catalina.core.StandardWrapper.invoke";
        let detections = plugin.analyze_stack_traces(content);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].signature, "Catalina Component");
    }

    #[test]
    fn test_full_detection() {
        let plugin = ApacheTomcatPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Apache-Coyote/1.1"));

        let body = "<title>Apache Tomcat</title><p>Apache Tomcat Version 9.0.65</p>";
        let http_inner = create_test_http_inner(body, headers, 200);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache Tomcat"));
        assert!(plugin_result.detection_info.contains("v9.0.65"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_error_page_detection() {
        let plugin = ApacheTomcatPlugin;
        let content = "HTTP Status 404 - type Status report";
        let detections = plugin.analyze_error_patterns(content, 404);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].signature, "Tomcat Error Page Format");
    }

    #[test]
    fn test_confidence_calculation() {
        let plugin = ApacheTomcatPlugin;
        let detections = vec![
            TomcatDetection {
                signature: "Test".to_string(),
                confidence: 1,
                version: None,
                evidence_type: EvidenceType::Version,
            },
            TomcatDetection {
                signature: "Test2".to_string(),
                confidence: 2,
                version: None,
                evidence_type: EvidenceType::Header,
            },
        ];

        let confidence = plugin.calculate_confidence(&detections);
        assert!(confidence > 0 && confidence <= 10);
    }

    #[test]
    fn test_format_detection_result() {
        let plugin = ApacheTomcatPlugin;
        let detections = vec![
            TomcatDetection {
                signature: "Default Title".to_string(),
                confidence: 1,
                version: Some("9.0.65".to_string()),
                evidence_type: EvidenceType::Content,
            },
            TomcatDetection {
                signature: "Coyote Connector".to_string(),
                confidence: 1,
                version: None,
                evidence_type: EvidenceType::Header,
            },
        ];

        let (detection_info, confidence, version) = plugin.format_detection_result(detections);
        assert!(detection_info.contains("v9.0.65"));
        assert!(detection_info.contains("evidence points"));
        assert!(confidence > 5);
        assert_eq!(version, Some("9.0.65".to_string()));
    }
}
