// File: wordpress_advanced.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Instant;

pub struct WordPressAdvancedPlugin;

static VERSION_PATTERNS: Lazy<Vec<(Regex, &str, u8)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(
                r#"<meta name=\"generator\" content=\"WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#,
            )
            .unwrap(),
            "Meta Generator Version",
            1,
        ),
        (
            Regex::new(r#"wp-includes/[^\"']*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#).unwrap(),
            "Asset Version Parameter",
            2,
        ),
        (
            Regex::new(r"/wp-json/wp/v([0-9]+)/").unwrap(),
            "REST API Version",
            2,
        ),
        (
            Regex::new(r#"WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#).unwrap(),
            "Generic Version Reference",
            4,
        ),
        (
            Regex::new(r"readme\.html.*WordPress.*Version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)").unwrap(),
            "Readme Version",
            3,
        ),
    ]
});

// Optimized content patterns - separate literal and regex patterns
static CONTENT_LITERAL_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("/wp-content/", "WP-Content Directory"),
            ("/wp-includes/", "WP-Includes Directory"),
            ("/wp-admin/", "WP-Admin Directory"),
            ("/wp-json/", "REST API Endpoint"),
            ("wp_enqueue_script", "WordPress Enqueue Functions"),
            ("wp_enqueue_style", "WordPress Enqueue Functions"),
            ("wp_head()", "WordPress Hook Functions"),
            ("wp_footer()", "WordPress Hook Functions"),
            ("xmlrpc.php", "XML-RPC EditURI Link"),
        ],
        &[
            (r#"<meta name="generator" content="WordPress(?:\.com)?""#, "Meta Generator Tag"),
            (r#"<link rel=['"]https://api\.w\.org/['"]"#, "WordPress REST API Link"),
            (r#"/wp-json/wp/v[0-9]+/"#, "REST API Endpoint"),
            (r#"(?:class|id)=['"](?:wp-|wordpress)[^'"]*['"]"#, "WordPress CSS Classes/IDs"),
            (r#"themes/[^/]+/(?:style\.css|screenshot\.png)"#, "Theme Assets"),
            (r#"plugins/[^/]+/"#, "Plugin Directory"),
            (r#"<link[^>]*rel=['"]EditURI['"][^>]*xmlrpc\.php"#, "XML-RPC EditURI Link"),
            (r#"<link[^>]*rel=['"]wlwmanifest['"]"#, "Windows Live Writer Manifest"),
            (r#"<body[^>]*class=['"][^'"]*(?:wordpress|wp-)[^'"]*['"]"#, "WordPress Body Classes"),
        ],
    )
});

// Confidence mapping for content patterns
static CONTENT_CONFIDENCE: Lazy<std::collections::HashMap<&'static str, u8>> = Lazy::new(|| {
    [
        ("Meta Generator Tag", 1u8),
        ("WordPress REST API Link", 1u8),
        ("REST API Endpoint", 1u8),
        ("WP-Content Directory", 2u8),
        ("WP-Includes Directory", 2u8),
        ("WP-Admin Directory", 3u8),
        ("WordPress CSS Classes/IDs", 3u8),
        ("WordPress Enqueue Functions", 2u8),
        ("WordPress Hook Functions", 2u8),
        ("Theme Assets", 3u8),
        ("Plugin Directory", 3u8),
        ("XML-RPC EditURI Link", 2u8),
        ("Windows Live Writer Manifest", 3u8),
        ("WordPress Body Classes", 2u8),
    ]
    .iter()
    .cloned()
    .collect()
});

static LOGIN_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r#"<title>[^<]*Log In"#).unwrap(),
            "Login Page Title",
        ),
        (
            Regex::new(r#"action=['\"].*wp-login\\.php['\"]"#).unwrap(),
            "Login Form Action",
        ),
        (
            Regex::new(r#"name=['\"]log['\"][^>]*placeholder=['\"][^'\"]*(?:Username|Email)"#)
                .unwrap(),
            "Login Username Field",
        ),
        (
            Regex::new(r#"Powered by WordPress"#).unwrap(),
            "Powered By Link",
        ),
        (
            Regex::new(r#"action=(?:lostpassword|retrievepassword)"#).unwrap(),
            "Password Recovery Action",
        ),
    ]
});

static SECURITY_PATTERNS: Lazy<Vec<(Regex, &str, u8)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"wp-config\.php").unwrap(),
            "Configuration File Reference",
            5,
        ),
        (
            Regex::new(r"wp_nonce_field").unwrap(),
            "WordPress Nonce Implementation",
            2,
        ),
        (
            Regex::new(r#"define\s*\(\s*['\"]\w+['\"]\s*,"#).unwrap(),
            "WordPress Constants",
            4,
        ),
    ]
});

// Optimized theme patterns - literal strings first, complex patterns in regex
static THEME_LITERAL_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("themes/twentytwentyfour", "Twenty Twenty-Four Theme"),
            ("themes/twentytwentythree", "Twenty Twenty-Three Theme"),
            ("themes/twentytwentytwo", "Twenty Twenty-Two Theme"),
            ("themes/twentytwentyone", "Twenty Twenty-One Theme"),
            ("themes/twentytwenty", "Twenty Twenty Theme"),
            ("themes/twentynineteen", "Twenty Nineteen Theme"),
        ],
        &[
            (r"themes/(?:twenty)?(?:ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen)", "Classic Twenty Theme"),
            (r"Theme Name:\s*([^\r\n]+)", "Theme Header Comment"),
        ],
    )
});

static PLUGIN_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"plugins/akismet").unwrap(), "Akismet Anti-Spam"),
        (Regex::new(r"plugins/yoast-seo").unwrap(), "Yoast SEO"),
        (
            Regex::new(r"plugins/elementor").unwrap(),
            "Elementor Page Builder",
        ),
        (Regex::new(r"plugins/woocommerce").unwrap(), "WooCommerce"),
        (
            Regex::new(r"plugins/contact-form-7").unwrap(),
            "Contact Form 7",
        ),
        (
            Regex::new(r"plugins/wordfence").unwrap(),
            "Wordfence Security",
        ),
        (Regex::new(r"plugins/jetpack").unwrap(), "Jetpack"),
        (
            Regex::new(r"Plugin Name:\s*([^\r\n]+)").unwrap(),
            "Plugin Header Comment",
        ),
    ]
});

#[derive(Debug, Clone)]
struct WordPressDetection {
    signature: String,
    confidence: u8,
    version: Option<String>,
    evidence_type: EvidenceType,
    additional_info: Option<String>,
}

#[derive(Debug, Clone)]
enum EvidenceType {
    Version,
    Content,
    Login,
    Theme,
    Plugin,
    Security,
    Api,
}

impl WordPressAdvancedPlugin {
    fn extract_version_info(&self, content: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();

        for (pattern, signature, confidence) in VERSION_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(content) {
                if let Some(version_match) = captures.get(1) {
                    let version_str = version_match.as_str();

                    debug!(
                        "WordPress version detected: {} via {}",
                        version_str, signature
                    );

                    detections.push(WordPressDetection {
                        signature: signature.to_string(),
                        confidence: *confidence,
                        version: Some(version_str.to_string()),
                        evidence_type: EvidenceType::Version,
                        additional_info: None,
                    });
                }
            }
        }

        detections
    }

    fn analyze_content(&self, content: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();

        // Use optimized pattern matcher for content analysis
        let matches = CONTENT_LITERAL_PATTERNS.find_matches(content);
        for signature in matches {
            debug!("WordPress content pattern matched: {}", signature);
            let confidence = CONTENT_CONFIDENCE.get(signature).copied().unwrap_or(1);
            
            detections.push(WordPressDetection {
                signature: signature.to_string(),
                confidence,
                version: None,
                evidence_type: EvidenceType::Content,
                additional_info: None,
            });
        }

        detections
    }

    fn analyze_login_patterns(&self, content: &str, url: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();

        if url.contains("wp-login") || url.contains("wp-admin") {
            for (pattern, signature) in LOGIN_PATTERNS.iter() {
                if pattern.is_match(content) {
                    debug!("WordPress login pattern matched: {}", signature);

                    detections.push(WordPressDetection {
                        signature: signature.to_string(),
                        confidence: 1,
                        version: None,
                        evidence_type: EvidenceType::Login,
                        additional_info: Some("Login page detected".to_string()),
                    });
                }
            }
        }

        detections
    }

    fn analyze_themes(&self, content: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();
        let mut detected_themes = Vec::new();

        // Use optimized theme pattern matcher
        let matches = THEME_LITERAL_PATTERNS.find_matches(content);
        for signature in matches {
            let theme_info = signature.to_string();

            if !detected_themes.contains(&theme_info) {
                debug!("WordPress theme detected: {}", theme_info);

                detected_themes.push(theme_info.clone());
                detections.push(WordPressDetection {
                    signature: "Theme Detection".to_string(),
                    confidence: 2,
                    version: None,
                    evidence_type: EvidenceType::Theme,
                    additional_info: Some(theme_info),
                });
            }
        }

        detections
    }

    fn analyze_plugins(&self, content: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();
        let mut detected_plugins = Vec::new();

        for (pattern, signature) in PLUGIN_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(content) {
                let plugin_info = if let Some(plugin_match) = captures.get(1) {
                    plugin_match.as_str().to_string()
                } else {
                    signature.to_string()
                };

                if !detected_plugins.contains(&plugin_info) {
                    debug!("WordPress plugin detected: {}", plugin_info);

                    detected_plugins.push(plugin_info.clone());
                    detections.push(WordPressDetection {
                        signature: "Plugin Detection".to_string(),
                        confidence: 3,
                        version: None,
                        evidence_type: EvidenceType::Plugin,
                        additional_info: Some(plugin_info),
                    });
                }
            }
        }

        detections
    }

    fn analyze_security_patterns(&self, content: &str) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();

        for (pattern, signature, confidence) in SECURITY_PATTERNS.iter() {
            if pattern.is_match(content) {
                debug!("WordPress security pattern matched: {}", signature);

                detections.push(WordPressDetection {
                    signature: signature.to_string(),
                    confidence: *confidence,
                    version: None,
                    evidence_type: EvidenceType::Security,
                    additional_info: None,
                });
            }
        }

        detections
    }

    fn analyze_headers(&self, headers: &reqwest::header::HeaderMap) -> Vec<WordPressDetection> {
        let mut detections = Vec::new();

        if let Some(powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("wordpress") {
                    debug!("WordPress detected in X-Powered-By header: {}", powered_str);

                    detections.push(WordPressDetection {
                        signature: "X-Powered-By Header".to_string(),
                        confidence: 2,
                        version: None,
                        evidence_type: EvidenceType::Content,
                        additional_info: Some(powered_str.to_string()),
                    });
                }
            }
        }

        if headers.get("x-pingback").is_some() {
            debug!("WordPress XML-RPC pingback header detected");

            detections.push(WordPressDetection {
                signature: "X-Pingback Header".to_string(),
                confidence: 2,
                version: None,
                evidence_type: EvidenceType::Api,
                additional_info: Some("XML-RPC enabled".to_string()),
            });
        }

        if let Some(link_header) = headers.get("link") {
            if let Ok(link_str) = link_header.to_str() {
                if link_str.contains("wp-json") {
                    debug!("WordPress REST API detected in Link header");

                    detections.push(WordPressDetection {
                        signature: "REST API Link Header".to_string(),
                        confidence: 1,
                        version: None,
                        evidence_type: EvidenceType::Api,
                        additional_info: Some("REST API available".to_string()),
                    });
                }
            }
        }

        detections
    }

    fn calculate_confidence(&self, detections: &[WordPressDetection]) -> u8 {
        if detections.is_empty() {
            return 0;
        }

        let weighted_sum: f32 = detections
            .iter()
            .map(|d| {
                let type_weight = match d.evidence_type {
                    EvidenceType::Version => 3.0,
                    EvidenceType::Content => 2.0,
                    EvidenceType::Api => 2.5,
                    EvidenceType::Login => 2.0,
                    EvidenceType::Theme => 1.5,
                    EvidenceType::Plugin => 1.2,
                    EvidenceType::Security => 1.0,
                };
                (10 - d.confidence) as f32 * type_weight
            })
            .sum();

        let max_possible = detections.len() as f32 * 10.0 * 3.0;
        let confidence_ratio = weighted_sum / max_possible;

        ((confidence_ratio * 9.0) + 1.0).round() as u8
    }

    fn format_detection_result(
        &self,
        detections: Vec<WordPressDetection>,
    ) -> Option<(String, u8, Option<String>)> {
        if detections.is_empty() {
            return None;
        }

        let confidence = self.calculate_confidence(&detections);

        if confidence < 3 {
            debug!("WordPress detection confidence too low: {}/10", confidence);
            return None;
        }

        let version = detections
            .iter()
            .filter_map(|d| d.version.as_ref())
            .min_by_key(|_version_str| {
                detections
                    .iter()
                    .find(|det| det.version.is_some())
                    .map(|det| det.confidence)
                    .unwrap_or(10)
            })
            .cloned();

        let mut features = Vec::new();
        let mut themes = Vec::new();
        let mut plugins = Vec::new();

        for detection in &detections {
            match detection.evidence_type {
                EvidenceType::Theme => {
                    if let Some(ref info) = detection.additional_info {
                        if !themes.contains(info) {
                            themes.push(info.clone());
                        }
                    }
                }
                EvidenceType::Plugin => {
                    if let Some(ref info) = detection.additional_info {
                        if !plugins.contains(info) {
                            plugins.push(info.clone());
                        }
                    }
                }
                EvidenceType::Api => features.push("REST API"),
                EvidenceType::Login => features.push("Admin Access"),
                _ => {}
            }
        }

        let mut result_parts = Vec::new();

        if let Some(ref ver) = version {
            result_parts.push(format!("v{}", ver));
        }

        if !themes.is_empty() {
            result_parts.push(format!("Theme[{}]", themes.join(", ")));
        }

        if !plugins.is_empty() {
            let plugin_list = if plugins.len() > 3 {
                format!("{} (+{} more)", plugins[..3].join(", "), plugins.len() - 3)
            } else {
                plugins.join(", ")
            };
            result_parts.push(format!("Plugins[{}]", plugin_list));
        }

        if !features.is_empty() {
            result_parts.push(format!("Features[{}]", features.join(", ")));
        }

        let evidence_count = detections.len();
        let detection_info = if result_parts.is_empty() {
            format!("detected ({} evidence points)", evidence_count)
        } else {
            format!(
                "{} ({} evidence points)",
                result_parts.join(" | "),
                evidence_count
            )
        };

        Some((detection_info, confidence, version))
    }
}

impl Plugin for WordPressAdvancedPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "WordPress Advanced",
            version: "2.0.0",
            description: "Advanced WordPress CMS detection with comprehensive fingerprinting, version detection, theme/plugin identification, and security analysis.",
            category: PluginCategory::ContentManagementSystem,
            author: "rprobe team",
            priority: 2,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        if let Some(powered_by) = http_inner.headers().get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("php") {
                    return true;
                }
            }
        }

        let url = http_inner.url();
        if url.contains("wp-") || url.contains("wordpress") {
            return true;
        }

        let body = http_inner.body();
        if body.len() < 100000 {
            let body_lower = body.to_lowercase();
            if body_lower.contains("wordpress")
                || body_lower.contains("wp-content")
                || body_lower.contains("wp-includes")
                || body_lower.contains("/wp-json/")
            {
                return true;
            }
        }

        if http_inner.headers().get("x-pingback").is_some() {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        let start_time = Instant::now();

        debug!(
            "Starting WordPress advanced detection for URL: {}",
            http_inner.url()
        );

        let mut all_detections = Vec::new();

        all_detections.extend(self.extract_version_info(http_inner.body()));
        all_detections.extend(self.analyze_content(http_inner.body()));
        all_detections.extend(self.analyze_login_patterns(http_inner.body(), http_inner.url()));
        all_detections.extend(self.analyze_themes(http_inner.body()));
        all_detections.extend(self.analyze_plugins(http_inner.body()));
        all_detections.extend(self.analyze_security_patterns(http_inner.body()));
        all_detections.extend(self.analyze_headers(http_inner.headers()));

        if all_detections.is_empty() {
            debug!(
                "No WordPress signatures detected for URL: {}",
                http_inner.url()
            );
            return Ok(None);
        }

        all_detections.sort_by(|a, b| a.signature.cmp(&b.signature));
        all_detections.dedup_by(|a, b| a.signature == b.signature);

        all_detections.sort_by_key(|d| d.confidence);

        match self.format_detection_result(all_detections) {
            Some((detection_info, confidence, _version)) => {
                let execution_time = start_time.elapsed().as_millis();

                info!(
                    "WordPress detected: {} (confidence: {}/10, {}ms)",
                    detection_info, confidence, execution_time
                );

                Ok(Some(PluginResult {
                    plugin_name: self.metadata().name.to_string(),
                    detection_info,
                    confidence,
                    execution_time_ms: execution_time,
                    category: PluginCategory::ContentManagementSystem,
                }))
            }
            None => {
                debug!("WordPress analysis completed but no confident detections");
                Ok(None)
            }
        }
    }

    fn name(&self) -> &'static str {
        self.metadata().name
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
        let plugin = WordPressAdvancedPlugin;
        let content = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        let detections = plugin.extract_version_info(content);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].version, Some("6.4.2".to_string()));
        assert_eq!(detections[0].signature, "Meta Generator Version");
    }

    #[test]
    fn test_content_analysis() {
        let plugin = WordPressAdvancedPlugin;
        let content = r#"<link rel='https://api.w.org/' href='https://example.com/wp-json/' />"#;
        let detections = plugin.analyze_content(content);

        assert!(!detections.is_empty());
        assert!(detections
            .iter()
            .any(|d| d.signature == "WordPress REST API Link"));
    }

    #[test]
    fn test_theme_detection() {
        let plugin = WordPressAdvancedPlugin;
        let content =
            r#"<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />"#;
        let detections = plugin.analyze_themes(content);

        assert!(!detections.is_empty());
        assert!(detections[0].additional_info.is_some());
    }

    #[test]
    fn test_plugin_detection() {
        let plugin = WordPressAdvancedPlugin;
        let content = r#"<script src="/wp-content/plugins/yoast-seo/js/yoast.js"></script>"#;
        let detections = plugin.analyze_plugins(content);

        assert!(!detections.is_empty());
        assert!(detections[0].additional_info.is_some());
    }

    #[test]
    fn test_header_analysis() {
        let plugin = WordPressAdvancedPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-pingback",
            HeaderValue::from_static("https://example.com/xmlrpc.php"),
        );

        let detections = plugin.analyze_headers(&headers);

        assert!(!detections.is_empty());
        assert_eq!(detections[0].signature, "X-Pingback Header");
    }

    #[test]
    fn test_plugin_metadata() {
        let plugin = WordPressAdvancedPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "WordPress Advanced");
        assert_eq!(metadata.category, PluginCategory::ContentManagementSystem);
        assert_eq!(metadata.priority, 2);
        assert!(metadata.enabled);
    }

    #[test]
    fn test_should_run_optimization() {
        let plugin = WordPressAdvancedPlugin;
        let mut headers = HeaderMap::new();

        headers.insert(
            "x-pingback",
            HeaderValue::from_static("https://example.com/xmlrpc.php"),
        );
        let http_inner = create_test_http_inner("test", headers, 200);
        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_full_detection() {
        let plugin = WordPressAdvancedPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.1"));

        let body = r#"
            <meta name="generator" content="WordPress 6.4.2" />
            <link rel="https://api.w.org/" href="https://example.com/wp-json/" />
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
        "#;
        let http_inner = create_test_http_inner(body, headers, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());

        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "WordPress Advanced");
        assert!(pr.detection_info.contains("v6.4.2"));
        assert!(pr.confidence >= 5);
        assert_eq!(pr.category, PluginCategory::ContentManagementSystem);
    }

    #[test]
    fn test_confidence_calculation() {
        let plugin = WordPressAdvancedPlugin;
        let detections = vec![
            WordPressDetection {
                signature: "Test Version".to_string(),
                confidence: 1,
                version: Some("6.4.2".to_string()),
                evidence_type: EvidenceType::Version,
                additional_info: None,
            },
            WordPressDetection {
                signature: "Test Content".to_string(),
                confidence: 2,
                version: None,
                evidence_type: EvidenceType::Content,
                additional_info: None,
            },
        ];

        let confidence = plugin.calculate_confidence(&detections);
        assert!(confidence > 5 && confidence <= 10);
    }
}
