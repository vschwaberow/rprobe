// File: nginxbasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::useless_vec)]

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use log::{debug, info};
use once_cell::sync::Lazy;

pub struct NginxBasicPlugin;

static BODY_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("Welcome to nginx", "Header Message"), 
            ("nginx", "Centered Text"),
            ("Thank you for using nginx", "Thank You Message"),
        ],
        &[
            (r"<title>Welcome to nginx!</title>", "Default Title"),
            (r"<hr><center>nginx/\d+\.\d+\.\d+</center>", "Version Info"),
        ]
    )
});

static HEADER_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("nginx", "Server Header"),
            ("openresty", "OpenResty Header"),
        ],
        &[
            (r"^nginx/\d+\.\d+\.\d+$", "Server Version Header"),
            (r"^openresty/\d+\.\d+\.\d+\.\d+$", "OpenResty Version Header"),
        ]
    )
});

impl Plugin for NginxBasicPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Nginx Basic",
            version: "1.2.0",
            description: "Nginx HTTP server and OpenResty detection through server headers, default pages, and content analysis",
            category: PluginCategory::WebServer,
            author: "rprobe team",
            priority: 1,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        if let Some(server) = http_inner.headers().get("server") {
            if let Ok(server_str) = server.to_str() {
                let server_lower = server_str.to_lowercase();
                if server_lower.contains("nginx") || server_lower.contains("openresty") {
                    return true;
                }
            }
        }

        if let Some(powered_by) = http_inner.headers().get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("nginx") {
                    return true;
                }
            }
        }

        let body = http_inner.body();
        if body.len() < 10000
            && (body.contains("Welcome to nginx") || body.contains("<center>nginx</center>"))
        {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!(
            "Starting Nginx Basic detection for URL: {}",
            http_inner.url()
        );

        let mut detections: Vec<&'static str> = Vec::new();
        let mut confidence_score = 0u8;

        // Use optimized pattern matching for body content
        let body_matches = BODY_PATTERNS.find_matches(http_inner.body());
        for detection in body_matches {
            info!("Nginx detected in body: {}", detection);
            detections.push(detection);

            let pattern_confidence = match detection {
                "Default Title" => 5,
                "Header Message" => 4,
                "Version Info" => 4,
                "Centered Text" => 3,
                "Thank You Message" => 3,
                _ => 2,
            };
            confidence_score = confidence_score.saturating_add(pattern_confidence);
        }

        // Use optimized pattern matching for headers
        if let Some(server_header_value) = http_inner.headers().get("server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            let header_matches = HEADER_PATTERNS.find_matches(server_value);
            
            for detection in header_matches {
                info!("Nginx detected in header: {}", detection);
                detections.push(detection);

                let header_confidence = match detection {
                    "Server Version Header" => 5,
                    "OpenResty Version Header" => 5,
                    "Server Header" => 4,
                    "OpenResty Header" => 4,
                    _ => 2,
                };
                confidence_score = confidence_score.saturating_add(header_confidence);
            }
        }

        // Check X-Powered-By header (not optimized as it's a simple contains check)
        if let Some(powered_by) = http_inner.headers().get("x-powered-by") {
            let powered_value = powered_by.to_str().unwrap_or("").to_lowercase();
            if powered_value.contains("nginx") {
                info!("Nginx detected in X-Powered-By header");
                detections.push("X-Powered-By Header");
                confidence_score = confidence_score.saturating_add(3);
            }
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!("No confident Nginx detection for URL: {}", http_inner.url());
            return Ok(None);
        }

        let order = vec![
            "Server Version Header",
            "OpenResty Version Header", 
            "Server Header",
            "OpenResty Header",
            "Default Title",
            "Header Message",
            "Version Info",
            "Centered Text",
            "Thank You Message",
            "X-Powered-By Header",
        ];

        detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
        detections.dedup();

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("Nginx HTTP Server ({})", detections.join(", "));

        info!(
            "Nginx detected: {} (confidence: {}/10)",
            detection_info, final_confidence
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence: final_confidence,
            execution_time_ms: 0,
            category: PluginCategory::WebServer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::str::FromStr;

    fn create_test_http_inner(body: &str, headers: Vec<(&str, &str)>) -> HttpInner {
        let mut header_map = HeaderMap::new();
        for (key, value) in headers {
            header_map.insert(
                HeaderName::from_str(key).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }

        HttpInner::new_with_all(
            header_map,
            body.to_string(),
            200,
            "https://example.com".to_string(),
            true,
        )
    }

    #[test]
    fn test_metadata() {
        let plugin = NginxBasicPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "Nginx Basic");
        assert_eq!(metadata.version, "1.2.0");
        assert_eq!(metadata.category, PluginCategory::WebServer);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 1);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("Nginx"));
    }

    #[test]
    fn test_nginx_server_header() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "nginx")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Server Header"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_nginx_version_header() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "nginx/1.18.0")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Server Version Header"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_openresty_header() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "openresty")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("OpenResty Header"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_openresty_version_header() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "openresty/1.19.3.1")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("OpenResty Version Header"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_welcome_title() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("<title>Welcome to nginx!</title>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Default Title"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_welcome_header() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("<h1>Welcome to nginx</h1>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Header Message"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_centered_text() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("<center>nginx</center>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Centered Text"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_version_info() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("<hr><center>nginx/1.18.0</center>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Version Info"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_thank_you_message() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("Thank you for using nginx", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Thank You Message"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_x_powered_by_nginx() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "nginx/1.18.0")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("X-Powered-By Header"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_no_detection() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_should_run_failed_request() {
        let plugin = NginxBasicPlugin;
        let mut http_inner = create_test_http_inner("test", vec![]);
        http_inner.set_success(false);

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner(
            "<title>Welcome to nginx!</title><h1>Welcome to nginx</h1>",
            vec![("server", "nginx/1.18.0")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Server Version Header"));
        assert!(plugin_result.detection_info.contains("Default Title"));
        assert!(plugin_result.detection_info.contains("Header Message"));
        assert_eq!(plugin_result.confidence, 8);
    }
}
