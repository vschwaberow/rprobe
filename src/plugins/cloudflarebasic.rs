// File: cloudflarebasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::useless_vec)]

use crate::httpinner::HttpInner;
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;

pub struct CloudflareBasicPlugin;

static HEADER_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[],
        &[
            (r"(?i)^cloudflare$", "Server Header"),
            (r"(?i)^cloudflare/\d+\.\d+$", "Server Version Header"),
            (r"^CF-RAY$", "CF-RAY Header"),
            (r"^CF-Cache-Status$", "CF-Cache-Status Header"),
            (r"^CF-Connecting-IP$", "CF-Connecting-IP Header"),
        ],
    )
});

static BODY_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("Cloudflare", "Cloudflare Challenge Page"),
            ("Error 1006", "Cloudflare Error 1006"),
        ],
        &[
            (r"Attention Required!|Cloudflare", "Cloudflare Challenge Page"),
            (r"Access denied|Cloudflare", "Cloudflare Access Denied"),
        ],
    )
});

impl Plugin for CloudflareBasicPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Cloudflare Basic",
            version: "1.2.0",
            description: "Cloudflare CDN and security service detection through headers, error pages, and challenge pages",
            category: PluginCategory::SecurityTechnology,
            author: "rprobe team",
            priority: 3,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        let headers = http_inner.headers();

        if headers.get("cf-ray").is_some()
            || headers.get("cf-cache-status").is_some()
            || headers.get("cf-connecting-ip").is_some()
        {
            return true;
        }

        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                if server_str.to_lowercase().contains("cloudflare") {
                    return true;
                }
            }
        }

        let status = http_inner.status();
        if (status == 403 || status == 503) && http_inner.body().contains("Cloudflare") {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!(
            "Starting Cloudflare Basic detection for URL: {}",
            http_inner.url()
        );

        let mut detections: Vec<&'static str> = Vec::new();
        let mut confidence_score = 0u8;
        let headers = http_inner.headers();

        if headers.get("cf-ray").is_some() {
            debug!("Cloudflare CF-RAY header detected");
            detections.push("CF-RAY Header");
            confidence_score = confidence_score.saturating_add(5);
        }

        if headers.get("cf-cache-status").is_some() {
            debug!("Cloudflare CF-Cache-Status header detected");
            detections.push("CF-Cache-Status Header");
            confidence_score = confidence_score.saturating_add(4);
        }

        if headers.get("cf-connecting-ip").is_some() {
            debug!("Cloudflare CF-Connecting-IP header detected");
            detections.push("CF-Connecting-IP Header");
            confidence_score = confidence_score.saturating_add(4);
        }

        if let Some(server_header_value) = headers.get("server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            let matches = HEADER_PATTERNS.find_matches(server_value);
            for description in matches.iter().take(2) {
                debug!("Cloudflare detected in server header: {}", description);
                detections.push(*description);

                let header_confidence = match *description {
                    "Server Version Header" => 4,
                    "Server Header" => 3,
                    _ => 2,
                };
                confidence_score = confidence_score.saturating_add(header_confidence);
            }
        }

        let body_matches = BODY_PATTERNS.find_matches(http_inner.body());
        for description in body_matches {
            debug!("Cloudflare detected in body: {}", description);
            detections.push(description);

            let body_confidence = match description {
                "Cloudflare Challenge Page" => 4,
                "Cloudflare Error 1006" => 3,
                "Cloudflare Access Denied" => 3,
                _ => 2,
            };
            confidence_score = confidence_score.saturating_add(body_confidence);
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!(
                "No confident Cloudflare detection for URL: {}",
                http_inner.url()
            );
            return Ok(None);
        }

        let order = vec![
            "CF-RAY Header",
            "CF-Cache-Status Header",
            "CF-Connecting-IP Header",
            "Server Version Header",
            "Server Header",
            "Cloudflare Challenge Page",
            "Cloudflare Error 1006",
            "Cloudflare Access Denied",
        ];

        detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
        detections.dedup();

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("Cloudflare CDN/Security ({})", detections.join(", "));

        info!(
            "Cloudflare detected: {} (confidence: {}/10)",
            detection_info, final_confidence
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence: final_confidence,
            execution_time_ms: 0,
            category: PluginCategory::SecurityTechnology,
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
        let plugin = CloudflareBasicPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "Cloudflare Basic");
        assert_eq!(metadata.version, "1.2.0");
        assert_eq!(metadata.category, PluginCategory::SecurityTechnology);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 3);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("Cloudflare"));
    }

    #[test]
    fn test_cf_ray_header() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("cf-ray", "7a1b2c3d4e5f6789-SJC")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("CF-RAY Header"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_cf_cache_status_header() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("cf-cache-status", "HIT")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("CF-Cache-Status Header"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_cf_connecting_ip_header() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("cf-connecting-ip", "192.168.1.100")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("CF-Connecting-IP Header"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_cloudflare_server_header() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "cloudflare")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Server Header"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_cloudflare_challenge_page() {
        let plugin = CloudflareBasicPlugin;
        let http_inner =
            create_test_http_inner("Attention Required! Cloudflare security check", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Cloudflare Challenge Page"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_cloudflare_error_1006() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("Error 1006: Access Denied", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Cloudflare Error 1006"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner(
            "Attention Required! Cloudflare",
            vec![
                ("cf-ray", "7a1b2c3d4e5f6789-SJC"),
                ("cf-cache-status", "MISS"),
                ("server", "cloudflare"),
            ],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("CF-RAY Header"));
        assert!(plugin_result
            .detection_info
            .contains("CF-Cache-Status Header"));
        assert!(plugin_result.detection_info.contains("Server Header"));
        assert!(plugin_result
            .detection_info
            .contains("Cloudflare Challenge Page"));
        assert_eq!(plugin_result.confidence, 8);
    }

    #[test]
    fn test_no_detection() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_should_run_with_cf_ray() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("cf-ray", "test")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_403_cloudflare() {
        let plugin = CloudflareBasicPlugin;
        let mut http_inner = create_test_http_inner("Access denied - Cloudflare", vec![]);
        http_inner.set_status(403);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_503_cloudflare() {
        let plugin = CloudflareBasicPlugin;
        let mut http_inner =
            create_test_http_inner("Service temporarily unavailable - Cloudflare", vec![]);
        http_inner.set_status(503);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_plugin_name_consistency() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("cf-ray", "test123")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert_eq!(plugin_result.plugin_name, "Cloudflare Basic");
        assert_eq!(plugin_result.category, PluginCategory::SecurityTechnology);
    }
}
