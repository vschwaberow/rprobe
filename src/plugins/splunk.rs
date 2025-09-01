// File: splunk.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::time::Instant;

pub struct SplunkPlugin;

static SERVER_SPLUNKD_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)splunkd").unwrap());

static SERVER_CHERRYPY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)cherrypy/[\d.]+").unwrap());

static CHERRYPY_VERSION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)cherrypy/([\d.]+)").unwrap());

static SERVICES_ENDPOINT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/services(?:NS)?/").unwrap());

static SPLUNKD_ENDPOINT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/splunkd/(?:__raw/)?").unwrap());

static LOCALIZATION_ENDPOINT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/en-US/(?:app|account|manager)/").unwrap());

static SPLUNKD_EXCEPTION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"SplunkdConnectionException").unwrap());

static SPLUNK_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/opt/splunk/lib/python[\d.]+/site-packages/").unwrap());

static LOGIN_FORM_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<form[^>]*class=[\"'][^\"']*loginForm[^\"']*[\"']"#).unwrap());

static DASHBOARD_ELEMENT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<dashboard>|dashboard-element-title|dashboard-panel").unwrap());

static SPLUNK_STATIC_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/static/app/[^/]+/|\{\{SPLUNKWEB_URL_PREFIX\}\}").unwrap());

static SPLUNK_JS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)splunk\.(?:min\.)?js|require\.config.*SPLUNKWEB_URL_PREFIX").unwrap()
});

impl Plugin for SplunkPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Splunk",
            version: "1.0.0",
            description: "Splunk Enterprise and Cloud detection through server headers, endpoints, and web interface patterns",
            category: PluginCategory::ApplicationFramework,
            author: "rprobe team",
            priority: 6,
            enabled: true,
        }
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        let start_time = Instant::now();

        debug!("Starting Splunk detection for URL: {}", http_inner.url());

        let mut evidence = HashMap::new();
        let headers = http_inner.headers();
        let body = http_inner.body();
        let url = http_inner.url();

        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                if SERVER_SPLUNKD_REGEX.is_match(server_str) {
                    debug!("Splunkd server header detected: {}", server_str);
                    evidence.insert("server_splunkd", (10, format!("Server[{}]", server_str)));

                    return self.build_result(evidence, start_time);
                }

                if SERVER_CHERRYPY_REGEX.is_match(server_str) {
                    debug!("CherryPy server header detected: {}", server_str);
                    let version_info =
                        if let Some(captures) = CHERRYPY_VERSION_REGEX.captures(server_str) {
                            let version = captures.get(1).map_or("", |m| m.as_str());
                            format!("CherryPy[{}]", version)
                        } else {
                            "CherryPy".to_string()
                        };
                    evidence.insert("server_cherrypy", (8, version_info));
                }
            }
        }

        if SERVICES_ENDPOINT_REGEX.is_match(url) {
            debug!("Splunk services endpoint detected in URL");
            evidence.insert(
                "services_endpoint",
                (9, "Services API Endpoint".to_string()),
            );
        }

        if SPLUNKD_ENDPOINT_REGEX.is_match(url) {
            debug!("Splunkd endpoint detected in URL");
            evidence.insert("splunkd_endpoint", (9, "Splunkd Raw Endpoint".to_string()));
        }

        if LOCALIZATION_ENDPOINT_REGEX.is_match(url) {
            debug!("Splunk localization endpoint detected");
            evidence.insert(
                "localization_endpoint",
                (7, "Localization Path".to_string()),
            );
        }

        if !body.is_empty() && body.len() < 50000 {
            if SPLUNKD_EXCEPTION_REGEX.is_match(body) {
                debug!("SplunkdConnectionException detected");
                evidence.insert(
                    "splunkd_exception",
                    (7, "SplunkdConnectionException".to_string()),
                );
            }

            if SPLUNK_PATH_REGEX.is_match(body) {
                debug!("Splunk installation path detected");
                evidence.insert("splunk_path", (6, "Splunk Installation Path".to_string()));
            }

            if LOGIN_FORM_REGEX.is_match(body) {
                debug!("Splunk login form detected");
                evidence.insert("login_form", (5, "Login Form".to_string()));
            }

            if DASHBOARD_ELEMENT_REGEX.is_match(body) {
                debug!("Splunk dashboard elements detected");
                evidence.insert("dashboard_elements", (4, "Dashboard Elements".to_string()));
            }

            if SPLUNK_STATIC_REGEX.is_match(body) {
                debug!("Splunk static resources detected");
                evidence.insert("static_resources", (4, "Static Resources".to_string()));
            }

            if SPLUNK_JS_REGEX.is_match(body) {
                debug!("Splunk JavaScript detected");
                evidence.insert("splunk_js", (5, "Splunk JavaScript".to_string()));
            }
        }

        if evidence.is_empty() {
            debug!("No Splunk indicators found");
            return Ok(None);
        }

        self.build_result(evidence, start_time)
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if http_inner.success() {
            return true;
        }

        if [401, 403, 404, 500].contains(&http_inner.status()) {
            return true;
        }

        let url = http_inner.url();

        if url.contains("/services") || url.contains("/splunkd") || url.contains("/en-US/") {
            return true;
        }

        if let Some(server) = http_inner.headers().get("server") {
            if let Ok(server_str) = server.to_str() {
                let server_lower = server_str.to_lowercase();
                if server_lower.contains("splunkd") || server_lower.contains("cherrypy") {
                    return true;
                }
            }
        }

        let body = http_inner.body();
        if body.len() < 10000 {
            let body_lower = body.to_lowercase();
            if body_lower.contains("splunk")
                || body_lower.contains("cherrypy")
                || body_lower.contains("dashboard")
            {
                return true;
            }
        }

        false
    }
}

impl SplunkPlugin {
    fn build_result(
        &self,
        evidence: HashMap<&str, (u8, String)>,
        start_time: Instant,
    ) -> Result<Option<PluginResult>, PluginError> {
        let confidence = self.calculate_confidence(&evidence);
        let detection_info = self.format_detection_info(&evidence);
        let execution_time = start_time.elapsed().as_millis();

        info!(
            "Splunk detected: {} (confidence: {}/10, {}ms)",
            detection_info, confidence, execution_time
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence,
            execution_time_ms: execution_time,
            category: self.metadata().category,
        }))
    }

    fn calculate_confidence(&self, evidence: &HashMap<&str, (u8, String)>) -> u8 {
        let mut weighted_score = 0.0;

        for (evidence_type, (base_score, _)) in evidence {
            let weight = match *evidence_type {
                "server_splunkd" => 1.0,
                "server_cherrypy" => 0.8,
                "services_endpoint" => 0.8,
                "splunkd_endpoint" => 0.8,
                "splunkd_exception" => 0.7,
                "localization_endpoint" => 0.6,
                "splunk_path" => 0.6,
                "splunk_js" => 0.5,
                "login_form" => 0.4,
                "dashboard_elements" => 0.4,
                "static_resources" => 0.3,
                _ => 0.3,
            };

            weighted_score += (*base_score as f32) * weight;
        }

        let scaled_confidence = weighted_score.clamp(1.0, 10.0) as u8;

        debug!(
            "Confidence calculation: weighted_score={:.2}, final={}",
            weighted_score, scaled_confidence
        );

        scaled_confidence
    }

    fn format_detection_info(&self, evidence: &HashMap<&str, (u8, String)>) -> String {
        let mut parts = Vec::new();

        let priority_order = [
            "server_splunkd",
            "server_cherrypy",
            "services_endpoint",
            "splunkd_endpoint",
            "splunkd_exception",
            "localization_endpoint",
            "splunk_path",
            "splunk_js",
            "login_form",
            "dashboard_elements",
            "static_resources",
        ];

        for &evidence_type in &priority_order {
            if let Some((_, description)) = evidence.get(evidence_type) {
                parts.push(description.clone());
            }
        }

        if parts.is_empty() {
            "Splunk Enterprise/Cloud".to_string()
        } else {
            format!("Splunk Enterprise/Cloud ({})", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn create_test_http_inner(headers: HeaderMap, body: String, status: u16) -> HttpInner {
        HttpInner::new_with_all(
            headers,
            body,
            status,
            "https://example.com".to_string(),
            true,
        )
    }

    #[test]
    fn test_plugin_metadata() {
        let plugin = SplunkPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "Splunk");
        assert_eq!(metadata.version, "1.0.0");
        assert!(metadata.description.contains("Splunk Enterprise and Cloud"));
        assert_eq!(metadata.category, PluginCategory::ApplicationFramework);
        assert!(metadata.enabled);
        assert_eq!(metadata.priority, 6);
    }

    #[test]
    fn test_splunkd_server_detection() {
        let plugin = SplunkPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Splunkd"));

        let http_inner = create_test_http_inner(headers, String::new(), 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "Splunk");
        assert!(pr.detection_info.contains("Server[Splunkd]"));
        assert_eq!(pr.confidence, 10);
        assert_eq!(pr.category, PluginCategory::ApplicationFramework);
    }

    #[test]
    fn test_cherrypy_server_detection() {
        let plugin = SplunkPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("CherryPy/3.1.2"));

        let http_inner = create_test_http_inner(headers, String::new(), 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("CherryPy[3.1.2]"));
        assert!(pr.confidence >= 6);
    }

    #[test]
    fn test_services_endpoint_detection() {
        let plugin = SplunkPlugin;
        let http_inner = HttpInner::new_with_all(
            HeaderMap::new(),
            String::new(),
            200,
            "https://example.com/services/authentication/users".to_string(),
            true,
        );

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Services API Endpoint"));
        assert!(pr.confidence >= 7);
    }

    #[test]
    fn test_splunkd_endpoint_detection() {
        let plugin = SplunkPlugin;
        let http_inner = HttpInner::new_with_all(
            HeaderMap::new(),
            String::new(),
            200,
            "https://example.com/splunkd/__raw/services/server".to_string(),
            true,
        );

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Splunkd Raw Endpoint"));
    }

    #[test]
    fn test_splunkd_exception_detection() {
        let plugin = SplunkPlugin;
        let body =
            "Error: SplunkdConnectionException: Splunkd daemon is not responding".to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 500);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("SplunkdConnectionException"));
        assert!(pr.confidence >= 4);
    }

    #[test]
    fn test_login_form_detection() {
        let plugin = SplunkPlugin;
        let body =
            r#"<form class="loginForm" method="post"><input name="username" type="text"></form>"#
                .to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Login Form"));
    }

    #[test]
    fn test_dashboard_elements_detection() {
        let plugin = SplunkPlugin;
        let body = r#"<dashboard><div class="dashboard-element-title">Analytics</div></dashboard>"
            .to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Dashboard Elements"));
    }

    #[test]
    fn test_splunk_javascript_detection() {
        let plugin = SplunkPlugin;
        let body = r#"<script src="splunk.min.js"></script><script>require.config({paths:{"{{SPLUNKWEB_URL_PREFIX}}/static/app/"}});</script>"#
            .to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Splunk JavaScript"));
    }

    #[test]
    fn test_multiple_evidence_detection() {
        let plugin = SplunkPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("CherryPy/3.1.2"));

        let body =
            r#"<form class="loginForm" method="post">SplunkdConnectionException occurred</form>"#
                .to_string();
        let http_inner = create_test_http_inner(headers, body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("CherryPy[3.1.2]"));
        assert!(pr.detection_info.contains("Login Form"));
        assert!(pr.detection_info.contains("SplunkdConnectionException"));
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_confidence_calculation() {
        let plugin = SplunkPlugin;

        let mut evidence = HashMap::new();
        evidence.insert("server_splunkd", (10, "Server[Splunkd]".to_string()));
        assert_eq!(plugin.calculate_confidence(&evidence), 10);

        let mut evidence = HashMap::new();
        evidence.insert("services_endpoint", (9, "Services API".to_string()));
        evidence.insert("login_form", (5, "Login Form".to_string()));
        let confidence = plugin.calculate_confidence(&evidence);
        assert!((6..=10).contains(&confidence));

        let mut evidence = HashMap::new();
        evidence.insert("static_resources", (4, "Static Resources".to_string()));
        assert!(plugin.calculate_confidence(&evidence) <= 5);
    }

    #[test]
    fn test_no_splunk_indicators() {
        let plugin = SplunkPlugin;
        let body = "This is a regular Apache server".to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_none());
    }

    #[test]
    fn test_should_run_filtering() {
        let plugin = SplunkPlugin;

        let http_inner = create_test_http_inner(HeaderMap::new(), String::new(), 200);
        assert!(plugin.should_run(&http_inner));

        let http_inner = create_test_http_inner(HeaderMap::new(), String::new(), 401);
        assert!(plugin.should_run(&http_inner));

        let http_inner = create_test_http_inner(HeaderMap::new(), String::new(), 500);
        assert!(plugin.should_run(&http_inner));

        let http_inner = HttpInner::new_with_all(
            HeaderMap::new(),
            String::new(),
            502,
            "https://example.com".to_string(),
            false,
        );
        assert!(!plugin.should_run(&http_inner));
    }
}
