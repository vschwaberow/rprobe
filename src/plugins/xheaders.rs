// File: xheaders.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::useless_vec)]

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::info;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Instant;

pub struct XHeadersPlugin;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InfrastructureComponent {
    LoadBalancer,
    ReverseProxy,
    Cdn,
    Cache,
    CloudProvider,
    WebAccelerator,
    SecurityGateway,
    Firewall,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpType {
    PublicIpv4,
    PrivateIpv4,
    LoopbackIpv4,
    LinkLocalIpv4,
    MulticastIpv4,
    PublicIpv6,
    PrivateIpv6,
    LoopbackIpv6,
    LinkLocalIpv6,
    MulticastIpv6,
    CloudProvider,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheStatus {
    Hit,
    Miss,
    None,
    Refresh,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XFrameOptionsPolicy {
    Deny,
    SameOrigin,
    AllowFrom { uri: String },
    Invalid { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickjackingRiskLevel {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XSSProtectionMode {
    Disabled,
    Enabled,
    Block,
    Report(String),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLevel {
    High,
    Medium,
    Low,
    None,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UACompatibilityMode {
    IEEdge,
    IE11,
    IE10,
    IE9,
    IE8,
    IE7,
    IEEmulation(String),
    ChromeFrame,
    MicrosoftEdge,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct XFrameOptionsAnalysis {
    pub policy: XFrameOptionsPolicy,
    pub risk_level: ClickjackingRiskLevel,
    pub compliance_issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub security_score: u8,
}

#[derive(Debug, Clone)]
pub struct XSSProtectionAnalysis {
    pub mode: XSSProtectionMode,
    pub security_level: SecurityLevel,
    pub compliance_notes: Vec<String>,
    pub recommendations: Vec<String>,
    pub security_score: u8,
}

#[derive(Debug, Clone)]
pub struct PoweredByAnalysis {
    pub technology: String,
    pub framework: Vec<String>,
    pub version: Option<String>,
    pub confidence_factors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UACompatibleAnalysis {
    pub modes: Vec<UACompatibilityMode>,
    pub sources: Vec<String>,
    pub insights: Vec<String>,
    pub compatibility_score: u8,
}

#[derive(Debug, Clone)]
pub struct InfrastructureElement {
    pub element_type: InfrastructureComponent,
    pub header_name: String,
    pub header_value: String,
    pub server_name: Option<String>,
    pub ip_address: Option<String>,
    pub ip_type: Option<IpType>,
    pub cloud_provider: Option<String>,
    pub cache_status: Option<CacheStatus>,
    pub x_frame_options_analysis: Option<XFrameOptionsAnalysis>,
    pub xss_protection_analysis: Option<XSSProtectionAnalysis>,
    pub powered_by_analysis: Option<PoweredByAnalysis>,
    pub ua_compatible_analysis: Option<UACompatibleAnalysis>,
    pub additional_info: HashMap<String, String>,
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub struct InfrastructureAnalysis {
    pub total_elements: usize,
    pub components: HashMap<InfrastructureComponent, usize>,
    pub cloud_providers: HashMap<String, usize>,
    pub proxy_chain_length: usize,
    pub cache_layers: usize,
    pub has_cdn: bool,
    pub has_load_balancer: bool,
    pub has_waf: bool,
    pub security_concerns: Vec<String>,
    pub performance_indicators: Vec<String>,
    pub architecture_insights: Vec<String>,
}

static BACKEND_HEADERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "x-backend",
        "x-backend-server",
        "x-backendhost",
        "x-backend-host",
        "x-served-by",
        "x-server",
        "x-upstream-server",
        "x-real-server",
    ]
});

static CACHE_HEADERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "x-cache",
        "x-cache-lookup",
        "x-cache-status",
        "cf-cache-status",
        "x-served-by",
        "x-cache-hits",
        "age",
        "x-varnish",
        "x-fastly-request-id",
    ]
});

static FORWARDING_HEADERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded",
        "x-cluster-client-ip",
        "x-original-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
    ]
});

static SECURITY_HEADERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "x-frame-options",
        "x-xss-protection",
        "x-content-type-options",
        "x-permitted-cross-domain-policies",
        "x-waf",
        "x-firewall",
    ]
});

static TECHNOLOGY_HEADERS: Lazy<Vec<&'static str>> =
    Lazy::new(|| vec!["x-powered-by", "x-ua-compatible"]);

static CLOUD_PATTERNS: Lazy<HashMap<&'static str, Vec<&'static str>>> = Lazy::new(|| {
    let mut patterns = HashMap::new();
    patterns.insert(
        "Amazon AWS",
        vec![
            "52.", "54.", "3.", "18.", "34.", "35.", "50.", "107.", "174.", "184.", "204.", "207.",
        ],
    );
    patterns.insert(
        "Google Cloud",
        vec![
            "35.", "107.", "108.", "130.", "146.", "162.", "199.", "209.",
        ],
    );
    patterns.insert(
        "Microsoft Azure",
        vec!["20.", "23.", "40.", "137.", "138.", "168.", "191."],
    );
    patterns.insert(
        "Cloudflare",
        vec![
            "103.21.", "103.22.", "103.31.", "104.16.", "108.162.", "131.0.", "141.101.",
            "162.158.", "172.64.", "173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
        ],
    );
    patterns.insert("Fastly", vec!["151.101.", "199.232.", "185.31.", "146.75."]);
    patterns
});

static COMPONENT_PATTERNS: Lazy<HashMap<InfrastructureComponent, Vec<Regex>>> = Lazy::new(|| {
    let mut patterns = HashMap::new();

    patterns.insert(
        InfrastructureComponent::LoadBalancer,
        vec![
            Regex::new(r"(?i)lb-").unwrap(),
            Regex::new(r"(?i)loadbalancer").unwrap(),
            Regex::new(r"(?i)haproxy").unwrap(),
            Regex::new(r"(?i)f5-").unwrap(),
        ],
    );

    patterns.insert(
        InfrastructureComponent::ReverseProxy,
        vec![
            Regex::new(r"(?i)proxy").unwrap(),
            Regex::new(r"(?i)nginx").unwrap(),
            Regex::new(r"(?i)apache").unwrap(),
        ],
    );

    patterns.insert(
        InfrastructureComponent::Cdn,
        vec![
            Regex::new(r"(?i)cloudflare").unwrap(),
            Regex::new(r"(?i)cloudfront").unwrap(),
            Regex::new(r"(?i)fastly").unwrap(),
            Regex::new(r"(?i)cdn").unwrap(),
        ],
    );

    patterns.insert(
        InfrastructureComponent::Cache,
        vec![
            Regex::new(r"(?i)varnish").unwrap(),
            Regex::new(r"(?i)squid").unwrap(),
            Regex::new(r"(?i)cache").unwrap(),
        ],
    );

    patterns.insert(
        InfrastructureComponent::SecurityGateway,
        vec![
            Regex::new(r"(?i)waf").unwrap(),
            Regex::new(r"(?i)firewall").unwrap(),
            Regex::new(r"(?i)security").unwrap(),
        ],
    );

    patterns
});

static IP_EXTRACTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)*::(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}")
        .expect("Invalid IP extraction regex")
});

static X_FRAME_OPTIONS_ALLOW_FROM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^allow-from\s+(https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/.*)?)\s*$")
        .expect("Invalid X-Frame-Options ALLOW-FROM regex")
});

static X_UA_COMPATIBLE_META_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<meta[^>]*http-equiv\s*=\s*['"]?X-UA-Compatible['"]?[^>]*content\s*=\s*['"]?([^'">\s]+)['"]?[^>]*>"#)
        .expect("Invalid X-UA-Compatible meta tag regex")
});

static VERSION_EXTRACTION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\d+\.\d+(?:\.\d+)?)").expect("Invalid version extraction regex"));

impl Plugin for XHeadersPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "X-Headers Comprehensive",
            version: "4.0.0",
            description: "Unified comprehensive X-Headers detection combining infrastructure analysis (backend, cache, proxy, CDN), security headers (X-Frame-Options, X-XSS-Protection), technology detection (X-Powered-By), and compatibility analysis (X-UA-Compatible) with cloud provider identification and architecture insights",
            category: PluginCategory::LoadBalancer,
            author: "rprobe",
            priority: 15,
            enabled: true,
        }
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        let start_time = Instant::now();

        if !self.should_run(http_inner) {
            return Ok(None);
        }

        let headers = http_inner.headers();
        let body = http_inner.body();
        let mut infrastructure_elements = Vec::new();

        for (header_name, header_value) in headers.iter() {
            let header_name_str = header_name.as_str().to_lowercase();

            if header_name_str.starts_with("x-") || self.is_infrastructure_header(&header_name_str)
            {
                if let Ok(value_str) = header_value.to_str() {
                    if !value_str.trim().is_empty() {
                        let elements = self.analyze_header(&header_name_str, value_str);
                        infrastructure_elements.extend(elements);
                    }
                }
            }
        }

        if let Some(captures) = X_UA_COMPATIBLE_META_REGEX.captures(body) {
            if let Some(content_match) = captures.get(1) {
                let content_value = content_match.as_str();
                if !content_value.trim().is_empty() {
                    let elements =
                        self.analyze_technology_header("x-ua-compatible", content_value.trim());
                    infrastructure_elements.extend(elements);
                }
            }
        }

        if infrastructure_elements.is_empty() {
            return Ok(None);
        }

        let analysis = self.analyze_infrastructure(&infrastructure_elements);
        let confidence = self.calculate_confidence(&infrastructure_elements, &analysis);
        let detection_info = self.format_detection_info(&infrastructure_elements, &analysis);

        let execution_time = start_time.elapsed().as_millis();

        info!(
            "X-Headers infrastructure detected: {} ({} element{}, confidence: {}/10, {}ms)",
            detection_info,
            analysis.total_elements,
            if analysis.total_elements == 1 {
                ""
            } else {
                "s"
            },
            confidence,
            execution_time
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence,
            execution_time_ms: execution_time,
            category: self.metadata().category,
        }))
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        let headers = http_inner.headers();

        let has_x_headers = headers.iter().any(|(name, _)| {
            let header_name = name.as_str().to_lowercase();
            header_name.starts_with("x-") || self.is_infrastructure_header(&header_name)
        });

        if has_x_headers {
            return true;
        }

        let body = http_inner.body();
        X_UA_COMPATIBLE_META_REGEX.is_match(body)
    }
}

impl XHeadersPlugin {
    fn is_infrastructure_header(&self, header_name: &str) -> bool {
        matches!(
            header_name,
            "age" | "via" | "server" | "cf-cache-status" | "cf-ray"
        )
    }

    fn analyze_header(&self, header_name: &str, header_value: &str) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        if BACKEND_HEADERS.contains(&header_name) {
            elements.extend(self.analyze_backend_header(header_name, header_value));
        }

        if CACHE_HEADERS.contains(&header_name) {
            elements.extend(self.analyze_cache_header(header_name, header_value));
        }

        if FORWARDING_HEADERS.contains(&header_name) {
            elements.extend(self.analyze_forwarding_header(header_name, header_value));
        }

        if SECURITY_HEADERS.contains(&header_name) {
            elements.extend(self.analyze_security_header(header_name, header_value));
        }

        if TECHNOLOGY_HEADERS.contains(&header_name) {
            elements.extend(self.analyze_technology_header(header_name, header_value));
        }

        if header_name.starts_with("x-") && elements.is_empty() {
            elements.push(self.analyze_generic_xheader(header_name, header_value));
        }

        elements
    }

    fn analyze_backend_header(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        for server_info in header_value.split(',').map(|s| s.trim()) {
            if server_info.is_empty() {
                continue;
            }

            let mut additional_info = HashMap::new();
            let server_name = self.extract_server_name(server_info);
            let ip_address = self.extract_ip_address(server_info);

            additional_info.insert("raw_value".to_string(), server_info.to_string());

            let component_type = self.identify_component_type(server_info);
            let cloud_provider = ip_address
                .as_ref()
                .and_then(|ip| self.detect_cloud_provider(ip));

            elements.push(InfrastructureElement {
                element_type: component_type.clone(),
                header_name: header_name.to_string(),
                header_value: server_info.to_string(),
                server_name,
                ip_address: ip_address.clone(),
                ip_type: ip_address.as_ref().map(|ip| self.classify_ip(ip)),
                cloud_provider: cloud_provider.clone(),
                cache_status: None,
                x_frame_options_analysis: None,
                xss_protection_analysis: None,
                powered_by_analysis: None,
                ua_compatible_analysis: None,
                additional_info,
                confidence: self.calculate_element_confidence(&component_type, &cloud_provider),
            });
        }

        elements
    }

    fn analyze_cache_header(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        if header_name == "x-cache" || header_name == "x-cache-lookup" {
            if let Some(captures) =
                Regex::new(r"(?i)(hit|miss|none|refresh|unknown)\s+from\s+([^\s,]+)")
                    .unwrap()
                    .captures(header_value)
            {
                let status_str = captures.get(1).unwrap().as_str();
                let server_name = captures.get(2).unwrap().as_str();

                let cache_status = self.parse_cache_status(status_str);
                let component_type = self.identify_cache_type(server_name, header_value);
                let cloud_provider = self.detect_cloud_provider(server_name);

                let mut additional_info = HashMap::new();
                additional_info.insert("cache_status".to_string(), status_str.to_string());

                elements.push(InfrastructureElement {
                    element_type: component_type,
                    header_name: header_name.to_string(),
                    header_value: header_value.to_string(),
                    server_name: Some(server_name.to_string()),
                    ip_address: None,
                    ip_type: None,
                    cloud_provider,
                    cache_status: Some(cache_status),
                    x_frame_options_analysis: None,
                    xss_protection_analysis: None,
                    powered_by_analysis: None,
                    ua_compatible_analysis: None,
                    additional_info,
                    confidence: 8,
                });
            }
        } else {
            let mut additional_info = HashMap::new();
            additional_info.insert("header_type".to_string(), "cache".to_string());

            elements.push(InfrastructureElement {
                element_type: InfrastructureComponent::Cache,
                header_name: header_name.to_string(),
                header_value: header_value.to_string(),
                server_name: None,
                ip_address: None,
                ip_type: None,
                cloud_provider: None,
                cache_status: None,
                x_frame_options_analysis: None,
                xss_protection_analysis: None,
                powered_by_analysis: None,
                ua_compatible_analysis: None,
                additional_info,
                confidence: 6,
            });
        }

        elements
    }

    fn analyze_forwarding_header(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        if header_name == "x-forwarded-for" {
            let ips: Vec<&str> = header_value
                .split(',')
                .map(|ip| ip.trim())
                .filter(|ip| !ip.is_empty())
                .collect();

            for (position, ip_str) in ips.iter().enumerate() {
                let cleaned_ip = self.clean_ip_address(ip_str);
                let ip_type = self.classify_ip(&cleaned_ip);
                let cloud_provider = self.detect_cloud_provider(&cleaned_ip);

                let mut additional_info = HashMap::new();
                additional_info.insert("position".to_string(), position.to_string());
                additional_info.insert("total_hops".to_string(), ips.len().to_string());

                elements.push(InfrastructureElement {
                    element_type: if cloud_provider.is_some() {
                        InfrastructureComponent::Cdn
                    } else {
                        InfrastructureComponent::ReverseProxy
                    },
                    header_name: header_name.to_string(),
                    header_value: cleaned_ip.clone(),
                    server_name: None,
                    ip_address: Some(cleaned_ip),
                    ip_type: Some(ip_type),
                    cloud_provider: cloud_provider.clone(),
                    cache_status: None,
                    x_frame_options_analysis: None,
                    xss_protection_analysis: None,
                    powered_by_analysis: None,
                    ua_compatible_analysis: None,
                    additional_info,
                    confidence: if cloud_provider.is_some() { 8 } else { 6 },
                });
            }
        } else {
            let ip_address = self.extract_ip_address(header_value);
            let cloud_provider = ip_address
                .as_ref()
                .and_then(|ip| self.detect_cloud_provider(ip));

            let mut additional_info = HashMap::new();
            additional_info.insert("header_type".to_string(), "forwarding".to_string());

            elements.push(InfrastructureElement {
                element_type: InfrastructureComponent::ReverseProxy,
                header_name: header_name.to_string(),
                header_value: header_value.to_string(),
                server_name: None,
                ip_address: ip_address.clone(),
                ip_type: ip_address.as_ref().map(|ip| self.classify_ip(ip)),
                cloud_provider,
                cache_status: None,
                x_frame_options_analysis: None,
                xss_protection_analysis: None,
                powered_by_analysis: None,
                ua_compatible_analysis: None,
                additional_info,
                confidence: 7,
            });
        }

        elements
    }

    fn analyze_security_header(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        if header_name == "x-frame-options" {
            elements.push(self.analyze_x_frame_options(header_value));
        } else if header_name == "x-xss-protection" {
            elements.push(self.analyze_x_xss_protection(header_value));
        } else {
            let mut additional_info = HashMap::new();
            additional_info.insert("security_policy".to_string(), header_value.to_string());

            elements.push(InfrastructureElement {
                element_type: InfrastructureComponent::SecurityGateway,
                header_name: header_name.to_string(),
                header_value: header_value.to_string(),
                server_name: None,
                ip_address: None,
                ip_type: None,
                cloud_provider: None,
                cache_status: None,
                x_frame_options_analysis: None,
                xss_protection_analysis: None,
                powered_by_analysis: None,
                ua_compatible_analysis: None,
                additional_info,
                confidence: 7,
            });
        }

        elements
    }

    fn analyze_x_frame_options(&self, header_value: &str) -> InfrastructureElement {
        let analysis = self.parse_x_frame_options_policy(header_value);

        let mut additional_info = HashMap::new();
        additional_info.insert("security_policy".to_string(), header_value.to_string());
        additional_info.insert(
            "policy_type".to_string(),
            match &analysis.policy {
                XFrameOptionsPolicy::Deny => "DENY".to_string(),
                XFrameOptionsPolicy::SameOrigin => "SAMEORIGIN".to_string(),
                XFrameOptionsPolicy::AllowFrom { uri } => format!("ALLOW-FROM {}", uri),
                XFrameOptionsPolicy::Invalid { value } => format!("INVALID: {}", value),
            },
        );
        additional_info.insert(
            "risk_level".to_string(),
            match analysis.risk_level {
                ClickjackingRiskLevel::None => "None".to_string(),
                ClickjackingRiskLevel::Low => "Low".to_string(),
                ClickjackingRiskLevel::Medium => "Medium".to_string(),
                ClickjackingRiskLevel::High => "High".to_string(),
            },
        );
        additional_info.insert(
            "security_score".to_string(),
            analysis.security_score.to_string(),
        );

        if !analysis.compliance_issues.is_empty() {
            additional_info.insert(
                "compliance_issues".to_string(),
                analysis.compliance_issues.join("; "),
            );
        }

        if !analysis.recommendations.is_empty() {
            additional_info.insert(
                "recommendations".to_string(),
                analysis.recommendations.join("; "),
            );
        }

        let confidence = match analysis.policy {
            XFrameOptionsPolicy::Deny | XFrameOptionsPolicy::SameOrigin => 9,
            XFrameOptionsPolicy::AllowFrom { .. } => 8,
            XFrameOptionsPolicy::Invalid { .. } => 6,
        };

        InfrastructureElement {
            element_type: InfrastructureComponent::SecurityGateway,
            header_name: "x-frame-options".to_string(),
            header_value: header_value.to_string(),
            server_name: None,
            ip_address: None,
            ip_type: None,
            cloud_provider: None,
            cache_status: None,
            x_frame_options_analysis: Some(analysis),
            xss_protection_analysis: None,
            powered_by_analysis: None,
            ua_compatible_analysis: None,
            additional_info,
            confidence,
        }
    }

    fn parse_x_frame_options_policy(&self, header_value: &str) -> XFrameOptionsAnalysis {
        let trimmed_value = header_value.trim();
        let normalized_value = trimmed_value.to_lowercase();

        let (policy, risk_level) = match normalized_value.as_str() {
            "deny" => (XFrameOptionsPolicy::Deny, ClickjackingRiskLevel::None),
            "sameorigin" => (XFrameOptionsPolicy::SameOrigin, ClickjackingRiskLevel::Low),
            value if value.starts_with("allow-from") => {
                if let Some(captures) = X_FRAME_OPTIONS_ALLOW_FROM_REGEX.captures(trimmed_value) {
                    let uri = captures.get(1).unwrap().as_str().to_string();
                    (
                        XFrameOptionsPolicy::AllowFrom { uri },
                        ClickjackingRiskLevel::Medium,
                    )
                } else {
                    (
                        XFrameOptionsPolicy::Invalid {
                            value: trimmed_value.to_string(),
                        },
                        ClickjackingRiskLevel::High,
                    )
                }
            }
            _ => (
                XFrameOptionsPolicy::Invalid {
                    value: trimmed_value.to_string(),
                },
                ClickjackingRiskLevel::High,
            ),
        };

        let mut compliance_issues = Vec::new();
        let mut recommendations = Vec::new();

        match &policy {
            XFrameOptionsPolicy::Deny => {
                recommendations
                    .push("Excellent security posture for clickjacking protection".to_string());
            }
            XFrameOptionsPolicy::SameOrigin => {
                recommendations
                    .push("Good protection against external clickjacking attacks".to_string());
                recommendations
                    .push("Consider DENY policy if embedding is not required".to_string());
            }
            XFrameOptionsPolicy::AllowFrom { uri } => {
                compliance_issues.push(
                    "ALLOW-FROM directive is deprecated and not widely supported".to_string(),
                );
                recommendations.push(
                    "Consider migrating to Content-Security-Policy frame-ancestors directive"
                        .to_string(),
                );
                recommendations.push(format!("Verify that {} is a trusted domain", uri));
            }
            XFrameOptionsPolicy::Invalid { value } => {
                compliance_issues.push(format!("Invalid X-Frame-Options value: {}", value));
                compliance_issues.push("Policy will be ignored by browsers".to_string());
                recommendations
                    .push("Use one of: DENY, SAMEORIGIN, or ALLOW-FROM <uri>".to_string());
                recommendations.push(
                    "Consider implementing Content-Security-Policy frame-ancestors instead"
                        .to_string(),
                );
            }
        }

        if let XFrameOptionsPolicy::AllowFrom { .. } = &policy {
            compliance_issues.push("ALLOW-FROM is not supported in modern browsers".to_string());
        }

        let security_score = match risk_level {
            ClickjackingRiskLevel::None => 10,
            ClickjackingRiskLevel::Low => 8,
            ClickjackingRiskLevel::Medium => 5,
            ClickjackingRiskLevel::High => 2,
        };

        XFrameOptionsAnalysis {
            policy,
            risk_level,
            compliance_issues,
            recommendations,
            security_score,
        }
    }

    fn analyze_generic_xheader(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> InfrastructureElement {
        let component_type = self.identify_component_type(header_value);
        let server_name = self.extract_server_name(header_value);
        let ip_address = self.extract_ip_address(header_value);
        let cloud_provider = ip_address
            .as_ref()
            .and_then(|ip| self.detect_cloud_provider(ip));

        let mut additional_info = HashMap::new();
        additional_info.insert("header_type".to_string(), "generic_x".to_string());

        InfrastructureElement {
            element_type: component_type,
            header_name: header_name.to_string(),
            header_value: header_value.to_string(),
            server_name,
            ip_address: ip_address.clone(),
            ip_type: ip_address.as_ref().map(|ip| self.classify_ip(ip)),
            cloud_provider,
            cache_status: None,
            x_frame_options_analysis: None,
            xss_protection_analysis: None,
            powered_by_analysis: None,
            ua_compatible_analysis: None,
            additional_info,
            confidence: 5,
        }
    }

    fn identify_component_type(&self, value: &str) -> InfrastructureComponent {
        for (component, patterns) in COMPONENT_PATTERNS.iter() {
            for pattern in patterns {
                if pattern.is_match(value) {
                    return component.clone();
                }
            }
        }

        if self.detect_cloud_provider(value).is_some() {
            return InfrastructureComponent::CloudProvider;
        }

        InfrastructureComponent::Unknown
    }

    fn identify_cache_type(
        &self,
        server_name: &str,
        header_value: &str,
    ) -> InfrastructureComponent {
        let combined = format!("{} {}", server_name, header_value).to_lowercase();

        if combined.contains("cloudflare")
            || combined.contains("cloudfront")
            || combined.contains("fastly")
        {
            InfrastructureComponent::Cdn
        } else if combined.contains("varnish") || combined.contains("squid") {
            InfrastructureComponent::Cache
        } else {
            InfrastructureComponent::WebAccelerator
        }
    }

    fn extract_server_name(&self, value: &str) -> Option<String> {
        Regex::new(r"(?i)(?:from\s+)?([a-zA-Z0-9.-]+)")
            .unwrap()
            .captures(value)
            .map(|captures| captures.get(1).unwrap().as_str().to_string())
    }

    fn extract_ip_address(&self, value: &str) -> Option<String> {
        IP_EXTRACTION_REGEX
            .find(value)
            .map(|m| self.clean_ip_address(m.as_str()))
    }

    fn clean_ip_address(&self, ip_str: &str) -> String {
        ip_str
            .trim()
            .trim_matches(|c| c == '[' || c == ']' || c == '"' || c == '\'')
            .to_string()
    }

    fn classify_ip(&self, ip_str: &str) -> IpType {
        match IpAddr::from_str(ip_str) {
            Ok(IpAddr::V4(ipv4)) => self.classify_ipv4(ipv4),
            Ok(IpAddr::V6(ipv6)) => self.classify_ipv6(ipv6),
            Err(_) => IpType::Unknown,
        }
    }

    fn classify_ipv4(&self, ip: Ipv4Addr) -> IpType {
        if ip.is_loopback() {
            IpType::LoopbackIpv4
        } else if ip.is_private() {
            IpType::PrivateIpv4
        } else if ip.is_link_local() {
            IpType::LinkLocalIpv4
        } else if ip.is_multicast() {
            IpType::MulticastIpv4
        } else if self.detect_cloud_provider(&ip.to_string()).is_some() {
            IpType::CloudProvider
        } else {
            IpType::PublicIpv4
        }
    }

    fn classify_ipv6(&self, ip: Ipv6Addr) -> IpType {
        if ip.is_loopback() {
            IpType::LoopbackIpv6
        } else if ip.is_multicast() {
            IpType::MulticastIpv6
        } else {
            let segments = ip.segments();
            if segments[0] & 0xfe00 == 0xfc00 {
                IpType::PrivateIpv6
            } else if segments[0] & 0xffc0 == 0xfe80 {
                IpType::LinkLocalIpv6
            } else if self.detect_cloud_provider(&ip.to_string()).is_some() {
                IpType::CloudProvider
            } else {
                IpType::PublicIpv6
            }
        }
    }

    fn detect_cloud_provider(&self, identifier: &str) -> Option<String> {
        let lower_identifier = identifier.to_lowercase();

        if lower_identifier.contains("cloudflare") {
            return Some("Cloudflare".to_string());
        }
        if lower_identifier.contains("cloudfront") {
            return Some("Amazon CloudFront".to_string());
        }
        if lower_identifier.contains("fastly") {
            return Some("Fastly".to_string());
        }

        for (provider, patterns) in CLOUD_PATTERNS.iter() {
            for pattern in patterns {
                if identifier.starts_with(pattern) {
                    return Some(provider.to_string());
                }
            }
        }

        None
    }

    fn parse_cache_status(&self, status_str: &str) -> CacheStatus {
        match status_str.to_lowercase().as_str() {
            "hit" => CacheStatus::Hit,
            "miss" | "pass" => CacheStatus::Miss,
            "none" => CacheStatus::None,
            "refresh" | "revalidate" => CacheStatus::Refresh,
            _ => CacheStatus::Unknown,
        }
    }

    fn calculate_element_confidence(
        &self,
        component_type: &InfrastructureComponent,
        cloud_provider: &Option<String>,
    ) -> u8 {
        let mut confidence = match component_type {
            InfrastructureComponent::Cdn => 8,
            InfrastructureComponent::LoadBalancer => 7,
            InfrastructureComponent::Cache => 7,
            InfrastructureComponent::ReverseProxy => 6,
            InfrastructureComponent::CloudProvider => 8,
            InfrastructureComponent::SecurityGateway => 6,
            _ => 5,
        };

        if cloud_provider.is_some() {
            confidence += 2;
        }

        confidence.min(10)
    }

    fn analyze_infrastructure(&self, elements: &[InfrastructureElement]) -> InfrastructureAnalysis {
        let mut analysis = InfrastructureAnalysis {
            total_elements: elements.len(),
            components: HashMap::new(),
            cloud_providers: HashMap::new(),
            proxy_chain_length: 0,
            cache_layers: 0,
            has_cdn: false,
            has_load_balancer: false,
            has_waf: false,
            security_concerns: Vec::new(),
            performance_indicators: Vec::new(),
            architecture_insights: Vec::new(),
        };

        let mut forwarded_ips = 0;
        let mut unique_providers = HashSet::new();

        for element in elements {
            *analysis
                .components
                .entry(element.element_type.clone())
                .or_insert(0) += 1;

            if let Some(provider) = &element.cloud_provider {
                *analysis
                    .cloud_providers
                    .entry(provider.clone())
                    .or_insert(0) += 1;
                unique_providers.insert(provider.clone());
            }

            match element.element_type {
                InfrastructureComponent::Cdn => analysis.has_cdn = true,
                InfrastructureComponent::LoadBalancer => analysis.has_load_balancer = true,
                InfrastructureComponent::SecurityGateway => analysis.has_waf = true,
                _ => {}
            }

            if element.header_name == "x-forwarded-for" {
                forwarded_ips += 1;
            }

            if matches!(
                element.element_type,
                InfrastructureComponent::Cache | InfrastructureComponent::Cdn
            ) {
                analysis.cache_layers += 1;
            }
        }

        analysis.proxy_chain_length = forwarded_ips;

        self.generate_architecture_insights(&mut analysis, &unique_providers);
        self.generate_performance_indicators(&mut analysis);
        self.generate_security_concerns(&mut analysis, elements);

        analysis
    }

    fn generate_architecture_insights(
        &self,
        analysis: &mut InfrastructureAnalysis,
        providers: &HashSet<String>,
    ) {
        if providers.len() > 2 {
            analysis
                .architecture_insights
                .push("Multi-cloud architecture detected".to_string());
        }

        if analysis.has_cdn && analysis.has_load_balancer {
            analysis
                .architecture_insights
                .push("Layered traffic distribution".to_string());
        }

        if analysis.cache_layers > 2 {
            analysis
                .architecture_insights
                .push("Multi-tier caching strategy".to_string());
        }

        if analysis.proxy_chain_length > 3 {
            analysis
                .architecture_insights
                .push("Complex proxy chain topology".to_string());
        }
    }

    fn generate_performance_indicators(&self, analysis: &mut InfrastructureAnalysis) {
        if analysis.has_cdn {
            analysis
                .performance_indicators
                .push("Global content delivery".to_string());
        }

        if analysis.cache_layers > 0 {
            analysis
                .performance_indicators
                .push(format!("{}-layer caching", analysis.cache_layers));
        }

        if analysis.has_load_balancer {
            analysis
                .performance_indicators
                .push("Load distribution".to_string());
        }
    }

    fn generate_security_concerns(
        &self,
        analysis: &mut InfrastructureAnalysis,
        elements: &[InfrastructureElement],
    ) {
        if analysis.proxy_chain_length > 5 {
            analysis
                .security_concerns
                .push("Excessive proxy chain length".to_string());
        }

        let mut has_private_ips = false;
        let mut has_public_ips = false;

        for element in elements {
            if let Some(ip_type) = &element.ip_type {
                match ip_type {
                    IpType::PrivateIpv4 | IpType::PrivateIpv6 => has_private_ips = true,
                    IpType::PublicIpv4 | IpType::PublicIpv6 => has_public_ips = true,
                    IpType::LoopbackIpv4 | IpType::LoopbackIpv6 => {
                        analysis
                            .security_concerns
                            .push("Loopback address in chain".to_string());
                    }
                    _ => {}
                }
            }
        }

        if has_private_ips && has_public_ips {
            analysis
                .security_concerns
                .push("Mixed public/private IP topology".to_string());
        }
    }

    fn calculate_confidence(
        &self,
        elements: &[InfrastructureElement],
        analysis: &InfrastructureAnalysis,
    ) -> u8 {
        if elements.is_empty() {
            return 0;
        }

        let avg_confidence =
            elements.iter().map(|e| e.confidence as f64).sum::<f64>() / elements.len() as f64;

        let mut confidence = avg_confidence as u8;

        if analysis.total_elements > 3 {
            confidence += 1;
        }

        if !analysis.cloud_providers.is_empty() {
            confidence += 1;
        }

        if analysis.architecture_insights.len() > 1 {
            confidence += 1;
        }

        confidence.min(10)
    }

    fn format_detection_info(
        &self,
        elements: &[InfrastructureElement],
        analysis: &InfrastructureAnalysis,
    ) -> String {
        let mut parts = Vec::new();

        let component_summary = self.format_component_summary(analysis);
        if !component_summary.is_empty() {
            parts.push(component_summary);
        }

        let key_elements = self.format_key_elements(elements);
        if !key_elements.is_empty() {
            parts.push(key_elements);
        }

        let technology_info = self.format_technology_info(elements);
        if !technology_info.is_empty() {
            parts.push(technology_info);
        }

        let security_info = self.format_security_info(elements);
        if !security_info.is_empty() {
            parts.push(security_info);
        }

        let compatibility_info = self.format_compatibility_info(elements);
        if !compatibility_info.is_empty() {
            parts.push(compatibility_info);
        }

        if !analysis.architecture_insights.is_empty() {
            parts.push(format!(
                "Architecture: {}",
                analysis.architecture_insights.join(", ")
            ));
        }

        if !analysis.performance_indicators.is_empty() {
            parts.push(format!(
                "Performance: {}",
                analysis.performance_indicators.join(", ")
            ));
        }

        if !analysis.security_concerns.is_empty() {
            parts.push(format!(
                "Concerns: {}",
                analysis.security_concerns.join(", ")
            ));
        }

        format!("X-Headers Analysis ({})", parts.join(" | "))
    }

    fn format_component_summary(&self, analysis: &InfrastructureAnalysis) -> String {
        let mut components = Vec::new();

        for (component_type, count) in &analysis.components {
            let type_name = match component_type {
                InfrastructureComponent::Cdn => "CDN",
                InfrastructureComponent::LoadBalancer => "Load Balancer",
                InfrastructureComponent::Cache => "Cache",
                InfrastructureComponent::ReverseProxy => "Reverse Proxy",
                InfrastructureComponent::CloudProvider => "Cloud Provider",
                InfrastructureComponent::SecurityGateway => "Security Gateway",
                InfrastructureComponent::WebAccelerator => "Web Accelerator",
                InfrastructureComponent::Firewall => "Firewall",
                InfrastructureComponent::Unknown => "Unknown",
            };

            if *count == 1 {
                components.push(type_name.to_string());
            } else {
                components.push(format!("{}x {}", count, type_name));
            }
        }

        if !components.is_empty() {
            format!("Components: {}", components.join(", "))
        } else {
            String::new()
        }
    }

    fn format_key_elements(&self, elements: &[InfrastructureElement]) -> String {
        let mut key_info = Vec::new();

        let mut providers = HashMap::new();
        for element in elements {
            if let Some(provider) = &element.cloud_provider {
                *providers.entry(provider.clone()).or_insert(0) += 1;
            }
        }

        for (provider, count) in providers {
            if count == 1 {
                key_info.push(provider);
            } else {
                key_info.push(format!("{}x {}", count, provider));
            }
        }

        if !key_info.is_empty() {
            format!("Providers: {}", key_info.join(", "))
        } else {
            String::new()
        }
    }

    fn analyze_technology_header(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Vec<InfrastructureElement> {
        let mut elements = Vec::new();

        if header_name == "x-powered-by" {
            elements.push(self.analyze_x_powered_by(header_value));
        } else if header_name == "x-ua-compatible" {
            elements.push(self.analyze_x_ua_compatible(header_name, header_value));
        }

        elements
    }

    fn analyze_x_powered_by(&self, header_value: &str) -> InfrastructureElement {
        let analysis = self.parse_powered_by_value(header_value);
        let confidence = self.calculate_powered_by_confidence(&analysis);

        let mut additional_info = HashMap::new();
        additional_info.insert("technology".to_string(), analysis.technology.clone());

        if let Some(version) = &analysis.version {
            additional_info.insert("version".to_string(), version.clone());
        }

        if !analysis.framework.is_empty() {
            additional_info.insert("frameworks".to_string(), analysis.framework.join(", "));
        }

        if !analysis.confidence_factors.is_empty() {
            additional_info.insert(
                "confidence_factors".to_string(),
                analysis.confidence_factors.join(", "),
            );
        }

        InfrastructureElement {
            element_type: InfrastructureComponent::WebAccelerator,
            header_name: "x-powered-by".to_string(),
            header_value: header_value.to_string(),
            server_name: None,
            ip_address: None,
            ip_type: None,
            cloud_provider: None,
            cache_status: None,
            x_frame_options_analysis: None,
            xss_protection_analysis: None,
            powered_by_analysis: Some(analysis),
            ua_compatible_analysis: None,
            additional_info,
            confidence,
        }
    }

    fn parse_powered_by_value(&self, value: &str) -> PoweredByAnalysis {
        let mut framework = Vec::new();
        let mut confidence_factors = Vec::new();
        let lower_value = value.to_lowercase();

        if lower_value.contains("php") {
            framework.push("PHP Framework".to_string());
            confidence_factors.push("PHP identified".to_string());
        }

        if lower_value.contains("asp.net") || lower_value.contains("aspnet") {
            framework.push("ASP.NET Framework".to_string());
            confidence_factors.push("ASP.NET identified".to_string());
        }

        if lower_value.contains("express") {
            framework.push("Express.js".to_string());
            confidence_factors.push("Express.js identified".to_string());
        }

        if lower_value.contains("laravel") {
            framework.push("Laravel Framework".to_string());
            confidence_factors.push("Laravel identified".to_string());
        }

        if lower_value.contains("symfony") {
            framework.push("Symfony Framework".to_string());
            confidence_factors.push("Symfony identified".to_string());
        }

        if lower_value.contains("codeigniter") {
            framework.push("CodeIgniter Framework".to_string());
            confidence_factors.push("CodeIgniter identified".to_string());
        }

        if lower_value.contains("rails") {
            framework.push("Ruby on Rails".to_string());
            confidence_factors.push("Rails identified".to_string());
        }

        if lower_value.contains("django") {
            framework.push("Django Framework".to_string());
            confidence_factors.push("Django identified".to_string());
        }

        if lower_value.contains("flask") {
            framework.push("Flask Framework".to_string());
            confidence_factors.push("Flask identified".to_string());
        }

        if lower_value.contains("node.js") || lower_value.contains("nodejs") {
            framework.push("Node.js".to_string());
            confidence_factors.push("Node.js identified".to_string());
        }

        if lower_value.contains("spring") {
            framework.push("Spring Framework".to_string());
            confidence_factors.push("Spring identified".to_string());
        }

        if lower_value.contains("tomcat") {
            framework.push("Apache Tomcat".to_string());
            confidence_factors.push("Tomcat identified".to_string());
        }

        if lower_value.contains("jetty") {
            framework.push("Eclipse Jetty".to_string());
            confidence_factors.push("Jetty identified".to_string());
        }

        let version = if let Some(captures) = VERSION_EXTRACTION_REGEX.captures(value) {
            confidence_factors.push("Version detected".to_string());
            Some(captures.get(1).unwrap().as_str().to_string())
        } else {
            None
        };

        PoweredByAnalysis {
            technology: value.to_string(),
            framework,
            version,
            confidence_factors,
        }
    }

    fn calculate_powered_by_confidence(&self, analysis: &PoweredByAnalysis) -> u8 {
        let mut confidence = 7u8;

        if !analysis.framework.is_empty() {
            confidence += 2;
        }

        if analysis.version.is_some() {
            confidence += 1;
        }

        confidence.min(10)
    }

    fn analyze_x_xss_protection(&self, header_value: &str) -> InfrastructureElement {
        let analysis = self.parse_xss_protection_value(header_value);
        let confidence = self.calculate_xss_protection_confidence(&analysis);

        let mut additional_info = HashMap::new();
        additional_info.insert("security_policy".to_string(), header_value.to_string());

        let mode_description = match &analysis.mode {
            XSSProtectionMode::Disabled => "Disabled",
            XSSProtectionMode::Enabled => "Enabled",
            XSSProtectionMode::Block => "Enabled with Blocking",
            XSSProtectionMode::Report(url) => &format!("Enabled with Reporting ({})", url),
            XSSProtectionMode::Unknown(_) => "Unknown Configuration",
        };

        additional_info.insert("mode".to_string(), mode_description.to_string());

        let security_level_str = match analysis.security_level {
            SecurityLevel::High => "High Security",
            SecurityLevel::Medium => "Medium Security",
            SecurityLevel::Low => "Low Security",
            SecurityLevel::None => "No Protection",
            SecurityLevel::Unknown => "Unknown Security",
        };

        additional_info.insert("security_level".to_string(), security_level_str.to_string());
        additional_info.insert(
            "security_score".to_string(),
            analysis.security_score.to_string(),
        );

        if !analysis.compliance_notes.is_empty() {
            additional_info.insert(
                "compliance_notes".to_string(),
                analysis.compliance_notes.join("; "),
            );
        }

        if !analysis.recommendations.is_empty() {
            additional_info.insert(
                "recommendations".to_string(),
                analysis.recommendations.join("; "),
            );
        }

        InfrastructureElement {
            element_type: InfrastructureComponent::SecurityGateway,
            header_name: "x-xss-protection".to_string(),
            header_value: header_value.to_string(),
            server_name: None,
            ip_address: None,
            ip_type: None,
            cloud_provider: None,
            cache_status: None,
            x_frame_options_analysis: None,
            xss_protection_analysis: Some(analysis),
            powered_by_analysis: None,
            ua_compatible_analysis: None,
            additional_info,
            confidence,
        }
    }

    fn parse_xss_protection_value(&self, header_value: &str) -> XSSProtectionAnalysis {
        let mode = self.parse_xss_protection_mode(header_value);
        let security_level = self.determine_xss_security_level(&mode);
        let (compliance_notes, recommendations) = self.generate_xss_security_analysis(&mode);
        let security_score = self.calculate_xss_security_score(&mode);

        XSSProtectionAnalysis {
            mode,
            security_level,
            compliance_notes,
            recommendations,
            security_score,
        }
    }

    fn parse_xss_protection_mode(&self, header_value: &str) -> XSSProtectionMode {
        let trimmed = header_value.trim();
        let lower_value = trimmed.to_lowercase();

        if lower_value == "0" {
            XSSProtectionMode::Disabled
        } else if lower_value == "1" {
            XSSProtectionMode::Enabled
        } else if lower_value.starts_with("1") {
            if lower_value.contains("mode=block") {
                XSSProtectionMode::Block
            } else if lower_value.contains("report=") {
                if let Some(report_start) = lower_value.find("report=") {
                    let report_part = &trimmed[report_start + 7..];
                    if let Some(semicolon) = report_part.find(';') {
                        let url = report_part[..semicolon].trim().to_string();
                        XSSProtectionMode::Report(url)
                    } else {
                        let url = report_part.trim().to_string();
                        XSSProtectionMode::Report(url)
                    }
                } else {
                    XSSProtectionMode::Enabled
                }
            } else {
                XSSProtectionMode::Enabled
            }
        } else {
            XSSProtectionMode::Unknown(trimmed.to_string())
        }
    }

    fn determine_xss_security_level(&self, mode: &XSSProtectionMode) -> SecurityLevel {
        match mode {
            XSSProtectionMode::Block => SecurityLevel::High,
            XSSProtectionMode::Report(_) => SecurityLevel::Medium,
            XSSProtectionMode::Enabled => SecurityLevel::Low,
            XSSProtectionMode::Disabled => SecurityLevel::None,
            XSSProtectionMode::Unknown(_) => SecurityLevel::Unknown,
        }
    }

    fn generate_xss_security_analysis(
        &self,
        mode: &XSSProtectionMode,
    ) -> (Vec<String>, Vec<String>) {
        let mut compliance_notes = Vec::new();
        let mut recommendations = Vec::new();

        match mode {
            XSSProtectionMode::Disabled => {
                compliance_notes.push("XSS protection is disabled".to_string());
                recommendations.push("Enable XSS protection with '1; mode=block'".to_string());
                recommendations
                    .push("Consider implementing Content Security Policy (CSP)".to_string());
            }
            XSSProtectionMode::Enabled => {
                compliance_notes.push("Basic XSS protection enabled".to_string());
                recommendations
                    .push("Consider using 'mode=block' for stronger protection".to_string());
                recommendations.push(
                    "XSS Auditor may have compatibility issues with modern browsers".to_string(),
                );
            }
            XSSProtectionMode::Block => {
                compliance_notes.push("XSS protection enabled with blocking mode".to_string());
                recommendations.push("Good security configuration".to_string());
                recommendations.push(
                    "Consider migrating to Content Security Policy for modern browsers".to_string(),
                );
            }
            XSSProtectionMode::Report(url) => {
                compliance_notes.push("XSS protection enabled with reporting".to_string());
                recommendations.push(format!("Verify report URL is accessible: {}", url));
                recommendations
                    .push("Consider adding 'mode=block' for better protection".to_string());
            }
            XSSProtectionMode::Unknown(value) => {
                compliance_notes.push(format!("Unknown X-XSS-Protection value: {}", value));
                compliance_notes
                    .push("Invalid configuration may not provide protection".to_string());
                recommendations
                    .push("Use standard values: '0', '1', or '1; mode=block'".to_string());
            }
        }

        compliance_notes.push("X-XSS-Protection is deprecated in modern browsers".to_string());
        recommendations
            .push("Implement Content-Security-Policy for comprehensive XSS protection".to_string());

        (compliance_notes, recommendations)
    }

    fn calculate_xss_security_score(&self, mode: &XSSProtectionMode) -> u8 {
        match mode {
            XSSProtectionMode::Block => 8,
            XSSProtectionMode::Report(_) => 6,
            XSSProtectionMode::Enabled => 4,
            XSSProtectionMode::Disabled => 2,
            XSSProtectionMode::Unknown(_) => 1,
        }
    }

    fn calculate_xss_protection_confidence(&self, analysis: &XSSProtectionAnalysis) -> u8 {
        let mut confidence = 8u8;

        match analysis.mode {
            XSSProtectionMode::Block | XSSProtectionMode::Report(_) => confidence += 2,
            XSSProtectionMode::Enabled => confidence += 1,
            XSSProtectionMode::Disabled => confidence += 1,
            XSSProtectionMode::Unknown(_) => confidence -= 1,
        }

        confidence.min(10)
    }

    fn analyze_x_ua_compatible(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> InfrastructureElement {
        let analysis = self.parse_ua_compatible_value(header_value, header_name);
        let confidence = self.calculate_ua_compatible_confidence(&analysis);

        let mut additional_info = HashMap::new();
        additional_info.insert("compatibility_value".to_string(), header_value.to_string());

        if !analysis.sources.is_empty() {
            additional_info.insert("sources".to_string(), analysis.sources.join(", "));
        }

        if !analysis.insights.is_empty() {
            additional_info.insert("insights".to_string(), analysis.insights.join(", "));
        }

        additional_info.insert(
            "compatibility_score".to_string(),
            analysis.compatibility_score.to_string(),
        );

        let _source_type = if header_name == "x-ua-compatible" {
            "http_header"
        } else {
            "meta_tag"
        };

        InfrastructureElement {
            element_type: InfrastructureComponent::WebAccelerator,
            header_name: header_name.to_string(),
            header_value: header_value.to_string(),
            server_name: None,
            ip_address: None,
            ip_type: None,
            cloud_provider: None,
            cache_status: None,
            x_frame_options_analysis: None,
            xss_protection_analysis: None,
            powered_by_analysis: None,
            ua_compatible_analysis: Some(analysis),
            additional_info,
            confidence,
        }
    }

    fn parse_ua_compatible_value(&self, header_value: &str, source: &str) -> UACompatibleAnalysis {
        let mut modes = Vec::new();
        let mut insights = Vec::new();
        let lower_value = header_value.to_lowercase();

        if lower_value.contains("ie=edge") {
            modes.push(UACompatibilityMode::IEEdge);
            insights.push("IE Edge Mode".to_string());
        } else if lower_value.contains("ie=11") {
            modes.push(UACompatibilityMode::IE11);
            insights.push("IE 11 Mode".to_string());
        } else if lower_value.contains("ie=10") {
            modes.push(UACompatibilityMode::IE10);
            insights.push("IE 10 Mode".to_string());
        } else if lower_value.contains("ie=9") {
            modes.push(UACompatibilityMode::IE9);
            insights.push("IE 9 Mode".to_string());
        } else if lower_value.contains("ie=8") {
            modes.push(UACompatibilityMode::IE8);
            insights.push("IE 8 Mode".to_string());
        } else if lower_value.contains("ie=7") {
            modes.push(UACompatibilityMode::IE7);
            insights.push("IE 7 Mode".to_string());
        } else if lower_value.contains("ie=") {
            modes.push(UACompatibilityMode::Unknown(header_value.to_string()));
            insights.push("IE Compatibility Mode".to_string());
        }

        if lower_value.contains("emulateie") {
            if let Some(version) = lower_value
                .strip_prefix("emulateie")
                .and_then(|v| v.chars().next())
            {
                modes.push(UACompatibilityMode::IEEmulation(version.to_string()));
                insights.push("IE Emulation Mode".to_string());
            }
        }

        if lower_value.contains("chrome=1") {
            modes.push(UACompatibilityMode::ChromeFrame);
            insights.push("Chrome Frame".to_string());
        }

        if lower_value == "edge" {
            modes.push(UACompatibilityMode::MicrosoftEdge);
            insights.push("Microsoft Edge Mode".to_string());
        }

        let compatibility_score = match modes.first() {
            Some(UACompatibilityMode::IEEdge) => 9,
            Some(UACompatibilityMode::IE11) => 8,
            Some(UACompatibilityMode::IE10) => 7,
            Some(UACompatibilityMode::IE9) => 6,
            Some(UACompatibilityMode::IE8) => 5,
            Some(UACompatibilityMode::IE7) => 4,
            Some(UACompatibilityMode::MicrosoftEdge) => 10,
            Some(UACompatibilityMode::ChromeFrame) => 8,
            _ => 3,
        };

        let source_type = if source == "x-ua-compatible" {
            "http_header".to_string()
        } else {
            "meta_tag".to_string()
        };

        UACompatibleAnalysis {
            modes,
            sources: vec![source_type],
            insights,
            compatibility_score,
        }
    }

    fn calculate_ua_compatible_confidence(&self, analysis: &UACompatibleAnalysis) -> u8 {
        let mut confidence = 6u8;

        if analysis.sources.contains(&"http_header".to_string()) {
            confidence += 2;
        }

        if analysis.sources.contains(&"meta_tag".to_string()) {
            confidence += 2;
        }

        if !analysis.modes.is_empty() {
            confidence += 1;
        }

        confidence.min(10)
    }

    fn format_technology_info(&self, elements: &[InfrastructureElement]) -> String {
        let mut tech_info = Vec::new();

        for element in elements {
            if let Some(analysis) = &element.powered_by_analysis {
                if !analysis.framework.is_empty() {
                    tech_info.push(format!("Tech: {}", analysis.framework.join(", ")));
                } else {
                    tech_info.push(format!("Tech: {}", analysis.technology));
                }
            }
        }

        if !tech_info.is_empty() {
            tech_info.join(", ")
        } else {
            String::new()
        }
    }

    fn format_security_info(&self, elements: &[InfrastructureElement]) -> String {
        let mut security_info = Vec::new();

        for element in elements {
            if let Some(analysis) = &element.x_frame_options_analysis {
                let policy_str = match &analysis.policy {
                    XFrameOptionsPolicy::Deny => "Frame: DENY",
                    XFrameOptionsPolicy::SameOrigin => "Frame: SAMEORIGIN",
                    XFrameOptionsPolicy::AllowFrom { .. } => "Frame: ALLOW-FROM",
                    XFrameOptionsPolicy::Invalid { .. } => "Frame: Invalid",
                };
                security_info.push(format!(
                    "{} (Score: {})",
                    policy_str, analysis.security_score
                ));
            }

            if let Some(analysis) = &element.xss_protection_analysis {
                let mode_str = match &analysis.mode {
                    XSSProtectionMode::Disabled => "XSS: Disabled",
                    XSSProtectionMode::Enabled => "XSS: Enabled",
                    XSSProtectionMode::Block => "XSS: Block",
                    XSSProtectionMode::Report(_) => "XSS: Report",
                    XSSProtectionMode::Unknown(_) => "XSS: Unknown",
                };
                security_info.push(format!("{} (Score: {})", mode_str, analysis.security_score));
            }
        }

        if !security_info.is_empty() {
            format!("Security: {}", security_info.join(", "))
        } else {
            String::new()
        }
    }

    fn format_compatibility_info(&self, elements: &[InfrastructureElement]) -> String {
        let mut compat_info = Vec::new();

        for element in elements {
            if let Some(analysis) = &element.ua_compatible_analysis {
                if !analysis.insights.is_empty() {
                    compat_info.push(format!(
                        "IE-Compat: {} (Score: {})",
                        analysis.insights.join(", "),
                        analysis.compatibility_score
                    ));
                }
            }
        }

        if !compat_info.is_empty() {
            compat_info.join(", ")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::httpinner::HttpInner;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn create_test_http_inner(headers: HeaderMap, status: u16) -> HttpInner {
        HttpInner::new_with_all(
            headers,
            String::new(),
            status,
            "https://example.com".to_string(),
            true,
        )
    }

    #[test]
    fn test_plugin_metadata() {
        let plugin = XHeadersPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "X-Headers Comprehensive");
        assert_eq!(metadata.version, "4.0.0");
        assert!(metadata
            .description
            .contains("Unified comprehensive X-Headers detection"));
        assert_eq!(metadata.category, PluginCategory::LoadBalancer);
        assert!(metadata.enabled);
    }

    #[test]
    fn test_comprehensive_infrastructure_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();

        headers.insert("x-backend", HeaderValue::from_static("lb-1.example.com"));
        headers.insert("x-cache", HeaderValue::from_static("HIT from cloudfront"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.168.1.1, 104.16.1.1"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "X-Headers Comprehensive");
        assert!(pr.detection_info.contains("X-Headers Analysis"));
        assert!(
            pr.detection_info.contains("Components") || pr.detection_info.contains("Architecture")
        );
        assert!(pr.confidence >= 7);
    }

    #[test]
    fn test_cloud_provider_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-served-by", HeaderValue::from_static("cache-sea4460-SEA"));
        headers.insert("x-cache", HeaderValue::from_static("HIT from cloudfront"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(
            pr.detection_info.contains("Amazon CloudFront") || pr.detection_info.contains("CDN")
        );
    }

    #[test]
    fn test_proxy_chain_analysis() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 192.168.1.1, 52.1.1.1"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("X-Headers Analysis"));
        assert!(pr.confidence >= 6);
    }

    #[test]
    fn test_security_header_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert(
            "x-xss-protection",
            HeaderValue::from_static("1; mode=block"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(
            pr.detection_info.contains("Security Gateway")
                || pr.detection_info.contains("Security")
        );
    }

    #[test]
    fn test_no_infrastructure_headers() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("content-length", HeaderValue::from_static("1234"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_none());
    }

    #[test]
    fn test_should_run_optimization() {
        let plugin = XHeadersPlugin;

        let mut headers = HeaderMap::new();
        headers.insert("x-backend", HeaderValue::from_static("server1"));
        let http_inner = create_test_http_inner(headers, 200);
        assert!(plugin.should_run(&http_inner));

        let headers_empty = HeaderMap::new();
        let http_inner_empty = create_test_http_inner(headers_empty, 200);
        assert!(!plugin.should_run(&http_inner_empty));
    }

    #[test]
    fn test_failed_http_request() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-backend", HeaderValue::from_static("server1"));

        let http_inner = HttpInner::new_with_all(
            headers,
            String::new(),
            500,
            "https://example.com".to_string(),
            false,
        );

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_ip_classification() {
        let plugin = XHeadersPlugin;

        assert_eq!(plugin.classify_ip("127.0.0.1"), IpType::LoopbackIpv4);
        assert_eq!(plugin.classify_ip("192.168.1.1"), IpType::PrivateIpv4);
        assert_eq!(plugin.classify_ip("8.8.8.8"), IpType::PublicIpv4);
        assert_eq!(plugin.classify_ip("::1"), IpType::LoopbackIpv6);
        assert_eq!(plugin.classify_ip("invalid-ip"), IpType::Unknown);
    }

    #[test]
    fn test_cache_status_parsing() {
        let plugin = XHeadersPlugin;

        assert_eq!(plugin.parse_cache_status("HIT"), CacheStatus::Hit);
        assert_eq!(plugin.parse_cache_status("miss"), CacheStatus::Miss);
        assert_eq!(plugin.parse_cache_status("NONE"), CacheStatus::None);
        assert_eq!(plugin.parse_cache_status("refresh"), CacheStatus::Refresh);
        assert_eq!(plugin.parse_cache_status("unknown"), CacheStatus::Unknown);
    }

    #[test]
    fn test_cloud_provider_detection_method() {
        let plugin = XHeadersPlugin;

        assert_eq!(
            plugin.detect_cloud_provider("104.16.1.1"),
            Some("Cloudflare".to_string())
        );
        assert_eq!(
            plugin.detect_cloud_provider("52.1.1.1"),
            Some("Amazon AWS".to_string())
        );
        assert_eq!(
            plugin.detect_cloud_provider("cloudfront.example.com"),
            Some("Amazon CloudFront".to_string())
        );
        assert_eq!(plugin.detect_cloud_provider("192.168.1.1"), None);
    }

    #[test]
    fn test_x_frame_options_deny_policy() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.confidence, 9);
        assert!(pr.detection_info.contains("Security"));
    }

    #[test]
    fn test_x_frame_options_sameorigin_policy() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.confidence, 9);
    }

    #[test]
    fn test_x_frame_options_allow_from_valid() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-frame-options",
            HeaderValue::from_static("ALLOW-FROM https://trusted.example.com"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.confidence, 8);
    }

    #[test]
    fn test_x_frame_options_allow_from_invalid() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-frame-options",
            HeaderValue::from_static("ALLOW-FROM invalid-uri"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.confidence, 6);
    }

    #[test]
    fn test_x_frame_options_invalid_value() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-frame-options",
            HeaderValue::from_static("INVALID_POLICY"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.confidence, 6);
    }

    #[test]
    fn test_parse_x_frame_options_policy_deny() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("DENY");

        assert_eq!(analysis.policy, XFrameOptionsPolicy::Deny);
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::None);
        assert_eq!(analysis.security_score, 10);
        assert!(analysis.compliance_issues.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_parse_x_frame_options_policy_sameorigin() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("sameorigin");

        assert_eq!(analysis.policy, XFrameOptionsPolicy::SameOrigin);
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::Low);
        assert_eq!(analysis.security_score, 8);
        assert!(analysis.compliance_issues.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_parse_x_frame_options_policy_allow_from_valid() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("ALLOW-FROM https://example.com");

        match analysis.policy {
            XFrameOptionsPolicy::AllowFrom { uri } => {
                assert_eq!(uri, "https://example.com");
            }
            _ => panic!("Expected AllowFrom policy"),
        }
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::Medium);
        assert_eq!(analysis.security_score, 5);
        assert!(!analysis.compliance_issues.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_parse_x_frame_options_policy_allow_from_invalid() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("ALLOW-FROM invalid");

        match analysis.policy {
            XFrameOptionsPolicy::Invalid { value } => {
                assert_eq!(value, "ALLOW-FROM invalid");
            }
            _ => panic!("Expected Invalid policy"),
        }
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::High);
        assert_eq!(analysis.security_score, 2);
        assert!(!analysis.compliance_issues.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_parse_x_frame_options_policy_invalid() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("UNKNOWN_VALUE");

        match analysis.policy {
            XFrameOptionsPolicy::Invalid { value } => {
                assert_eq!(value, "UNKNOWN_VALUE");
            }
            _ => panic!("Expected Invalid policy"),
        }
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::High);
        assert_eq!(analysis.security_score, 2);
        assert!(!analysis.compliance_issues.is_empty());
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_x_frame_options_case_insensitive() {
        let plugin = XHeadersPlugin;
        let analysis_upper = plugin.parse_x_frame_options_policy("DENY");
        let analysis_lower = plugin.parse_x_frame_options_policy("deny");
        let analysis_mixed = plugin.parse_x_frame_options_policy("Deny");

        assert_eq!(analysis_upper.policy, analysis_lower.policy);
        assert_eq!(analysis_lower.policy, analysis_mixed.policy);
        assert_eq!(analysis_upper.risk_level, analysis_lower.risk_level);
        assert_eq!(analysis_upper.security_score, analysis_lower.security_score);
    }

    #[test]
    fn test_x_frame_options_whitespace_handling() {
        let plugin = XHeadersPlugin;
        let analysis = plugin.parse_x_frame_options_policy("  SAMEORIGIN  ");

        assert_eq!(analysis.policy, XFrameOptionsPolicy::SameOrigin);
        assert_eq!(analysis.risk_level, ClickjackingRiskLevel::Low);
    }

    #[test]
    fn test_x_powered_by_php_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.1.0"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "X-Headers Comprehensive");
        assert!(pr.detection_info.contains("X-Headers Analysis"));
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_x_powered_by_aspnet_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", HeaderValue::from_static("ASP.NET"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_parse_powered_by_value() {
        let plugin = XHeadersPlugin;

        let php_analysis = plugin.parse_powered_by_value("PHP/8.1.0");
        assert_eq!(php_analysis.technology, "PHP/8.1.0");
        assert!(php_analysis
            .framework
            .contains(&"PHP Framework".to_string()));
        assert_eq!(php_analysis.version, Some("8.1.0".to_string()));
        assert!(php_analysis
            .confidence_factors
            .contains(&"PHP identified".to_string()));
        assert!(php_analysis
            .confidence_factors
            .contains(&"Version detected".to_string()));

        let express_analysis = plugin.parse_powered_by_value("Express");
        assert!(express_analysis
            .framework
            .contains(&"Express.js".to_string()));
        assert!(express_analysis
            .confidence_factors
            .contains(&"Express.js identified".to_string()));

        let laravel_analysis = plugin.parse_powered_by_value("Laravel Framework");
        assert!(laravel_analysis
            .framework
            .contains(&"Laravel Framework".to_string()));
    }

    #[test]
    fn test_powered_by_confidence_calculation() {
        let plugin = XHeadersPlugin;

        let php_analysis = plugin.parse_powered_by_value("PHP/8.1.0");
        let confidence = plugin.calculate_powered_by_confidence(&php_analysis);
        assert_eq!(confidence, 10);

        let generic_analysis = plugin.parse_powered_by_value("Unknown");
        let confidence = plugin.calculate_powered_by_confidence(&generic_analysis);
        assert_eq!(confidence, 7);
    }

    #[test]
    fn test_x_xss_protection_disabled() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-xss-protection", HeaderValue::from_static("0"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "X-Headers Comprehensive");
        assert!(pr.confidence >= 7);
    }

    #[test]
    fn test_x_xss_protection_block_mode() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-xss-protection",
            HeaderValue::from_static("1; mode=block"),
        );

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.confidence >= 9);
    }

    #[test]
    fn test_parse_xss_protection_modes() {
        let plugin = XHeadersPlugin;

        let disabled = plugin.parse_xss_protection_mode("0");
        assert_eq!(disabled, XSSProtectionMode::Disabled);

        let enabled = plugin.parse_xss_protection_mode("1");
        assert_eq!(enabled, XSSProtectionMode::Enabled);

        let block = plugin.parse_xss_protection_mode("1; mode=block");
        assert_eq!(block, XSSProtectionMode::Block);

        let report = plugin.parse_xss_protection_mode("1; report=https://example.com");
        match report {
            XSSProtectionMode::Report(url) => assert_eq!(url, "https://example.com"),
            _ => panic!("Expected Report mode"),
        }

        let unknown = plugin.parse_xss_protection_mode("invalid");
        match unknown {
            XSSProtectionMode::Unknown(value) => assert_eq!(value, "invalid"),
            _ => panic!("Expected Unknown mode"),
        }
    }

    #[test]
    fn test_xss_protection_security_levels() {
        let plugin = XHeadersPlugin;

        assert_eq!(
            plugin.determine_xss_security_level(&XSSProtectionMode::Block),
            SecurityLevel::High
        );
        assert_eq!(
            plugin.determine_xss_security_level(&XSSProtectionMode::Report("url".to_string())),
            SecurityLevel::Medium
        );
        assert_eq!(
            plugin.determine_xss_security_level(&XSSProtectionMode::Enabled),
            SecurityLevel::Low
        );
        assert_eq!(
            plugin.determine_xss_security_level(&XSSProtectionMode::Disabled),
            SecurityLevel::None
        );
    }

    #[test]
    fn test_xss_protection_security_score() {
        let plugin = XHeadersPlugin;

        assert_eq!(
            plugin.calculate_xss_security_score(&XSSProtectionMode::Block),
            8
        );
        assert_eq!(
            plugin.calculate_xss_security_score(&XSSProtectionMode::Report("url".to_string())),
            6
        );
        assert_eq!(
            plugin.calculate_xss_security_score(&XSSProtectionMode::Enabled),
            4
        );
        assert_eq!(
            plugin.calculate_xss_security_score(&XSSProtectionMode::Disabled),
            2
        );
        assert_eq!(
            plugin.calculate_xss_security_score(&XSSProtectionMode::Unknown("test".to_string())),
            1
        );
    }

    #[test]
    fn test_x_ua_compatible_header_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-ua-compatible", HeaderValue::from_static("IE=edge"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "X-Headers Comprehensive");
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_x_ua_compatible_meta_tag_detection() {
        let plugin = XHeadersPlugin;
        let headers = HeaderMap::new();
        let body = r#"<html><head><meta http-equiv=\"X-UA-Compatible\" content=\"IE=11\" /></head></html>"#;

        let http_inner = HttpInner::new_with_all(
            headers,
            body.to_string(),
            200,
            "https://example.com".to_string(),
            true,
        );
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.confidence >= 7);
    }

    #[test]
    fn test_parse_ua_compatible_modes() {
        let plugin = XHeadersPlugin;

        let edge_analysis = plugin.parse_ua_compatible_value("IE=edge", "x-ua-compatible");
        assert!(edge_analysis.modes.contains(&UACompatibilityMode::IEEdge));
        assert!(edge_analysis.insights.contains(&"IE Edge Mode".to_string()));
        assert_eq!(edge_analysis.compatibility_score, 9);

        let ie11_analysis = plugin.parse_ua_compatible_value("IE=11", "x-ua-compatible");
        assert!(ie11_analysis.modes.contains(&UACompatibilityMode::IE11));
        assert!(ie11_analysis.insights.contains(&"IE 11 Mode".to_string()));

        let chrome_frame_analysis =
            plugin.parse_ua_compatible_value("IE=edge,chrome=1", "x-ua-compatible");
        assert!(chrome_frame_analysis
            .modes
            .contains(&UACompatibilityMode::IEEdge));
        assert!(chrome_frame_analysis
            .modes
            .contains(&UACompatibilityMode::ChromeFrame));
        assert!(chrome_frame_analysis
            .insights
            .contains(&"Chrome Frame".to_string()));

        let edge_mode_analysis = plugin.parse_ua_compatible_value("edge", "x-ua-compatible");
        assert!(edge_mode_analysis
            .modes
            .contains(&UACompatibilityMode::MicrosoftEdge));
        assert!(edge_mode_analysis
            .insights
            .contains(&"Microsoft Edge Mode".to_string()));
        assert_eq!(edge_mode_analysis.compatibility_score, 10);
    }

    #[test]
    fn test_ua_compatible_confidence_calculation() {
        let plugin = XHeadersPlugin;

        let header_analysis = plugin.parse_ua_compatible_value("IE=edge", "x-ua-compatible");
        let confidence = plugin.calculate_ua_compatible_confidence(&header_analysis);
        assert_eq!(confidence, 9);

        let meta_analysis = plugin.parse_ua_compatible_value("IE=11", "meta_tag");
        let confidence = plugin.calculate_ua_compatible_confidence(&meta_analysis);
        assert_eq!(confidence, 9);
    }

    #[test]
    fn test_multiple_x_headers_detection() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.1.0"));
        headers.insert(
            "x-xss-protection",
            HeaderValue::from_static("1; mode=block"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        headers.insert("x-ua-compatible", HeaderValue::from_static("IE=edge"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "X-Headers Comprehensive");
        assert!(pr.detection_info.contains("X-Headers Analysis"));
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_technology_header_analysis() {
        let plugin = XHeadersPlugin;

        let elements = plugin.analyze_technology_header("x-powered-by", "PHP/7.4.0");
        assert_eq!(elements.len(), 1);
        assert!(elements[0].powered_by_analysis.is_some());

        let elements = plugin.analyze_technology_header("x-ua-compatible", "IE=11");
        assert_eq!(elements.len(), 1);
        assert!(elements[0].ua_compatible_analysis.is_some());
    }

    #[test]
    fn test_case_insensitive_header_parsing() {
        let plugin = XHeadersPlugin;

        let upper_block = plugin.parse_xss_protection_mode("1; MODE=BLOCK");
        assert_eq!(upper_block, XSSProtectionMode::Block);

        let mixed_analysis = plugin.parse_ua_compatible_value("ie=EDGE", "x-ua-compatible");
        assert!(mixed_analysis.modes.contains(&UACompatibilityMode::IEEdge));
    }

    #[test]
    fn test_enhanced_detection_info_formatting() {
        let plugin = XHeadersPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.1.0"));
        headers.insert(
            "x-xss-protection",
            HeaderValue::from_static("1; mode=block"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert("x-ua-compatible", HeaderValue::from_static("IE=edge"));

        let http_inner = create_test_http_inner(headers, 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        let info = &pr.detection_info;

        assert!(info.contains("X-Headers Analysis"));

        assert!(info.contains("Tech:") || info.contains("PHP"));

        assert!(info.contains("Security:"));
        assert!(info.contains("Frame:") || info.contains("XSS:"));

        assert!(info.contains("IE-Compat:") || info.contains("IE Edge"));

        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_analyze_x_frame_options_element_creation() {
        let plugin = XHeadersPlugin;
        let element = plugin.analyze_x_frame_options("DENY");

        assert_eq!(
            element.element_type,
            InfrastructureComponent::SecurityGateway
        );
        assert_eq!(element.header_name, "x-frame-options");
        assert_eq!(element.header_value, "DENY");
        assert_eq!(element.confidence, 9);
        assert!(element.x_frame_options_analysis.is_some());

        let analysis = element.x_frame_options_analysis.unwrap();
        assert_eq!(analysis.policy, XFrameOptionsPolicy::Deny);
        assert_eq!(analysis.security_score, 10);
    }
}
