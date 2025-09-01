// File: http.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::config::ConfigParameter;
use crate::getstate::GetState;
use crate::httpinner::HttpInner;
use crate::screenshot;
use futures::stream::{self, StreamExt};
use governor::{clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter};
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use log::{debug, error, trace};
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

use reqwest::Url;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

fn validate_url(url: &str) -> Result<Url, Box<dyn std::error::Error + Send + Sync>> {
    let parsed = Url::parse(url)?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Invalid URL scheme".into()),
    }

    if parsed.host_str().is_none() {
        return Err("Invalid host".into());
    }

    if is_internal_address(&parsed)? {
        return Err("Internal addresses not allowed".into());
    }

    Ok(parsed)
}

fn is_internal_address(url: &Url) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(host) = url.host() {
        match host {
            url::Host::Domain(domain) => {
                let socket_addr = format!("{}:80", domain);
                match socket_addr.to_socket_addrs() {
                    Ok(addrs) => {
                        for addr in addrs {
                            if is_private_ip(&addr.ip()) {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    Err(_) => Ok(false),
                }
            }
            url::Host::Ipv4(ip) => Ok(is_private_ipv4(&ip)),
            url::Host::Ipv6(ip) => Ok(is_private_ipv6(&ip)),
        }
    } else {
        Ok(false)
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || *ip == Ipv4Addr::new(169, 254, 169, 254)
        || ip.octets()[0] == 127
        || (ip.octets()[0] == 10)
        || (ip.octets()[0] == 172 && ip.octets()[1] >= 16 && ip.octets()[1] <= 31)
        || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_multicast() || (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[derive(Debug)]
pub struct Http {
    pub state_ptr: Arc<GetState>,
    pub config_ptr: ConfigParameter,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, HttpInner>>>,
}

impl Http {
    pub fn new(
        state_ptr: Arc<GetState>,
        config_ptr: ConfigParameter,
        rate_limit: NonZeroU32,
    ) -> Self {
        debug!(
            "Creating HTTP client with timeout={}s, rate_limit={}/s, user_agent=rprobe/{}",
            config_ptr.timeout(),
            rate_limit,
            env!("CARGO_PKG_VERSION")
        );

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config_ptr.timeout()))
            .user_agent(format!("rprobe/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Failed to build reqwest client");

        debug!("HTTP client created successfully");

        Http {
            state_ptr,
            config_ptr,
            rate_limiter: Arc::new(RateLimiter::direct(Quota::per_second(rate_limit))),
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn work(&mut self, lines_vec: Arc<Vec<String>>) -> Vec<HttpInner> {
        debug!(
            "Starting HTTP operations for {} targets with {} workers",
            lines_vec.len(),
            self.config_ptr.workers()
        );

        let output_dir = self.config_ptr.output_dir();
        if !Path::new(output_dir).exists() {
            debug!("Creating output directory: {}", output_dir);
            if let Err(e) = fs::create_dir_all(output_dir) {
                error!("Failed to create output directory {}: {}", output_dir, e);
            }
        } else {
            debug!("Output directory exists: {}", output_dir);
        }

        let mp = MultiProgress::new();
        let main_pb = mp.add(ProgressBar::new(lines_vec.len() as u64));
        main_pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let worker_pb = mp.add(ProgressBar::new_spinner());
        worker_pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        worker_pb.set_message("Processing requests...");

        let mp_handle = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });

        let timeout = self.config_ptr.timeout();
        let client = self.client.clone();
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let state_ptr = Arc::clone(&self.state_ptr);
        let take_screenshot = self.config_ptr.screenshot();
        let output_dir = self.config_ptr.output_dir().to_string();
        let cache = self.cache.clone();
        let config_ptr = self.config_ptr.clone();

        let semaphore = Arc::new(Semaphore::new(self.config_ptr.workers() as usize));

        let mut results = Vec::with_capacity(lines_vec.len());

        let tasks = stream::iter(lines_vec.iter().cloned())
            .map(|url| {
                let client = client.clone();
                let rate_limiter = Arc::clone(&rate_limiter);
                let state_ptr = Arc::clone(&state_ptr);
                let cache = cache.clone();
                let config_ptr = config_ptr.clone();
                let output_dir = output_dir.clone();
                let semaphore = semaphore.clone();
                let main_pb = main_pb.clone();

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    trace!("Acquired semaphore permit for URL: {}", url);

                    rate_limiter.until_ready().await;
                    trace!("Rate limiter ready for URL: {}", url);
                    if url.trim().is_empty() {
                        main_pb.inc(1);
                        return HttpInner::new_with_all(
                            HeaderMap::new(),
                            "Empty URL".to_string(),
                            0,
                            url,
                            false,
                        );
                    }

                    if let Some(cached) = cache.lock().unwrap().get(&url).cloned() {
                        debug!("Cache hit: loaded URL {} from cache", url);
                        main_pb.inc(1);
                        return cached;
                    }
                    trace!("Cache miss: URL {} not in cache", url);

                    let clean_url = url.trim();
                    let final_url = if !clean_url.starts_with("http://")
                        && !clean_url.starts_with("https://")
                    {
                        let prefixed = if config_ptr.https() {
                            format!("https://{}", clean_url)
                        } else if config_ptr.http() {
                            format!("http://{}", clean_url)
                        } else {
                            format!("https://{}", clean_url)
                        };
                        trace!("Added protocol prefix: {} -> {}", clean_url, prefixed);
                        prefixed
                    } else {
                        clean_url.to_string()
                    };

                    debug!("Starting HTTP request for URL: {}", final_url);

                    let validated_url = match validate_url(&final_url) {
                        Ok(url) => {
                            trace!("URL validation passed for: {}", final_url);
                            url
                        },
                        Err(e) => {
                            state_ptr.add_failure();
                            debug!("URL validation failed for {}: {}", final_url, e);
                            main_pb.inc(1);
                            return HttpInner::new_with_timing(
                                HeaderMap::new(),
                                format!("URL validation failed: {}", e),
                                0,
                                final_url,
                                false,
                                None,
                            );
                        }
                    };

                    trace!("Sending HTTP GET request to: {}", final_url);
                    let start_time = std::time::Instant::now();
                    let response = client
                        .get(validated_url)
                        .timeout(Duration::from_secs(timeout))
                        .send()
                        .await;
                    let response_time_ms = start_time.elapsed().as_millis() as u64;

                    let res = match response {
                        Ok(resp) => {
                            let url = resp.url().to_string();
                            let status = resp.status().as_u16();
                            let headers = resp.headers().clone();

                            debug!("HTTP response received: {} status={} content_length={:?}", 
                                   url, status, headers.get("content-length"));
                            trace!("Response headers: {:?}", headers);

                            let mut screenshot_path_opt: Option<String> = None;
                            if take_screenshot && (200..400).contains(&status) {
                                debug!("Capturing screenshot for successful response: {}", url);
                                match screenshot::capture_screenshot(
                                    &url,
                                    &format!("{}/screenshots", output_dir),
                                )
                                .await
                                {
                                    Ok(Some(p)) => {
                                        trace!("Screenshot captured successfully for: {}", url);
                                        screenshot_path_opt = Some(p);
                                    }
                                    Ok(None) => {
                                        debug!("Screenshot capture returned no path for {}", url);
                                    }
                                    Err(e) => {
                                        debug!("Screenshot capture failed for {}: {}", url, e);
                                    }
                                }
                            }

                            match resp.text().await {
                                Ok(body_text) => {
                                    let body_size = body_text.len();
                                    debug!("Response body read successfully: {} bytes", body_size);
                                    trace!("First 100 chars of body: {}", 
                                           body_text.chars().take(100).collect::<String>());
                                    state_ptr.add_success();
                                    let mut inner = HttpInner::new_with_timing(
                                        headers,
                                        body_text,
                                        status,
                                        url,
                                        true,
                                        Some(response_time_ms),
                                    );
                                    if screenshot_path_opt.is_some() {
                                        inner.set_screenshot_path(screenshot_path_opt);
                                    }
                                    inner
                                }
                                Err(e) => {
                                    state_ptr.add_failure();
                                    debug!("Failed to read response body for {}: {}", url, e);
                                    HttpInner::new_with_timing(
                                        headers,
                                        format!("Failed to read body: {}", e),
                                        status,
                                        url,
                                        false,
                                        Some(response_time_ms),
                                    )
                                }
                            }
                        }
                        Err(e) => {
                            state_ptr.add_failure();
                            let status_code = e.status().map_or(0, |s| s.as_u16());
                            let url = e.url().map_or_else(|| final_url.clone(), |u| u.to_string());
                            debug!("HTTP request failed for {}: {} (status={})", final_url, e, status_code);

                            if e.is_timeout() {
                                debug!("Request timeout occurred for: {}", final_url);
                            } else if e.is_connect() {
                                debug!("Connection error for: {}", final_url);
                            } else if e.is_redirect() {
                                debug!("Redirect error for: {}", final_url);
                            }

                            HttpInner::new_with_timing(
                                HeaderMap::new(),
                                format!("Error: {}", e),
                                status_code,
                                url,
                                false,
                                Some(response_time_ms),
                            )
                        }
                    };

                    if res.success() {
                        let hash_input = format!("{}{}", res.url(), res.body());
                        let mut hasher = Sha256::new();
                        hasher.update(&hash_input);
                        let hash = format!("{:x}", hasher.finalize());

                        debug!("Generated content hash for {}: {}", res.url(), hash);

                        let header_filename = format!("{}/headers/{}.header", output_dir, hash);
                        let html_filename = format!("{}/html/{}.html", output_dir, hash);
                        let robots_filename = format!("{}/robots/{}.robots", output_dir, hash);

                        trace!("File paths - header: {}, html: {}, robots: {}", 
                               header_filename, html_filename, robots_filename);

                        for dir in &[
                            format!("{}/headers", output_dir),
                            format!("{}/html", output_dir),
                            format!("{}/robots", output_dir),
                        ] {
                            if let Err(e) = fs::create_dir_all(dir) {
                                error!("Failed to create directory {}: {}", dir, e);
                            }
                        }

                        if let Ok(mut file) = File::create(&header_filename) {
                            let headers_str = format!("{:?}", res.headers());
                            if let Err(e) = file.write_all(headers_str.as_bytes()) {
                                debug!("Failed to write header file {}: {}", header_filename, e);
                            } else {
                                trace!("Header file written: {}", header_filename);
                            }
                        } else {
                            debug!("Failed to create header file: {}", header_filename);
                        }

                        if let Ok(mut file) = File::create(&html_filename) {
                            if let Err(e) = file.write_all(res.body().as_bytes()) {
                                debug!("Failed to write HTML file {}: {}", html_filename, e);
                            } else {
                                trace!("HTML file written: {} ({} bytes)", html_filename, res.body().len());
                            }
                        } else {
                            debug!("Failed to create HTML file: {}", html_filename);
                        }

                        if config_ptr.download_robots() {
                            debug!("Attempting to download robots.txt for: {}", res.url());
                            if let Ok(mut robots_url) = Url::parse(res.url()) {
                                robots_url.set_path("/robots.txt");
                                trace!("Robots.txt URL: {}", robots_url);
                                match validate_url(robots_url.as_str()) {
                                    Ok(validated_robots_url) => {
                                        match client.get(validated_robots_url).send().await {
                                            Ok(robot_resp) => {
                                                if let Ok(robot_text) = robot_resp.text().await {
                                                    debug!("Downloaded robots.txt ({} bytes) for: {}", 
                                                           robot_text.len(), res.url());
                                                    if let Ok(mut file) = File::create(&robots_filename) {
                                                        if let Err(e) =
                                                            file.write_all(robot_text.as_bytes())
                                                        {
                                                            debug!(
                                                                "Failed to write robots file {}: {}",
                                                                robots_filename, e
                                                            );
                                                        } else {
                                                            trace!("Robots file written: {}", robots_filename);
                                                        }
                                                    } else {
                                                        debug!(
                                                            "Failed to create robots file: {}",
                                                            robots_filename
                                                        );
                                                    }
                                                } else {
                                                    debug!("Failed to read robots.txt response for: {}", res.url());
                                                }
                                            }
                                            Err(e) => {
                                                debug!(
                                                    "Failed to fetch robots.txt for {}: {}",
                                                    res.url(),
                                                    e
                                                );
                                            }
                                        }
                                }
                                Err(e) => {
                                    debug!(
                                        "Robots URL validation failed for {}: {}",
                                        robots_url.as_str(),
                                        e
                                    );
                                }
                            }
                        }
                    }

                        let index_line = format!(
                            "{},{},{},{},{}\n",
                            hash,
                            res.url(),
                            header_filename,
                            html_filename,
                            if config_ptr.download_robots() {
                                robots_filename
                            } else {
                                String::new()
                            }
                        );

                        let index_path = format!("{}/index.txt", output_dir);
                        let mut index_file = match OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&index_path)
                        {
                            Ok(file) => file,
                            Err(e) => {
                                error!("Failed to open index file {}: {}", index_path, e);
                                File::create(&index_path).unwrap_or_else(|_| {
                                    panic!("Critical error: Could not create index file")
                                })
                            }
                        };

                        if let Err(e) = index_file.write_all(index_line.as_bytes()) {
                            error!("Failed to write to index file: {}", e);
                        }

                        cache.lock().unwrap().insert(final_url.clone(), res.clone());
                        trace!("Cached result for URL: {}", final_url);
                    }

                    debug!("HTTP scan completed for URL: {} (success={})", final_url, res.success());
                    main_pb.inc(1);
                    res
                }
            })
            .buffer_unordered(self.config_ptr.workers() as usize)
            .collect::<Vec<_>>()
            .await;

        results.extend(tasks);

        debug!(
            "HTTP operations completed: {} results (successful={}, failed={})",
            results.len(),
            results.iter().filter(|r| r.success()).count(),
            results.iter().filter(|r| !r.success()).count()
        );

        main_pb.finish_with_message("Scan completed");
        worker_pb.finish_with_message("All requests processed");

        mp_handle.abort();
        let _ = mp_handle.await;

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4_detection() {
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 169, 254)));

        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_url_scheme_validation() {
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("https://example.com").is_ok());

        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_internal_ip_blocking() {
        assert!(validate_url("http://127.0.0.1").is_err());
        assert!(validate_url("http://localhost").is_err());
        assert!(validate_url("http://10.0.0.1").is_err());
        assert!(validate_url("http://192.168.1.1").is_err());
        assert!(validate_url("http://172.16.0.1").is_err());
        assert!(validate_url("http://169.254.169.254").is_err());
    }
}
