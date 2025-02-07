// File: http.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::config::ConfigParameter;
use crate::getstate::GetState;
use crate::httpinner::HttpInner;
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use reqwest::header::HeaderMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::HashMap;
use log::{debug, error, info};
use std::fs::{self, File, OpenOptions};
use sha2::{Sha256, Digest};
use std::io::Write;
use reqwest::Url;

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
        let client = reqwest::Client::builder()
            .build()
            .expect("Failed to build reqwest client");
        Http {
            state_ptr,
            config_ptr,
            rate_limiter: Arc::new(RateLimiter::direct(Quota::per_second(rate_limit))),
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn work(&mut self, lines_vec: Arc<Vec<String>>) -> Vec<HttpInner> {
        let pb = ProgressBar::new(lines_vec.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
            .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let mut results = Vec::new();
        let timeout = self.config_ptr.timeout();
        let client = self.client.clone();
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let state_ptr = Arc::clone(&self.state_ptr);

        fs::create_dir_all("scan").expect("Failed to create scan directory");

        let mut futures = FuturesUnordered::new();

        for line in lines_vec.iter() {
            let url = line.clone();
            let client = client.clone();
            let rate_limiter = Arc::clone(&rate_limiter);
            let state_ptr = Arc::clone(&state_ptr);
            let cache = self.cache.clone();
            let config_ptr = self.config_ptr.clone();
            futures.push(tokio::spawn(async move {
                rate_limiter.until_ready().await;
                if url.trim().is_empty() {
                    return HttpInner::new_with_all(
                        HeaderMap::new(),
                        "Empty URL".to_string(),
                        0,
                        url,
                        false,
                    );
                }

                if let Some(cached) = cache.lock().unwrap().get(&url).cloned() {
                    debug!("Loaded URL {} from cache", url);
                    return cached;
                }

                info!("Starting scan for URL: {}", url);
                let response = client
                    .get(&url)
                    .timeout(Duration::from_secs(timeout))
                    .send()
                    .await;

                let res = match response {
                    Ok(resp) => {
                        let url = resp.url().to_string();
                        let status = resp.status().as_u16();
                        let headers = resp.headers().clone();
                        match resp.text().await {
                            Ok(body_text) => {
                                state_ptr.add_success();
                                HttpInner::new_with_all(headers, body_text, status, url, true)
                            }
                            Err(e) => {
                                state_ptr.add_failure();
                                error!("Failed to read body for {}: {}", url, e);
                                HttpInner::new_with_all(
                                    headers,
                                    format!("Failed to read body: {}", e),
                                    status,
                                    url,
                                    false,
                                )
                            }
                        }
                    }
                    Err(e) => {
                        state_ptr.add_failure();
                        error!("HTTP request failed for {}: {}", url, e);
                        let status_code = e.status().map_or(0, |s| s.as_u16());
                        let url = e
                            .url()
                            .map_or_else(|| "Unknown URL".to_string(), |u| u.to_string());
                        HttpInner::new_with_all(
                            HeaderMap::new(),
                            format!("Error: {}", e),
                            status_code,
                            url,
                            false,
                        )
                    }
                };

                let mut hasher = Sha256::new();
                hasher.update(res.body());
                let hash = format!("{:x}", hasher.finalize());

                let header_filename = format!("scan/{}.header", hash);
                let html_filename = format!("scan/{}.html", hash);
                let robots_filename = format!("scan/{}.robots", hash);

                if let Ok(mut file) = File::create(&header_filename) {
                    let headers_str = format!("{:?}", res.headers());
                    let _ = file.write_all(headers_str.as_bytes());
                } else {
                    error!("Failed to create header file {}", header_filename);
                }

                if let Ok(mut file) = File::create(&html_filename) {
                    let _ = file.write_all(res.body().as_bytes());
                } else {
                    error!("Failed to create HTML file {}", html_filename);
                }

                if config_ptr.download_robots() {
                    if let Ok(mut robots_url) = Url::parse(&url) {
                        robots_url.set_path("/robots.txt");
                        match client.get(robots_url.as_str()).send().await {
                            Ok(robot_resp) => {
                                if let Ok(robot_text) = robot_resp.text().await {
                                    if let Ok(mut file) = File::create(&robots_filename) {
                                        let _ = file.write_all(robot_text.as_bytes());
                                    } else {
                                        error!("Failed to create robots file {}", robots_filename);
                                    }
                                } else {
                                    error!("Failed to read robots.txt for {}", url);
                                }
                            }
                            Err(e) => {
                                error!("Failed to fetch robots.txt for {}: {}", url, e);
                            }
                        }
                    }
                }

                let index_line = if config_ptr.download_robots() {
                    format!("{},{},{},{},{}\n", hash, url, header_filename, html_filename, robots_filename)
                } else {
                    format!("{},{},{},{}\n", hash, url, header_filename, html_filename)
                };
                let mut index_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("scan/index.txt")
                    .expect("Failed to open scan index file");
                let _ = index_file.write_all(index_line.as_bytes());

                cache.lock().unwrap().insert(url.clone(), res.clone());
                info!("Scan for URL {} completed", url);
                // state_ptr.add_request(); // This method does not exist
                res
            }));
        }

        while let Some(task) = futures.next().await {
            if let Ok(result) = task {
                results.push(result);
                pb.inc(1);
            }
        }
        pb.finish();
        results
    }
}