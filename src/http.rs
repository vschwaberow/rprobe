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
use log::{debug, error, info, warn};
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
            .timeout(Duration::from_secs(config_ptr.timeout()))
            .user_agent(format!("rprobe/{}", env!("CARGO_PKG_VERSION")))
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
        let output_dir = self.config_ptr.output_dir();
        if !Path::new(output_dir).exists() {
            if let Err(e) = fs::create_dir_all(output_dir) {
                error!("Failed to create output directory {}: {}", output_dir, e);
            }
        }

        let mp = MultiProgress::new();
        let main_pb = mp.add(ProgressBar::new(lines_vec.len() as u64));
        main_pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
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
                    
                    rate_limiter.until_ready().await;
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
                        debug!("Loaded URL {} from cache", url);
                        main_pb.inc(1);
                        return cached;
                    }

                    let clean_url = url.trim();
                    let final_url = if !clean_url.starts_with("http://") && !clean_url.starts_with("https://") {
                        if config_ptr.https() {
                            format!("https://{}", clean_url)
                        } else if config_ptr.http() {
                            format!("http://{}", clean_url)
                        } else {
                            format!("https://{}", clean_url)
                        }
                    } else {
                        clean_url.to_string()
                    };

                    info!("Starting scan for URL: {}", final_url);
                    let response = client
                        .get(&final_url)
                        .timeout(Duration::from_secs(timeout))
                        .send()
                        .await;

                    let res = match response {
                        Ok(resp) => {
                            let url = resp.url().to_string();
                            let status = resp.status().as_u16();
                            let headers = resp.headers().clone();
                            
                            if take_screenshot && status >= 200 && status < 400 {
                                if let Err(e) = screenshot::capture_screenshot(&url, &format!("{}/screenshots", output_dir)).await {
                                    warn!("Failed to capture screenshot for {}: {}", url, e);
                                }
                            }
                            
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
                            error!("HTTP request failed for {}: {}", final_url, e);
                            let status_code = e.status().map_or(0, |s| s.as_u16());
                            let url = e
                                .url()
                                .map_or_else(|| final_url.clone(), |u| u.to_string());
                            HttpInner::new_with_all(
                                HeaderMap::new(),
                                format!("Error: {}", e),
                                status_code,
                                url,
                                false,
                            )
                        }
                    };

                    if res.success() {
                        let hash_input = format!("{}{}", res.url(), res.body());
                        let mut hasher = Sha256::new();
                        hasher.update(&hash_input);
                        let hash = format!("{:x}", hasher.finalize());

                        let header_filename = format!("{}/headers/{}.header", output_dir, hash);
                        let html_filename = format!("{}/html/{}.html", output_dir, hash);
                        let robots_filename = format!("{}/robots/{}.robots", output_dir, hash);

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
                                error!("Failed to write to header file {}: {}", header_filename, e);
                            }
                        } else {
                            error!("Failed to create header file {}", header_filename);
                        }

                        if let Ok(mut file) = File::create(&html_filename) {
                            if let Err(e) = file.write_all(res.body().as_bytes()) {
                                error!("Failed to write to HTML file {}: {}", html_filename, e);
                            }
                        } else {
                            error!("Failed to create HTML file {}", html_filename);
                        }

                        if config_ptr.download_robots() {
                            if let Ok(mut robots_url) = Url::parse(res.url()) {
                                robots_url.set_path("/robots.txt");
                                match client.get(robots_url.as_str()).send().await {
                                    Ok(robot_resp) => {
                                        if let Ok(robot_text) = robot_resp.text().await {
                                            if let Ok(mut file) = File::create(&robots_filename) {
                                                if let Err(e) = file.write_all(robot_text.as_bytes()) {
                                                    error!("Failed to write robots file {}: {}", robots_filename, e);
                                                }
                                            } else {
                                                error!("Failed to create robots file {}", robots_filename);
                                            }
                                        } else {
                                            error!("Failed to read robots.txt for {}", res.url());
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to fetch robots.txt for {}: {}", res.url(), e);
                                    }
                                }
                            }
                        }

                        let index_line = format!("{},{},{},{},{}\n", 
                            hash, 
                            res.url(), 
                            header_filename, 
                            html_filename,
                            if config_ptr.download_robots() { robots_filename } else { String::new() }
                        );
                        
                        let index_path = format!("{}/index.txt", output_dir);
                        let mut index_file = match OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&index_path) {
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
                    }

                    info!("Scan for URL {} completed", final_url);
                    main_pb.inc(1);
                    res
                }
            })
            .buffer_unordered(self.config_ptr.workers() as usize)
            .collect::<Vec<_>>()
            .await;

        results.extend(tasks);
        
        main_pb.finish_with_message("Scan completed");
        worker_pb.finish_with_message("All requests processed");
        
        mp_handle.abort();
        let _ = mp_handle.await;

        results
    }
}
