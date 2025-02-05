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
use std::fmt::Write;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Http {
    pub state_ptr: Arc<GetState>,
    pub config_ptr: ConfigParameter,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    client: reqwest::Client,
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
        }
    }

    pub async fn work(&mut self, lines_vec: Arc<Vec<String>>) -> Vec<HttpInner> {
        let pb = ProgressBar::new(lines_vec.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
            .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let mut results = Vec::new();
        let timeout = self.config_ptr.timeout();
        let client = self.client.clone();
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let state_ptr = Arc::clone(&self.state_ptr);

        let mut futures = FuturesUnordered::new();

        for line in lines_vec.iter() {
            let url = line.clone();
            let client = client.clone();
            let rate_limiter = Arc::clone(&rate_limiter);
            let state_ptr = Arc::clone(&state_ptr);
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

                let response = client
                    .get(&url)
                    .timeout(Duration::from_secs(timeout))
                    .send()
                    .await;

                match response {
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
                }
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