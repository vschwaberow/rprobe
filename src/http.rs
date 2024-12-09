// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::config::ConfigParameter;
use crate::getstate::GetState;
use crate::httpinner::HttpInner;
use governor::{clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use reqwest::header::HeaderMap;
use std::fmt::Write;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use std::{ops::Deref, rc::Rc};

#[derive(Debug, Clone)]
pub struct Http {
    pub state_ptr: GetState,
    pub config_ptr: ConfigParameter,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl Http {
    pub fn new(state_ptr: GetState, config_ptr: ConfigParameter, rate_limit: NonZeroU32) -> Self {
        Http {
            state_ptr,
            config_ptr,
            rate_limiter: Arc::new(RateLimiter::direct(Quota::per_second(rate_limit))),
        }
    }

    pub async fn work(&mut self, lines_vec: Rc<Vec<String>>) -> Vec<HttpInner> {
        let mut tasks = Vec::new();
        let time = self.config_ptr.timeout();
        let ptr = lines_vec.deref().clone();

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

        let mut intv = tokio::time::interval(Duration::from_millis(15));

        for line in ptr {
            self.rate_limiter.until_ready().await;

            let rate_limiter = Arc::clone(&self.rate_limiter);
            let task = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                rate_limiter.until_ready().await;

                if line.trim().is_empty() {
                    return HttpInner::new_with_all(
                        HeaderMap::new(),
                        "Empty URL".to_string(),
                        0,
                        "Empty URL".to_string(),
                        false,
                    );
                }

                let client = reqwest::Client::new();
                let res = client
                    .get(line)
                    .timeout(std::time::Duration::from_secs(time))
                    .send()
                    .await;

                match res {
                    Ok(myresp) => {
                        let url = myresp.url().to_string();
                        let status = myresp.status().as_u16();
                        let headers = myresp.headers().clone();
                        let body = myresp.text().await;

                        match body {
                            Ok(body_text) => HttpInner::new_with_all(
                                headers,
                                body_text,
                                status,
                                url,
                                true,
                            ),
                            Err(e) => {
                                let error_msg = format!("Failed to read body: {}", e);
                                HttpInner::new_with_all(headers, error_msg, status, url, false)
                            }
                        }
                    }
                    Err(e) => {
                        let status_code = e.status().map_or(0, |s| s.as_u16());
                        let url = e
                            .url()
                            .map_or_else(|| "Unknown URL".to_string(), |u| u.to_string());
                        let error_msg = format!("Error: {}", e);

                        println!("Request failed for {}: {}", url, error_msg);

                        HttpInner::new_with_all(
                            HeaderMap::new(),
                            error_msg,
                            status_code,
                            url,
                            false,
                        )
                    }
                }
            });
            tasks.push(task);
        }

        let mut http_vec: Vec<HttpInner> = Vec::new();

        for task in tasks {
            let rval = task.await;
            if let Ok(rvalu) = rval {
                if rvalu.success() {
                    intv.tick().await;

                    pb.inc(1);
                    let http_inner = rvalu;
                    http_vec.push(http_inner);
                    self.state_ptr.add_success();
                } else {
                    intv.tick().await;

                    pb.inc(1);
                    let empty = "".to_string();
                    let url = rvalu.url().to_string();
                    let http_inner =
                        HttpInner::new_with_all(HeaderMap::new(), empty, 0, url, false);

                    http_vec.push(http_inner);
                    self.state_ptr.add_failure();
                }
            }
        }
        pb.finish();
        http_vec
    }
}
