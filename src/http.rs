// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::config::ConfigParameter;
use crate::getstate::GetState;
use crate::httpinner::HttpInner;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::header::HeaderMap;
use std::time::Duration;
use std::{ops::Deref, rc::Rc};

#[derive(Debug, Clone, Copy)]
pub struct Http {
    pub state_ptr: GetState,
    pub config_ptr: ConfigParameter,
}

impl Http {
    pub fn new(state_ptr: GetState, config_ptr: ConfigParameter) -> Self {
        Http {
            state_ptr,
            config_ptr,
        }
    }

    pub async fn work(&mut self, lines_vec: Rc<Vec<String>>) -> Vec<HttpInner> {
        let time = self.config_ptr.timeout();
        let ptr = lines_vec.deref().clone();
        let len = lines_vec.len() as u64;

        let pb = ProgressBar::new(len);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let mut intv = tokio::time::interval(Duration::from_millis(15));

        let tasks = ptr.into_iter().map(|line| {
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let res = client
                    .get(&line)
                    .timeout(Duration::from_secs(time))
                    .send()
                    .await;

                match res {
                    Ok(myresp) => {
                        let url = myresp.url().to_string();
                        let status = myresp.status().as_u16();
                        let headers = myresp.headers().clone();
                        let body = myresp.text().await.unwrap_or_default();

                        HttpInner::new_with_all(headers, body, status, url, true)
                    }
                    Err(myresp) => {
                        let status = myresp.status().map(|s| s.as_u16()).unwrap_or(0);
                        let url = myresp.url().unwrap_or_default().as_str().to_string();
                        let empty = "".to_string();

                        HttpInner::new_with_all(HeaderMap::new(), empty, status, url, false)
                    }
                }
            })
        }).collect::<Vec<_>>();

        let mut http_vec: Vec<HttpInner> = Vec::new();

        for task in tasks {
            let rval = task.await;
            if let Ok(rvalu) = rval {
                intv.tick().await;
                pb.inc(1);

                if rvalu.success() {
                    http_vec.push(rvalu);
                    self.state_ptr.add_success();
                } else {
                    let url = rvalu.url().to_string();
                    let http_inner =
                        HttpInner::new_with_all(HeaderMap::new(), "".to_string(), 0, url, false);

                    http_vec.push(http_inner);
                    self.state_ptr.add_failure();
                }
            }
        }
        pb.finish();
        http_vec
    }
}
