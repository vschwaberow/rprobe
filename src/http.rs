// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>


use crate::config::ConfigParameter;
use crate::getstate::GetState;
use crate::httpinner::HttpInner;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use reqwest::header::HeaderMap;
use std::fmt::Write;
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
            let task = tokio::spawn(async move {
                let client = reqwest::Client::new();
                let res = client
                    .get(line)
                    .timeout(std::time::Duration::from_secs(time))
                    .send()
                    .await;

                match res {
                    Ok(_) => {
                        let myresp = res.unwrap();
                        let url = myresp.url().to_string();
                        let status = myresp.status().as_u16();
                        let headers = myresp.headers().clone();
                        let body = myresp.text().await;
                        //        let mut http_inner = HttpInner::new();

                        match body {
                            Ok(_) => {
                                let body = body.unwrap().to_string();
                                return HttpInner::new_with_all(headers, body, status, url, true);
                            }
                            Err(_) => {
                                let body = "".to_string();
                                let http_inner =
                                    HttpInner::new_with_all(headers, body, status, url, false);

                                return http_inner;
                            }
                        }
                    }
                    Err(_) => {
                        let myresp = res.unwrap_err();
                        //                  let mut status_code = 0;
                        let status = myresp.status();
                        let mut status_code = 0;
                        match status {
                            Some(_) => {
                                let _a = status_code;
                                let status = status.unwrap().as_u16();
                                status_code = status;
                            }
                            None => {
                                status_code = 0 as u16;
                            }
                        }
                        let det_status = status_code;
                        let url = myresp.url().unwrap().as_str().to_string();
                        let empty = "".to_string();

                        let http_inner = HttpInner::new_with_all(
                            HeaderMap::new(),
                            empty,
                            det_status,
                            url,
                            false,
                        );
                        return http_inner;
                    }
                }
            });
            tasks.push(task);
        }

        let mut http_vec: Vec<HttpInner> = Vec::new();

        for task in tasks {
            let rval = task.await;
            match rval {
                Ok(_) => {
                    let rvalu = rval.unwrap();
                    match rvalu.success() {
                        true => {
                            intv.tick().await;

                            pb.inc(1);
                            let http_inner = rvalu;
                            http_vec.push(http_inner);
                            self.state_ptr.add_success();
                        }
                        false => {
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
                Err(_) => {}
            }
        }
        pb.finish();
        http_vec
    }
}
