// File: httpinner.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(dead_code)]
use reqwest::header::HeaderMap;

#[derive(Debug)]
pub struct HttpInner {
    body: String,
    headers: HeaderMap,
    status: u16,
    success: bool,
    url: String,
}

impl HttpInner {
    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn success(&self) -> bool {
        self.success
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn new() -> Self {
        HttpInner {
            body: "".to_string(),
            headers: HeaderMap::new(),
            status: 0,
            success: false,
            url: "".to_string(),
        }
    }

    pub fn new_with_all(
        headers: HeaderMap,
        body: String,
        status: u16,
        url: String,
        success: bool,
    ) -> Self {
        HttpInner {
            body,
            headers,
            status,
            success,
            url,
        }
    }

    pub fn set_body(&mut self, body: String) {
        self.body = body;
    }

    pub fn set_headers(&mut self, headers: HeaderMap) {
        self.headers = headers;
    }

    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    pub fn set_success(&mut self, success: bool) {
        self.success = success;
    }

    pub fn set_url(&mut self, url: String) {
        self.url = url;
    }
}