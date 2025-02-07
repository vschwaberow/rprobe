// File: config.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use std::num::NonZeroU32;

#[derive(Debug, Clone, Copy)]
pub struct ConfigParameter {
    print_failed: bool,
    detect_all: bool,
    http: bool,
    https: bool,
    timeout: u64,
    suppress_stats: bool,
    rate_limit: NonZeroU32,
    download_robots: bool,
}

impl Default for ConfigParameter {
    fn default() -> Self {
        Self {
            print_failed: false,
            detect_all: false,
            http: true,
            https: true,
            timeout: 10,
            suppress_stats: false,
            rate_limit: NonZeroU32::new(100).unwrap(),
            download_robots: false,
        }
    }
}

impl ConfigParameter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_download_robots(&mut self, download_robots: bool) {
        self.download_robots = download_robots;
    }

    pub fn download_robots(&self) -> bool {
        self.download_robots
    }

    pub fn set_print_failed(&mut self, print_failed: bool) {
        self.print_failed = print_failed;
    }

    pub fn print_failed(&self) -> bool {
        self.print_failed
    }

    pub fn set_detect_all(&mut self, detect_all: bool) {
        self.detect_all = detect_all;
    }

    pub fn detect_all(&self) -> bool {
        self.detect_all
    }

    pub fn set_http(&mut self, http: bool) {
        self.http = http;
    }

    pub fn http(&self) -> bool {
        self.http
    }

    pub fn set_https(&mut self, https: bool) {
        self.https = https;
    }

    pub fn https(&self) -> bool {
        self.https
    }

    pub fn set_timeout(&mut self, timeout: u64) {
        self.timeout = timeout;
    }

    pub fn timeout(&self) -> u64 {
        self.timeout
    }

    pub fn suppress_stats(&self) -> bool {
        self.suppress_stats
    }

    pub fn set_suppress_stats(&mut self, suppress_stats: bool) {
        self.suppress_stats = suppress_stats;
    }

    #[allow(dead_code)]
    pub fn set_rate_limit(&mut self, rate: NonZeroU32) {
        self.rate_limit = rate;
    }

    #[allow(dead_code)]
    pub fn rate_limit(&self) -> NonZeroU32 {
        self.rate_limit
    }
}

#[allow(dead_code)]
fn display_rate_limit(config: &ConfigParameter) {
    println!("Current rate limit: {}", config.rate_limit());
}