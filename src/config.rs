// File: config.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>


#[derive(Debug, Clone)]
pub struct ConfigParameter {
    print_failed: bool,
    detect_all: bool,
    http: bool,
    https: bool,
    timeout: u64,
    suppress_stats: bool,
    download_robots: bool,
    screenshot: bool,
    workers: u32,
    output_dir: String,
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
            download_robots: false,
            screenshot: false,
            workers: 10,
            output_dir: "scan".to_string(),
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

    pub fn set_screenshot(&mut self, screenshot: bool) {
        self.screenshot = screenshot;
    }

    pub fn screenshot(&self) -> bool {
        self.screenshot
    }

    pub fn set_workers(&mut self, workers: u32) {
        self.workers = workers;
    }

    pub fn workers(&self) -> u32 {
        self.workers
    }

    pub fn set_output_dir(&mut self, output_dir: String) {
        self.output_dir = output_dir;
    }

    pub fn output_dir(&self) -> &str {
        &self.output_dir
    }
}
