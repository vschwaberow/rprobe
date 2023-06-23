// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

#[derive(Debug, Clone, Copy)]
pub struct ConfigParameter {
    print_failed: bool,
    detect_all: bool,
    http: bool,
    https: bool,
    timeout: u64,
    suppress_stats: bool,
}

impl ConfigParameter {
    pub fn new() -> Self {
        Self {
            print_failed: false,
            detect_all: false,
            http: true,
            https: true,
            timeout: 10,
            suppress_stats: false,
        }
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
}
