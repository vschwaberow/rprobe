// File: getstate.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug)]
pub struct GetState {
    total_requests: AtomicU64,
    successful_requests: AtomicUsize,
    failed_requests: AtomicUsize,
    start_time: AtomicU64,
    end_time: AtomicU64,
}

impl GetState {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicUsize::new(0),
            failed_requests: AtomicUsize::new(0),
            start_time: AtomicU64::new(0),
            end_time: AtomicU64::new(0),
        }
    }

    pub fn add_success(&self) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_failure(&self) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn set_total_requests(&self, total: u64) {
        self.total_requests.store(total, Ordering::Relaxed);
    }

    pub fn successful_requests(&self) -> usize {
        self.successful_requests.load(Ordering::Relaxed)
    }

    pub fn failed_requests(&self) -> usize {
        self.failed_requests.load(Ordering::Relaxed)
    }

    pub fn set_start_time(&self, time: u64) {
        self.start_time.store(time, Ordering::Relaxed);
    }

    pub fn start_time(&self) -> u64 {
        self.start_time.load(Ordering::Relaxed)
    }

    pub fn set_end_time(&self, time: u64) {
        self.end_time.store(time, Ordering::Relaxed);
    }

    pub fn end_time(&self) -> u64 {
        self.end_time.load(Ordering::Relaxed)
    }
}