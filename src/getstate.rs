// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>


#[derive(Debug, Clone, Copy)]
pub struct GetState {
    total_requests: u64,
    successful_requests: usize,
    failed_requests: usize,
    start_time: u64,
    end_time: u64,
}

impl GetState {
    pub fn new() -> GetState {
        GetState {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            start_time: 0,
            end_time: 0,
        }
    }

    pub fn add_success(&mut self) {
        self.successful_requests += 1;
    }

    pub fn add_failure(&mut self) {
        self.failed_requests += 1;
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn set_total_requests(&mut self, total_requests: u64) {
        self.total_requests = total_requests;
    }

    pub fn successful_requests(&self) -> usize {
        self.successful_requests
    }

    pub fn failed_requests(&self) -> usize {
        self.failed_requests
    }

    pub fn set_start_time(&mut self, start_time: u64) {
        self.start_time = start_time;
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    pub fn set_end_time(&mut self, end_time: u64) {
        self.end_time = end_time;
    }

    pub fn end_time(&self) -> u64 {
        self.end_time
    }
}
