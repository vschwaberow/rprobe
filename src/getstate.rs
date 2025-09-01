// File: getstate.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
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

impl Default for GetState {
    fn default() -> Self {
        Self::new()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_new_state_initialization() {
        let state = GetState::new();

        assert_eq!(state.total_requests(), 0);
        assert_eq!(state.successful_requests(), 0);
        assert_eq!(state.failed_requests(), 0);
        assert_eq!(state.start_time(), 0);
        assert_eq!(state.end_time(), 0);
    }

    #[test]
    fn test_default_state_initialization() {
        let state = GetState::default();

        assert_eq!(state.total_requests(), 0);
        assert_eq!(state.successful_requests(), 0);
        assert_eq!(state.failed_requests(), 0);
        assert_eq!(state.start_time(), 0);
        assert_eq!(state.end_time(), 0);
    }

    #[test]
    fn test_success_counter() {
        let state = GetState::new();

        assert_eq!(state.successful_requests(), 0);

        state.add_success();
        assert_eq!(state.successful_requests(), 1);

        state.add_success();
        state.add_success();
        assert_eq!(state.successful_requests(), 3);
    }

    #[test]
    fn test_failure_counter() {
        let state = GetState::new();

        assert_eq!(state.failed_requests(), 0);

        state.add_failure();
        assert_eq!(state.failed_requests(), 1);

        state.add_failure();
        state.add_failure();
        assert_eq!(state.failed_requests(), 3);
    }

    #[test]
    fn test_total_requests_setter_getter() {
        let state = GetState::new();

        assert_eq!(state.total_requests(), 0);

        state.set_total_requests(100);
        assert_eq!(state.total_requests(), 100);

        state.set_total_requests(u64::MAX);
        assert_eq!(state.total_requests(), u64::MAX);

        state.set_total_requests(0);
        assert_eq!(state.total_requests(), 0);
    }

    #[test]
    fn test_time_setters_getters() {
        let state = GetState::new();
        let current_timestamp = 1640995200u64;
        let end_timestamp = 1640998800u64;

        assert_eq!(state.start_time(), 0);
        assert_eq!(state.end_time(), 0);

        state.set_start_time(current_timestamp);
        assert_eq!(state.start_time(), current_timestamp);

        state.set_end_time(end_timestamp);
        assert_eq!(state.end_time(), end_timestamp);
    }

    #[test]
    fn test_mixed_operations() {
        let state = GetState::new();

        state.set_total_requests(50);
        state.add_success();
        state.add_success();
        state.add_failure();

        assert_eq!(state.total_requests(), 50);
        assert_eq!(state.successful_requests(), 2);
        assert_eq!(state.failed_requests(), 1);
    }

    #[test]
    fn test_concurrent_success_updates() {
        let state = Arc::new(GetState::new());
        let num_threads = 10;
        let operations_per_thread = 100;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..operations_per_thread {
                        state.add_success();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            state.successful_requests(),
            num_threads * operations_per_thread
        );
        assert_eq!(state.failed_requests(), 0);
    }

    #[test]
    fn test_concurrent_failure_updates() {
        let state = Arc::new(GetState::new());
        let num_threads = 10;
        let operations_per_thread = 100;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..operations_per_thread {
                        state.add_failure();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(state.failed_requests(), num_threads * operations_per_thread);
        assert_eq!(state.successful_requests(), 0);
    }

    #[test]
    fn test_concurrent_mixed_updates() {
        let state = Arc::new(GetState::new());
        let num_threads = 8;
        let operations_per_thread = 50;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..operations_per_thread {
                        if i % 2 == 0 {
                            state.add_success();
                        } else {
                            state.add_failure();
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let half_threads = num_threads / 2;
        assert_eq!(
            state.successful_requests(),
            half_threads * operations_per_thread
        );
        assert_eq!(
            state.failed_requests(),
            half_threads * operations_per_thread
        );
    }

    #[test]
    fn test_concurrent_total_requests_updates() {
        let state = Arc::new(GetState::new());
        let num_threads = 5;
        let barrier = Arc::new(Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    state.set_total_requests((i + 1) as u64 * 10);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let final_value = state.total_requests();
        assert!(
            final_value == 10
                || final_value == 20
                || final_value == 30
                || final_value == 40
                || final_value == 50
        );
    }

    #[test]
    fn test_state_overflow_behavior() {
        let state = GetState::new();

        state.set_total_requests(u64::MAX);
        assert_eq!(state.total_requests(), u64::MAX);

        for _ in 0..1000 {
            state.add_success();
            state.add_failure();
        }

        assert!(state.successful_requests() > 0);
        assert!(state.failed_requests() > 0);
    }
}
