// File: pattern_matcher.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexSet};
use std::time::Instant;

#[derive(Debug)]
pub struct OptimizedPatternMatcher {
    literal_matcher: Option<AhoCorasick>,
    literal_patterns: Vec<(&'static str, &'static str)>,
    regex_patterns: Vec<(Regex, &'static str)>,
}

impl OptimizedPatternMatcher {
    pub fn new(
        literal_patterns: &[(&'static str, &'static str)],
        regex_patterns: &[(&'static str, &'static str)],
    ) -> Self {
        let literal_matcher = if literal_patterns.is_empty() {
            None
        } else {
            let patterns: Vec<&str> = literal_patterns.iter().map(|(pattern, _)| *pattern).collect();
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(patterns)
                    .expect("Failed to build Aho-Corasick automaton"),
            )
        };

        let compiled_regex_patterns = regex_patterns
            .iter()
            .map(|(pattern, name)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| panic!("Invalid regex pattern: {}", pattern)),
                    *name,
                )
            })
            .collect();

        Self {
            literal_matcher,
            literal_patterns: literal_patterns.to_vec(),
            regex_patterns: compiled_regex_patterns,
        }
    }

    pub fn find_matches(&self, content: &str) -> Vec<&'static str> {
        let mut matches = Vec::new();

        // Fast literal matching with Aho-Corasick
        if let Some(ref matcher) = self.literal_matcher {
            for mat in matcher.find_iter(content) {
                let (_, name) = self.literal_patterns[mat.pattern()];
                matches.push(name);
            }
        }

        // Regex matching for complex patterns
        for (regex, name) in &self.regex_patterns {
            if regex.is_match(content) {
                matches.push(name);
            }
        }

        matches
    }

    pub fn find_first_match(&self, content: &str) -> Option<&'static str> {
        // Check literals first (faster)
        if let Some(ref matcher) = self.literal_matcher {
            if let Some(mat) = matcher.find(content) {
                let (_, name) = self.literal_patterns[mat.pattern()];
                return Some(name);
            }
        }

        // Then check regex patterns
        for (regex, name) in &self.regex_patterns {
            if regex.is_match(content) {
                return Some(name);
            }
        }

        None
    }

    pub fn count_patterns(&self) -> (usize, usize) {
        (self.literal_patterns.len(), self.regex_patterns.len())
    }
}

#[derive(Debug)]
pub struct ContentPatternMatcher {
    pattern_set: RegexSet,
    patterns: Vec<(Regex, &'static str, &'static str, crate::content_analyzer::FindingSeverity)>,
}

impl ContentPatternMatcher {
    pub fn new(pattern_data: &[(&'static str, &'static str, &'static str, crate::content_analyzer::FindingSeverity)]) -> Self {
        let pattern_strings: Vec<&str> = pattern_data.iter().map(|(pattern, _, _, _)| *pattern).collect();
        let pattern_set = RegexSet::new(&pattern_strings)
            .expect("Failed to create RegexSet for content patterns");
        
        let patterns = pattern_data
            .iter()
            .map(|(pattern, category, description, severity)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| panic!("Invalid regex pattern: {}", pattern)),
                    *category,
                    *description,
                    severity.clone(),
                )
            })
            .collect();

        Self { pattern_set, patterns }
    }

    pub fn find_matches<'a>(&'a self, content: &str) -> impl Iterator<Item = (usize, &'a (Regex, &'static str, &'static str, crate::content_analyzer::FindingSeverity))> {
        let matches = self.pattern_set.matches(content);
        matches.into_iter().map(move |idx| (idx, &self.patterns[idx]))
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

#[derive(Debug, Default, Clone)]
pub struct PatternMatchingMetrics {
    pub total_matches: u64,
    pub literal_matches: u64,
    pub regex_matches: u64,
    pub total_time_micros: u128,
    pub average_time_micros: f64,
}

impl PatternMatchingMetrics {
    pub fn record_match(&mut self, is_literal: bool, elapsed_micros: u128) {
        self.total_matches += 1;
        if is_literal {
            self.literal_matches += 1;
        } else {
            self.regex_matches += 1;
        }
        self.total_time_micros += elapsed_micros;
        self.average_time_micros = self.total_time_micros as f64 / self.total_matches as f64;
    }

    pub fn get_performance_summary(&self) -> String {
        format!(
            "Pattern Matching Stats: {} total matches ({} literal, {} regex), avg time: {:.2}μs",
            self.total_matches, self.literal_matches, self.regex_matches, self.average_time_micros
        )
    }
}

pub struct TimedPatternMatcher {
    matcher: OptimizedPatternMatcher,
    metrics: std::sync::Mutex<PatternMatchingMetrics>,
}

impl TimedPatternMatcher {
    pub fn new(
        literal_patterns: &[(&'static str, &'static str)],
        regex_patterns: &[(&'static str, &'static str)],
    ) -> Self {
        Self {
            matcher: OptimizedPatternMatcher::new(literal_patterns, regex_patterns),
            metrics: std::sync::Mutex::new(PatternMatchingMetrics::default()),
        }
    }

    pub fn find_matches_with_timing(&self, content: &str) -> Vec<&'static str> {
        let start = Instant::now();
        let matches = self.matcher.find_matches(content);
        let elapsed = start.elapsed().as_micros();

        if let Ok(mut metrics) = self.metrics.lock() {
            for _match in &matches {
                metrics.record_match(true, elapsed / matches.len() as u128);
            }
        }

        matches
    }

    pub fn get_metrics(&self) -> PatternMatchingMetrics {
        if let Ok(metrics) = self.metrics.lock() {
            metrics.clone()
        } else {
            PatternMatchingMetrics::default()
        }
    }
}

// Convenience macros for creating pattern matchers
#[macro_export]
macro_rules! optimized_patterns {
    (
        literals: [$($lit_pattern:expr => $lit_name:expr),* $(,)?]
        $(, regexes: [$($regex_pattern:expr => $regex_name:expr),* $(,)?])?
    ) => {
        $crate::plugins::pattern_matcher::OptimizedPatternMatcher::new(
            &[$( ($lit_pattern, $lit_name) ),*],
            &[$( $( ($regex_pattern, $regex_name) ),* )?]
        )
    };
}

#[macro_export]
macro_rules! lazy_optimized_patterns {
    (
        $name:ident,
        literals: [$($lit_pattern:expr => $lit_name:expr),* $(,)?]
        $(, regexes: [$($regex_pattern:expr => $regex_name:expr),* $(,)?])?
    ) => {
        static $name: once_cell::sync::Lazy<$crate::plugins::pattern_matcher::OptimizedPatternMatcher> = 
            once_cell::sync::Lazy::new(|| {
                optimized_patterns!(
                    literals: [$( $lit_pattern => $lit_name ),*]
                    $(, regexes: [$( $regex_pattern => $regex_name ),*])?
                )
            });
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_pattern_matcher_literals() {
        let matcher = OptimizedPatternMatcher::new(
            &[("Apache", "Apache Server"), ("nginx", "Nginx Server")],
            &[],
        );

        let matches = matcher.find_matches("Running Apache/2.4.41");
        assert_eq!(matches, vec!["Apache Server"]);
    }

    #[test]
    fn test_optimized_pattern_matcher_regex() {
        let matcher = OptimizedPatternMatcher::new(
            &[],
            &[(r"Apache/\d+\.\d+", "Apache Version")],
        );

        let matches = matcher.find_matches("Server: Apache/2.4.41");
        assert_eq!(matches, vec!["Apache Version"]);
    }

    #[test]
    fn test_mixed_pattern_matching() {
        let matcher = OptimizedPatternMatcher::new(
            &[("nginx", "Nginx Literal")],
            &[(r"nginx/\d+", "Nginx Version")],
        );

        let content = "Server: nginx/1.18.0";
        let matches = matcher.find_matches(content);
        assert!(matches.contains(&"Nginx Literal"));
        assert!(matches.contains(&"Nginx Version"));
    }

    #[test]
    fn test_pattern_count() {
        let matcher = OptimizedPatternMatcher::new(
            &[("test1", "Test1"), ("test2", "Test2")],
            &[("regex1", "Regex1")],
        );

        let (literal_count, regex_count) = matcher.count_patterns();
        assert_eq!(literal_count, 2);
        assert_eq!(regex_count, 1);
    }

    #[test]
    fn test_macro_usage() {
        lazy_optimized_patterns!(
            TEST_PATTERNS,
            literals: [
                "Apache" => "Apache Server",
                "nginx" => "Nginx Server"
            ],
            regexes: [
                r"Apache/\d+" => "Apache Version"
            ]
        );

        let matches = TEST_PATTERNS.find_matches("Apache/2.4");
        assert!(matches.contains(&"Apache Server"));
        assert!(matches.contains(&"Apache Version"));
    }
}