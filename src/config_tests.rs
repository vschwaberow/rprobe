// File: config_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#[cfg(test)]
mod tests {
    use crate::config::ConfigParameter;
    use rstest::*;

    #[test]
    fn test_config_parameter_default() {
        let config = ConfigParameter::default();

        assert_eq!(config.print_failed(), false);
        assert_eq!(config.detect_all(), false);
        assert_eq!(config.http(), true);
        assert_eq!(config.https(), true);
        assert_eq!(config.timeout(), 10);
        assert_eq!(config.suppress_stats(), false);
        assert_eq!(config.download_robots(), false);
        assert_eq!(config.screenshot(), false);
        assert_eq!(config.workers(), 10);
        assert_eq!(config.output_dir(), "scan");
    }

    #[test]
    fn test_config_parameter_new() {
        let config = ConfigParameter::new();

        assert_eq!(config.print_failed(), false);
        assert_eq!(config.detect_all(), false);
        assert_eq!(config.http(), true);
        assert_eq!(config.https(), true);
        assert_eq!(config.timeout(), 10);
        assert_eq!(config.suppress_stats(), false);
        assert_eq!(config.download_robots(), false);
        assert_eq!(config.screenshot(), false);
        assert_eq!(config.workers(), 10);
        assert_eq!(config.output_dir(), "scan");
    }

    #[test]
    fn test_set_print_failed() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.print_failed(), false);

        config.set_print_failed(true);
        assert_eq!(config.print_failed(), true);

        config.set_print_failed(false);
        assert_eq!(config.print_failed(), false);
    }

    #[test]
    fn test_set_detect_all() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.detect_all(), false);

        config.set_detect_all(true);
        assert_eq!(config.detect_all(), true);

        config.set_detect_all(false);
        assert_eq!(config.detect_all(), false);
    }

    #[test]
    fn test_set_http() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.http(), true);

        config.set_http(false);
        assert_eq!(config.http(), false);

        config.set_http(true);
        assert_eq!(config.http(), true);
    }

    #[test]
    fn test_set_https() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.https(), true);

        config.set_https(false);
        assert_eq!(config.https(), false);

        config.set_https(true);
        assert_eq!(config.https(), true);
    }

    #[rstest]
    #[case(0)]
    #[case(5)]
    #[case(30)]
    #[case(60)]
    #[case(120)]
    fn test_set_timeout(#[case] timeout_value: u64) {
        let mut config = ConfigParameter::new();

        config.set_timeout(timeout_value);
        assert_eq!(config.timeout(), timeout_value);
    }

    #[test]
    fn test_set_suppress_stats() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.suppress_stats(), false);

        config.set_suppress_stats(true);
        assert_eq!(config.suppress_stats(), true);

        config.set_suppress_stats(false);
        assert_eq!(config.suppress_stats(), false);
    }

    #[test]
    fn test_set_download_robots() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.download_robots(), false);

        config.set_download_robots(true);
        assert_eq!(config.download_robots(), true);

        config.set_download_robots(false);
        assert_eq!(config.download_robots(), false);
    }

    #[test]
    fn test_set_screenshot() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.screenshot(), false);

        config.set_screenshot(true);
        assert_eq!(config.screenshot(), true);

        config.set_screenshot(false);
        assert_eq!(config.screenshot(), false);
    }

    #[rstest]
    #[case(1)]
    #[case(5)]
    #[case(10)]
    #[case(20)]
    #[case(100)]
    fn test_set_workers(#[case] workers_value: u32) {
        let mut config = ConfigParameter::new();

        config.set_workers(workers_value);
        assert_eq!(config.workers(), workers_value);
    }

    #[rstest]
    #[case("output")]
    #[case("results")]
    #[case("/tmp/scan")]
    #[case("./scan_results")]
    #[case("my-scan-123")]
    fn test_set_output_dir(#[case] dir_name: &str) {
        let mut config = ConfigParameter::new();

        config.set_output_dir(dir_name.to_string());
        assert_eq!(config.output_dir(), dir_name);
    }

    #[test]
    fn test_config_clone() {
        let mut config = ConfigParameter::new();

        config.set_print_failed(true);
        config.set_detect_all(true);
        config.set_http(false);
        config.set_https(false);
        config.set_timeout(30);
        config.set_suppress_stats(true);
        config.set_download_robots(true);
        config.set_screenshot(true);
        config.set_workers(20);
        config.set_output_dir("custom_output".to_string());

        let cloned_config = config.clone();

        assert_eq!(cloned_config.print_failed(), true);
        assert_eq!(cloned_config.detect_all(), true);
        assert_eq!(cloned_config.http(), false);
        assert_eq!(cloned_config.https(), false);
        assert_eq!(cloned_config.timeout(), 30);
        assert_eq!(cloned_config.suppress_stats(), true);
        assert_eq!(cloned_config.download_robots(), true);
        assert_eq!(cloned_config.screenshot(), true);
        assert_eq!(cloned_config.workers(), 20);
        assert_eq!(cloned_config.output_dir(), "custom_output");
    }

    #[test]
    fn test_config_debug_format() {
        let config = ConfigParameter::new();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("ConfigParameter"));
        assert!(debug_str.contains("print_failed"));
        assert!(debug_str.contains("detect_all"));
        assert!(debug_str.contains("http"));
        assert!(debug_str.contains("https"));
        assert!(debug_str.contains("timeout"));
        assert!(debug_str.contains("suppress_stats"));
        assert!(debug_str.contains("download_robots"));
        assert!(debug_str.contains("screenshot"));
        assert!(debug_str.contains("workers"));
        assert!(debug_str.contains("output_dir"));
    }

    #[test]
    fn test_multiple_modifications() {
        let mut config = ConfigParameter::new();

        config.set_print_failed(true);
        config.set_detect_all(true);
        config.set_timeout(20);

        assert_eq!(config.print_failed(), true);
        assert_eq!(config.detect_all(), true);
        assert_eq!(config.timeout(), 20);

        assert_eq!(config.http(), true);
        assert_eq!(config.https(), true);
        assert_eq!(config.suppress_stats(), false);
        assert_eq!(config.download_robots(), false);
        assert_eq!(config.screenshot(), false);
        assert_eq!(config.workers(), 10);
        assert_eq!(config.output_dir(), "scan");
    }

    #[test]
    fn test_config_independence() {
        let mut config1 = ConfigParameter::new();
        let mut config2 = ConfigParameter::new();

        config1.set_print_failed(true);
        config1.set_workers(50);
        config1.set_output_dir("config1_output".to_string());

        assert_eq!(config2.print_failed(), false);
        assert_eq!(config2.workers(), 10);
        assert_eq!(config2.output_dir(), "scan");

        config2.set_detect_all(true);
        config2.set_timeout(60);

        assert_eq!(config1.detect_all(), false);
        assert_eq!(config1.timeout(), 10);
    }

    #[test]
    fn test_edge_case_values() {
        let mut config = ConfigParameter::new();

        config.set_timeout(0);
        assert_eq!(config.timeout(), 0);

        config.set_timeout(u64::MAX);
        assert_eq!(config.timeout(), u64::MAX);

        config.set_workers(0);
        assert_eq!(config.workers(), 0);

        config.set_workers(u32::MAX);
        assert_eq!(config.workers(), u32::MAX);

        config.set_output_dir(String::new());
        assert_eq!(config.output_dir(), "");

        config.set_output_dir(" ".repeat(1000));
        assert_eq!(config.output_dir().len(), 1000);
    }

    #[test]
    fn test_protocol_combinations() {
        let mut config = ConfigParameter::new();

        assert_eq!(config.http(), true);
        assert_eq!(config.https(), true);

        config.set_http(true);
        config.set_https(false);
        assert_eq!(config.http(), true);
        assert_eq!(config.https(), false);

        config.set_http(false);
        config.set_https(true);
        assert_eq!(config.http(), false);
        assert_eq!(config.https(), true);

        config.set_http(false);
        config.set_https(false);
        assert_eq!(config.http(), false);
        assert_eq!(config.https(), false);
    }
}
