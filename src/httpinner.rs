// File: httpinner.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(dead_code)]
use reqwest::header::HeaderMap;

#[derive(Debug, Clone)]
pub struct HttpInner {
    body: String,
    headers: HeaderMap,
    status: u16,
    success: bool,
    url: String,
    response_time_ms: Option<u64>,
    screenshot_path: Option<String>,
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

    pub fn response_time_ms(&self) -> Option<u64> {
        self.response_time_ms
    }

    pub fn new() -> Self {
        HttpInner {
            body: "".to_string(),
            headers: HeaderMap::new(),
            status: 0,
            success: false,
            url: "".to_string(),
            response_time_ms: None,
            screenshot_path: None,
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
            response_time_ms: None,
            screenshot_path: None,
        }
    }

    pub fn new_with_timing(
        headers: HeaderMap,
        body: String,
        status: u16,
        url: String,
        success: bool,
        response_time_ms: Option<u64>,
    ) -> Self {
        HttpInner {
            body,
            headers,
            status,
            success,
            url,
            response_time_ms,
            screenshot_path: None,
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

    pub fn set_response_time_ms(&mut self, response_time_ms: Option<u64>) {
        self.response_time_ms = response_time_ms;
    }

    pub fn screenshot_path(&self) -> Option<&String> {
        self.screenshot_path.as_ref()
    }

    pub fn set_screenshot_path(&mut self, path: Option<String>) {
        self.screenshot_path = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

    #[test]
    fn test_new_http_inner() {
        let http_inner = HttpInner::new();

        assert_eq!(http_inner.body(), "");
        assert_eq!(http_inner.headers().len(), 0);
        assert_eq!(http_inner.status(), 0);
        assert_eq!(http_inner.success(), false);
        assert_eq!(http_inner.url(), "");
        assert_eq!(http_inner.response_time_ms(), None);
    }

    #[test]
    fn test_new_with_all_constructor() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let body = r#"{"key": "value"}"#.to_string();
        let status = 200;
        let url = "https://example.com".to_string();
        let success = true;

        let http_inner =
            HttpInner::new_with_all(headers.clone(), body.clone(), status, url.clone(), success);

        assert_eq!(http_inner.body(), &body);
        assert_eq!(http_inner.headers().len(), 1);
        assert_eq!(
            http_inner.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(http_inner.status(), status);
        assert_eq!(http_inner.success(), success);
        assert_eq!(http_inner.url(), &url);
        assert_eq!(http_inner.response_time_ms(), None);
    }

    #[test]
    fn test_new_with_timing_constructor() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx/1.18.0"),
        );

        let body = "<html><body>Hello World</body></html>".to_string();
        let status = 200;
        let url = "https://test.example.com/page".to_string();
        let success = true;
        let response_time = Some(150u64);

        let http_inner = HttpInner::new_with_timing(
            headers.clone(),
            body.clone(),
            status,
            url.clone(),
            success,
            response_time,
        );

        assert_eq!(http_inner.body(), &body);
        assert_eq!(http_inner.headers().len(), 1);
        assert_eq!(http_inner.headers().get("server").unwrap(), "nginx/1.18.0");
        assert_eq!(http_inner.status(), status);
        assert_eq!(http_inner.success(), success);
        assert_eq!(http_inner.url(), &url);
        assert_eq!(http_inner.response_time_ms(), response_time);
    }

    #[test]
    fn test_setters_and_getters() {
        let mut http_inner = HttpInner::new();

        let new_body = "Updated body content".to_string();
        http_inner.set_body(new_body.clone());
        assert_eq!(http_inner.body(), &new_body);

        let mut new_headers = HeaderMap::new();
        new_headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("test-agent"),
        );
        new_headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html"),
        );
        http_inner.set_headers(new_headers.clone());
        assert_eq!(http_inner.headers().len(), 2);
        assert_eq!(
            http_inner.headers().get("user-agent").unwrap(),
            "test-agent"
        );
        assert_eq!(http_inner.headers().get("accept").unwrap(), "text/html");

        let new_status = 404;
        http_inner.set_status(new_status);
        assert_eq!(http_inner.status(), new_status);

        let new_success = true;
        http_inner.set_success(new_success);
        assert_eq!(http_inner.success(), new_success);

        let new_url = "https://updated.example.com/new-path".to_string();
        http_inner.set_url(new_url.clone());
        assert_eq!(http_inner.url(), &new_url);

        let new_response_time = Some(250u64);
        http_inner.set_response_time_ms(new_response_time);
        assert_eq!(http_inner.response_time_ms(), new_response_time);
    }

    #[test]
    fn test_clone_functionality() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/html"),
        );
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("Apache"),
        );

        let body = "<html><head><title>Test</title></head></html>".to_string();
        let status = 200;
        let url = "https://clone.example.com".to_string();
        let success = true;
        let response_time = Some(75u64);

        let original = HttpInner::new_with_timing(
            headers,
            body.clone(),
            status,
            url.clone(),
            success,
            response_time,
        );
        let cloned = original.clone();

        assert_eq!(original.body(), cloned.body());
        assert_eq!(original.headers().len(), cloned.headers().len());
        assert_eq!(
            original.headers().get("content-type"),
            cloned.headers().get("content-type")
        );
        assert_eq!(
            original.headers().get("server"),
            cloned.headers().get("server")
        );
        assert_eq!(original.status(), cloned.status());
        assert_eq!(original.success(), cloned.success());
        assert_eq!(original.url(), cloned.url());
        assert_eq!(original.response_time_ms(), cloned.response_time_ms());
    }

    #[test]
    fn test_debug_formatting() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("PHP/7.4"),
        );

        let body = "Debug test body".to_string();
        let status = 500;
        let url = "https://debug.example.com".to_string();
        let success = false;

        let http_inner = HttpInner::new_with_all(headers, body, status, url, success);
        let debug_output = format!("{:?}", http_inner);

        assert!(debug_output.contains("HttpInner"));
        assert!(debug_output.contains("Debug test body"));
        assert!(debug_output.contains("500"));
        assert!(debug_output.contains("debug.example.com"));
        assert!(debug_output.contains("false"));
    }

    #[test]
    fn test_empty_headers() {
        let empty_headers = HeaderMap::new();
        let http_inner = HttpInner::new_with_all(
            empty_headers,
            "".to_string(),
            200,
            "https://example.com".to_string(),
            true,
        );

        assert_eq!(http_inner.headers().len(), 0);
        assert!(http_inner.headers().is_empty());
    }

    #[test]
    fn test_large_body_content() {
        let large_body = "x".repeat(1_000_000);
        let mut http_inner = HttpInner::new();
        http_inner.set_body(large_body.clone());

        assert_eq!(http_inner.body().len(), 1_000_000);
        assert_eq!(http_inner.body(), &large_body);
    }

    #[test]
    fn test_special_characters_in_url() {
        let special_url =
            "https://example.com/path with spaces & symbols?query=value&param=测试".to_string();
        let mut http_inner = HttpInner::new();
        http_inner.set_url(special_url.clone());

        assert_eq!(http_inner.url(), &special_url);
    }

    #[test]
    fn test_various_status_codes() {
        let status_codes = [100, 200, 301, 404, 500, 503];

        for status in status_codes {
            let mut http_inner = HttpInner::new();
            http_inner.set_status(status);
            assert_eq!(http_inner.status(), status);
        }
    }

    #[test]
    fn test_success_flag_combinations() {
        let mut http_inner = HttpInner::new();

        http_inner.set_success(true);
        assert!(http_inner.success());

        http_inner.set_success(false);
        assert!(!http_inner.success());

        http_inner.set_success(true);
        http_inner.set_status(404);
        assert!(http_inner.success());
        assert_eq!(http_inner.status(), 404);
    }

    #[test]
    fn test_response_time_edge_cases() {
        let mut http_inner = HttpInner::new();

        http_inner.set_response_time_ms(Some(0));
        assert_eq!(http_inner.response_time_ms(), Some(0));

        http_inner.set_response_time_ms(Some(u64::MAX));
        assert_eq!(http_inner.response_time_ms(), Some(u64::MAX));

        http_inner.set_response_time_ms(None);
        assert_eq!(http_inner.response_time_ms(), None);
    }

    #[test]
    fn test_multiple_header_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("session=abc123; path=/"),
        );
        headers.append(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("token=xyz789; secure"),
        );
        headers.insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-cache"),
        );

        let http_inner = HttpInner::new_with_all(
            headers,
            "".to_string(),
            200,
            "https://example.com".to_string(),
            true,
        );

        assert_eq!(http_inner.headers().len(), 3);
        let cookie_values: Vec<_> = http_inner.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookie_values.len(), 2);

        assert_eq!(
            http_inner.headers().get("cache-control").unwrap(),
            "no-cache"
        );
    }

    #[test]
    fn test_header_case_sensitivity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-header"),
            HeaderValue::from_static("custom-value"),
        );

        let http_inner = HttpInner::new_with_all(
            headers,
            "".to_string(),
            200,
            "https://example.com".to_string(),
            true,
        );

        assert_eq!(
            http_inner.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            http_inner.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            http_inner.headers().get("CONTENT-TYPE").unwrap(),
            "application/json"
        );
        assert_eq!(
            http_inner.headers().get("x-custom-header").unwrap(),
            "custom-value"
        );
        assert_eq!(
            http_inner.headers().get("X-Custom-Header").unwrap(),
            "custom-value"
        );
    }

    #[test]
    fn test_body_with_json_content() {
        let json_body =
            r#"{"users": [{"id": 1, "name": "John"}, {"id": 2, "name": "Jane"}], "total": 2}"#
                .to_string();
        let mut http_inner = HttpInner::new();
        http_inner.set_body(json_body.clone());

        assert_eq!(http_inner.body(), &json_body);
        assert!(http_inner.body().contains("users"));
        assert!(http_inner.body().contains("total"));
    }

    #[test]
    fn test_body_with_html_content() {
        let html_body = r#"<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello</h1><p>This is a test page.</p></body></html>"#.to_string();
        let mut http_inner = HttpInner::new();
        http_inner.set_body(html_body.clone());

        assert_eq!(http_inner.body(), &html_body);
        assert!(http_inner.body().contains("<!DOCTYPE html>"));
        assert!(http_inner.body().contains("<title>Test</title>"));
        assert!(http_inner.body().contains("<h1>Hello</h1>"));
    }

    #[test]
    fn test_unicode_in_body() {
        let unicode_body = "Hello 世界! Привет мир! مرحبا بالعالم!".to_string();
        let mut http_inner = HttpInner::new();
        http_inner.set_body(unicode_body.clone());

        assert_eq!(http_inner.body(), &unicode_body);
    }

    #[test]
    fn test_realistic_http_response_simulation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx/1.18.0 (Ubuntu)"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/html; charset=UTF-8"),
        );
        headers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("1234"),
        );
        headers.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("PHP/8.0.0"),
        );
        headers.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("PHPSESSID=abc123def456; path=/; HttpOnly"),
        );

        let body = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.0">
    <title>Test Website</title>
</head>
<body>
    <div class="wp-content">
        <h1>Welcome to Test Site</h1>
        <p>This is a test page for plugin detection.</p>
    </div>
    <script src="/wp-includes/js/jquery.min.js"></script>
</body>
</html>"#
            .to_string();

        let status = 200;
        let url = "https://test-website.com/index.php".to_string();
        let success = true;
        let response_time = Some(125u64);

        let http_inner = HttpInner::new_with_timing(
            headers,
            body.clone(),
            status,
            url.clone(),
            success,
            response_time,
        );

        assert_eq!(http_inner.body(), &body);
        assert_eq!(http_inner.status(), 200);
        assert_eq!(http_inner.success(), true);
        assert_eq!(http_inner.url(), "https://test-website.com/index.php");
        assert_eq!(http_inner.response_time_ms(), Some(125));

        assert_eq!(
            http_inner.headers().get("server").unwrap(),
            "nginx/1.18.0 (Ubuntu)"
        );
        assert_eq!(
            http_inner.headers().get("content-type").unwrap(),
            "text/html; charset=UTF-8"
        );
        assert_eq!(
            http_inner.headers().get("x-powered-by").unwrap(),
            "PHP/8.0.0"
        );
        assert!(http_inner
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("PHPSESSID"));

        assert!(http_inner.body().contains("WordPress"));
        assert!(http_inner.body().contains("wp-content"));
        assert!(http_inner.body().contains("wp-includes"));
    }
}
