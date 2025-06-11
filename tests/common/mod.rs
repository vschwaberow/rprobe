// File: common/mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use reqwest::Response;
use serde_json::json;
use std::collections::HashMap;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

pub async fn setup_mock_server() -> MockServer {
    MockServer::start().await
}

pub fn create_mock_response(status: u16, body: &str, headers: HashMap<&str, &str>) -> ResponseTemplate {
    let mut response = ResponseTemplate::new(status).set_body_string(body);
    for (key, value) in headers {
        response = response.append_header(key, value);
    }
    response
}

pub fn create_html_response(content: &str) -> ResponseTemplate {
    let mut headers = HashMap::new();
    headers.insert("content-type", "text/html");
    create_mock_response(200, content, headers)
}

pub fn create_json_response(data: serde_json::Value) -> ResponseTemplate {
    let mut headers = HashMap::new();
    headers.insert("content-type", "application/json");
    create_mock_response(200, &data.to_string(), headers)
}

pub fn sample_html_with_tech() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Test Site</title>
    <meta name="generator" content="WordPress 6.4">
    <script src="/wp-includes/js/jquery/jquery.min.js"></script>
</head>
<body>
    <h1>Welcome to Test Site</h1>
    <p>This is a test page with various technologies.</p>
    <div class="laravel-app">
        <!-- Laravel content -->
    </div>
    <!-- Powered by Apache/2.4.54 -->
</body>
</html>"#.to_string()
}

pub fn sample_html_with_sensitive_data() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Sensitive Data Test</title>
</head>
<body>
    <p>API Key: sk-1234567890abcdef</p>
    <p>AWS Access Key: AKIAIOSFODNN7EXAMPLE</p>
    <p>Email: admin@example.com</p>
    <p>Phone: +1-555-123-4567</p>
    <script>
        var apiKey = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";
        var privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
    </script>
    <form action="/login">
        <input type="password" name="password" value="secretpass123">
    </form>
</body>
</html>"#.to_string()
}

pub fn sample_server_headers() -> HashMap<&'static str, &'static str> {
    let mut headers = HashMap::new();
    headers.insert("server", "Apache/2.4.54 (Ubuntu)");
    headers.insert("x-powered-by", "PHP/8.1.2");
    headers.insert("x-generator", "Drupal 10");
    headers
}

pub fn create_test_http_response(url: &str, status: u16, body: String, headers: HashMap<String, String>) -> crate::httpinner::HttpResponse {
    use crate::httpinner::HttpResponse;
    
    HttpResponse {
        url: url.to_string(),
        status_code: status,
        headers,
        body,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_setup() {
        let server = setup_mock_server().await;
        assert!(!server.uri().is_empty());
    }

    #[test]
    fn test_create_html_response() {
        let response = create_html_response("<h1>Test</h1>");
        let headers = response.headers();
        assert!(headers.contains_key("content-type"));
    }
}