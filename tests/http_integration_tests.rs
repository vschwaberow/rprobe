// File: http_integration_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use rprobe::http::Http;
use rprobe::config::ConfigParameter;
use rprobe::getstate::GetState;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use tokio;
use serial_test::serial;
use std::sync::Arc;
use std::num::NonZeroU32;

#[tokio::test]
#[serial]
async fn test_basic_http_request() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string("Hello, World!")
            .append_header("content-type", "text/html"))
        .mount(&mock_server)
        .await;
    
    let config = ConfigParameter::new();
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    let urls = Arc::new(vec![mock_server.uri()]);
    let results = http.work(urls).await;
    
    assert_eq!(results.len(), 1);
    let response = &results[0];
    assert_eq!(response.status(), 200);
    assert!(response.body().contains("Hello, World!"));
    assert!(response.success());
}

#[tokio::test] 
#[serial]
async fn test_multiple_status_codes() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/success"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&mock_server)
        .await;
    
    Mock::given(method("GET"))
        .and(path("/notfound"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&mock_server)
        .await;
    
    let config = ConfigParameter::new();
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    let urls = Arc::new(vec![
        format!("{}/success", mock_server.uri()),
        format!("{}/notfound", mock_server.uri()),
    ]);
    let results = http.work(urls).await;
    
    assert_eq!(results.len(), 2);
    
    let success_result = results.iter().find(|r| r.url().contains("/success")).unwrap();
    assert_eq!(success_result.status(), 200);
    assert!(success_result.body().contains("Success"));
    
    let notfound_result = results.iter().find(|r| r.url().contains("/notfound")).unwrap();
    assert_eq!(notfound_result.status(), 404);
}

#[tokio::test]
#[serial]
async fn test_headers_capture() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200)
            .append_header("server", "Apache/2.4.41")
            .append_header("x-powered-by", "PHP/7.4.3"))
        .mount(&mock_server)
        .await;
    
    let config = ConfigParameter::new();
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    let urls = Arc::new(vec![mock_server.uri()]);
    let results = http.work(urls).await;
    
    assert_eq!(results.len(), 1);
    let response = &results[0];
    
    // Check that headers are captured
    let headers = response.headers();
    assert!(headers.contains_key("server"));
    assert!(headers.contains_key("x-powered-by"));
}

#[tokio::test]
#[serial]
async fn test_config_workers() {
    let mock_server = MockServer::start().await;
    
    for i in 1..=5 {
        Mock::given(method("GET"))
            .and(path(format!("/page{}", i)))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!("Page {}", i)))
            .mount(&mock_server)
            .await;
    }
    
    let mut config = ConfigParameter::new();
    config.set_workers(2);
    
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    let urls: Vec<String> = (1..=5)
        .map(|i| format!("{}/page{}", mock_server.uri(), i))
        .collect();
    
    let results = http.work(Arc::new(urls)).await;
    
    assert_eq!(results.len(), 5);
    for response in &results {
        assert_eq!(response.status(), 200);
        assert!(response.body().starts_with("Page "));
    }
}