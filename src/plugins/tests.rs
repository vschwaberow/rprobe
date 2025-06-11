use super::*;
use crate::httpinner::HttpInner;
use reqwest::header::{HeaderMap, HeaderValue};
use rstest::*;

fn create_test_http_inner(body: &str, headers: Vec<(&'static str, &'static str)>) -> HttpInner {
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        header_map.insert(
            key,
            HeaderValue::from_str(value).unwrap(),
        );
    }
    
    HttpInner::new_with_all(
        header_map,
        body.to_string(),
        200,
        "https://example.com".to_string(),
        true,
    )
}

fn create_test_http_inner_dynamic(body: &str, key: &str, value: &str) -> HttpInner {
    let mut header_map = HeaderMap::new();
    header_map.insert(
        key,
        HeaderValue::from_str(value).unwrap(),
    );
    
    HttpInner::new_with_all(
        header_map,
        body.to_string(),
        200,
        "https://example.com".to_string(),
        true,
    )
}

#[cfg(test)]
mod plugin_handler_tests {
    use super::*;

    #[test]
    fn test_plugin_handler_initialization() {
        let handler = PluginHandler::new();
        let plugins = handler.list();
        assert!(!plugins.is_empty());
        assert!(plugins.contains(&"Wordpress Basic".to_string()));
        assert!(plugins.contains(&"Apache Basic".to_string()));
        assert!(plugins.contains(&"Nginx Basic".to_string()));
        assert!(plugins.contains(&"Laravel".to_string()));
        assert!(plugins.contains(&"PHP Basic".to_string()));
        assert!(plugins.contains(&"Cloudflare Basic".to_string()));
    }

    #[test]
    fn test_plugin_handler_run_empty_response() {
        let handler = PluginHandler::new();
        let http_inner = create_test_http_inner("", vec![]);
        let results = handler.run(&http_inner);
        assert!(results.is_empty() || results.iter().all(|r| !r.contains("Detected")));
    }

    #[test]
    fn test_plugin_handler_run_wordpress_detection() {
        let handler = PluginHandler::new();
        let http_inner = create_test_http_inner(
            r#"<html><head><meta name="generator" content="WordPress 6.0"></head></html>"#,
            vec![],
        );
        let results = handler.run(&http_inner);
        let wordpress_result = results.iter().find(|r| r.contains("Wordpress Basic"));
        assert!(wordpress_result.is_some());
        assert!(wordpress_result.unwrap().contains("WordPress Detected"));
    }

    #[test]
    fn test_plugin_handler_multiple_detections() {
        let handler = PluginHandler::new();
        let http_inner = create_test_http_inner(
            r#"<html>
                <head><meta name="generator" content="WordPress 6.0"></head>
                <body>
                    <div class="wp-content"></div>
                    <!-- Laravel app -->
                </body>
            </html>"#,
            vec![("server", "Apache/2.4.41")],
        );
        let results = handler.run(&http_inner);
        assert!(results.len() >= 2); // At least WordPress and Apache
    }
}

#[cfg(test)]
mod wordpress_plugin_tests {
    use super::*;
    use wordpressbasic::WordpressBasicPlugin;

    #[rstest]
    #[case(r#"<meta name="generator" content="WordPress 6.0">"#, "Meta Generator")]
    #[case(r#"<link href="/wp-content/themes/twentytwenty/style.css">"#, "WP Content")]
    #[case(r#"<script src="/wp-includes/js/jquery.js"></script>"#, "WP Includes")]
    #[case(r#"<link rel='https://api.w.org/' href='https://example.com/wp-json/' />"#, "WordPress API Link")]
    fn test_wordpress_detection_patterns(#[case] html: &str, #[case] expected_detection: &str) {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(html, vec![]);
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains(expected_detection));
    }

    #[test]
    fn test_wordpress_multiple_patterns() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<html>
                <meta name="generator" content="WordPress 6.0">
                <link href="/wp-content/themes/style.css">
                <script src="/wp-includes/js/jquery.js"></script>
            </html>"#,
            vec![],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        let detection = result.unwrap();
        assert!(detection.contains("Meta Generator"));
        assert!(detection.contains("WP Content"));
        assert!(detection.contains("WP Includes"));
    }

    #[test]
    fn test_wordpress_no_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("<html><body>Regular HTML</body></html>", vec![]);
        let result = plugin.run(&http_inner);
        assert!(result.is_none());
    }

    #[test]
    fn test_wordpress_case_insensitive() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<META NAME="GENERATOR" CONTENT="WordPress 6.0">"#,
            vec![],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
    }
}

#[cfg(test)]
mod apache_plugin_tests {
    use super::*;
    use apachebasic::ApacheBasicPlugin;

    #[rstest]
    #[case("Apache", true)]
    #[case("Apache/2.4.41", true)]
    #[case("Apache/2.4.41 (Ubuntu)", true)]
    #[case("nginx", false)]
    #[case("Microsoft-IIS/10.0", false)]
    fn test_apache_server_header_detection(#[case] server_value: &str, #[case] should_detect: bool) {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner_dynamic("", "server", server_value);
        let result = plugin.run(&http_inner);
        assert_eq!(result.is_some(), should_detect);
        if should_detect {
            assert!(result.unwrap().contains("Apache"));
        }
    }

    #[test]
    fn test_apache_body_detection() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<!-- Powered by Apache/2.4.41 -->",
            vec![],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Apache"));
    }
}

#[cfg(test)]
mod nginx_plugin_tests {
    use super::*;
    use nginxbasic::NginxBasicPlugin;

    #[rstest]
    #[case("nginx", true)]
    #[case("nginx/1.18.0", true)]
    #[case("nginx/1.18.0 (Ubuntu)", true)]
    #[case("Apache", false)]
    #[case("cloudflare", false)]
    fn test_nginx_server_header_detection(#[case] server_value: &str, #[case] should_detect: bool) {
        let plugin = NginxBasicPlugin;
        let http_inner = create_test_http_inner_dynamic("", "server", server_value);
        let result = plugin.run(&http_inner);
        assert_eq!(result.is_some(), should_detect);
        if should_detect {
            assert!(result.unwrap().contains("Nginx"));
        }
    }
}

#[cfg(test)]
mod laravel_plugin_tests {
    use super::*;
    use laravel::LaravelPlugin;

    #[test]
    fn test_laravel_cookie_detection() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![("set-cookie", "laravel_session=abc123; path=/; httponly")],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Laravel"));
    }

    #[test]
    fn test_laravel_csrf_token_detection() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            r#"<meta name="csrf-token" content="abc123">"#,
            vec![],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Laravel"));
    }

    #[test]
    fn test_laravel_multiple_indicators() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            r#"<html>
                <meta name="csrf-token" content="abc123">
                <body class="laravel">
                    <!-- Laravel app content -->
                </body>
            </html>"#,
            vec![("set-cookie", "laravel_session=xyz; path=/")],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        let detection = result.unwrap();
        assert!(detection.contains("Laravel"));
        assert!(detection.contains("Multiple indicators"));
    }
}

#[cfg(test)]
mod php_plugin_tests {
    use super::*;
    use phpbasic::PHPBasicPlugin;

    #[rstest]
    #[case("PHP/7.4.3", true)]
    #[case("PHP/8.0.0", true)]
    #[case("Python/3.8", false)]
    fn test_php_x_powered_by_detection(#[case] powered_by: &str, #[case] should_detect: bool) {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner_dynamic("", "x-powered-by", powered_by);
        let result = plugin.run(&http_inner);
        assert_eq!(result.is_some(), should_detect);
        if should_detect {
            let result_str = result.unwrap();
            assert!(result_str.contains("PHP"));
            assert!(result_str.contains(powered_by));
        }
    }

    #[test]
    fn test_php_session_cookie_detection() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![("set-cookie", "PHPSESSID=abc123; path=/")],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("PHP"));
    }
}

#[cfg(test)]
mod cloudflare_plugin_tests {
    use super::*;
    use cloudflarebasic::CloudflareBasicPlugin;

    #[test]
    fn test_cloudflare_server_detection() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "cloudflare")]);
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Cloudflare"));
    }

    #[test]
    fn test_cloudflare_ray_id_detection() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![("cf-ray", "7a1b2c3d4e5f6789-SJC")],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Cloudflare"));
    }

    #[test]
    fn test_cloudflare_multiple_headers() {
        let plugin = CloudflareBasicPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![
                ("server", "cloudflare"),
                ("cf-ray", "7a1b2c3d4e5f6789-SJC"),
                ("cf-cache-status", "HIT"),
            ],
        );
        let result = plugin.run(&http_inner);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Cloudflare"));
    }
}

struct MockPlugin {
    name: &'static str,
    should_detect: bool,
}

impl Plugin for MockPlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn run(&self, _http_inner: &HttpInner) -> Option<String> {
        if self.should_detect {
            Some(format!("{} detected", self.name))
        } else {
            None
        }
    }
}

#[test]
fn test_custom_plugin_implementation() {
    let plugin = MockPlugin {
        name: "Custom Plugin",
        should_detect: true,
    };
    let http_inner = create_test_http_inner("", vec![]);
    let result = plugin.run(&http_inner);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "Custom Plugin detected");
}

#[test]
fn test_plugin_trait_object() {
    let plugins: Vec<Box<dyn Plugin + Send + Sync>> = vec![
        Box::new(MockPlugin {
            name: "Plugin1",
            should_detect: true,
        }),
        Box::new(MockPlugin {
            name: "Plugin2",
            should_detect: false,
        }),
    ];
    
    let http_inner = create_test_http_inner("", vec![]);
    let results: Vec<_> = plugins
        .iter()
        .filter_map(|p| p.run(&http_inner))
        .collect();
    
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], "Plugin1 detected");
}