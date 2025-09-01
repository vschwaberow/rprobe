// File: html.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{ReportConfig, ReportData, ReportGenerator, Theme};
use crate::content_analyzer::FindingSeverity;

pub struct HtmlGenerator;

impl HtmlGenerator {
    pub fn new() -> Self {
        Self
    }

    fn render_theme_toggle(&self) -> String {
        r#"
        <script>
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = localStorage.getItem('theme') || 'light';
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            
            html.classList.remove('light', 'dark');
            html.classList.add(newTheme);
            localStorage.setItem('theme', newTheme);
            
            const toggleBtn = document.getElementById('theme-toggle');
            toggleBtn.textContent = newTheme === 'light' ? '🌙' : '☀️';
        }

        document.addEventListener('DOMContentLoaded', function() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.classList.add(savedTheme);
            const toggleBtn = document.getElementById('theme-toggle');
            if (toggleBtn) {
                toggleBtn.textContent = savedTheme === 'light' ? '🌙' : '☀️';
            }
        });
        </script>
        "#
        .to_string()
    }

    fn render_header(&self, data: &ReportData) -> String {
        format!(
            r#"
        <header class="bg-white dark:bg-gray-900 shadow-sm border-b border-gray-200 dark:border-gray-700">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center py-6">
                    <div>
                        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">{}</h1>
                        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                            Generated on {} | {} scans analyzed
                        </p>
                    </div>
                    <div class="flex items-center space-x-4">
                        <button 
                            id="theme-toggle" 
                            onclick="toggleTheme()"
                            class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                        >
                            🌙
                        </button>
                        <div class="flex items-center text-sm text-gray-500 dark:text-gray-400">
                            <span class="inline-block w-3 h-3 bg-green-500 rounded-full mr-2"></span>
                            rprobe v{}
                        </div>
                    </div>
                </div>
            </div>
        </header>
        "#,
            data.title,
            data.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            data.summary.total_scans,
            env!("CARGO_PKG_VERSION")
        )
    }

    fn render_summary_cards(&self, data: &ReportData) -> String {
        let summary = &data.summary;

        format!(
            r#"
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-8 h-8 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
                            <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4 flex-1">
                        <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Total Scans</p>
                        <p class="text-2xl font-bold text-gray-900 dark:text-white">{}</p>
                    </div>
                </div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-8 h-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                            <svg class="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4 flex-1">
                        <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Successful</p>
                        <p class="text-2xl font-bold text-green-600 dark:text-green-400">{}</p>
                    </div>
                </div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-8 h-8 bg-red-100 dark:bg-red-900 rounded-full flex items-center justify-center">
                            <svg class="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4 flex-1">
                        <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Failed</p>
                        <p class="text-2xl font-bold text-red-600 dark:text-red-400">{}</p>
                    </div>
                </div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-8 h-8 bg-purple-100 dark:bg-purple-900 rounded-full flex items-center justify-center">
                            <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4 flex-1">
                        <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Unique URLs</p>
                        <p class="text-2xl font-bold text-purple-600 dark:text-purple-400">{}</p>
                    </div>
                </div>
            </div>
        </div>
        "#,
            summary.total_scans,
            summary.successful_scans,
            summary.failed_scans,
            summary.unique_urls
        )
    }

    fn render_security_findings(&self, data: &ReportData) -> String {
        let security = &data.summary.security_findings;

        if security.total_findings == 0 {
            return r#"
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
                <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-4">Security Analysis</h2>
                <div class="text-center py-8">
                    <div class="w-16 h-16 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mx-auto mb-4">
                        <svg class="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white">No Security Issues Found</h3>
                    <p class="text-gray-500 dark:text-gray-400 mt-2">All scanned endpoints appear to be secure.</p>
                </div>
            </div>
            "#.to_string();
        }

        format!(
            r#"
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-6">Security Findings</h2>
            
            <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <div class="text-center">
                    <div class="text-2xl font-bold text-red-600 dark:text-red-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Critical</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-orange-600 dark:text-orange-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">High</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Medium</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Low</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-gray-600 dark:text-gray-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Info</div>
                </div>
            </div>

            {}
        </div>
        "#,
            security.critical_count,
            security.high_count,
            security.medium_count,
            security.low_count,
            security.info_count,
            self.render_security_categories(security)
        )
    }

    fn render_security_categories(&self, security: &crate::reports::SecuritySummary) -> String {
        if security.categories.is_empty() {
            return String::new();
        }

        let mut categories: Vec<_> = security.categories.iter().collect();
        categories.sort_by(|a, b| b.1.cmp(a.1));

        let mut html = String::from(
            r#"<div class="mt-6"><h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Finding Categories</h3><div class="space-y-2">"#,
        );

        for (category, count) in categories.iter().take(10) {
            let percentage = (**count as f32 / security.total_findings as f32 * 100.0) as usize;
            html.push_str(&format!(
                r#"
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-700 dark:text-gray-300">{}</span>
                    <span class="text-sm font-medium text-gray-900 dark:text-white">{} ({}%)</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div class="bg-blue-600 h-2 rounded-full" style="width: {}%"></div>
                </div>
                "#,
                category, count, percentage, percentage
            ));
        }

        html.push_str("</div></div>");
        html
    }

    fn render_technology_distribution(&self, data: &ReportData) -> String {
        if data.summary.unique_technologies.is_empty() {
            return String::new();
        }

        let mut html = String::from(
            r#"
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-6">Technology Detection</h2>
            <div class="flex flex-wrap gap-2">
        "#,
        );

        for tech in &data.summary.unique_technologies {
            html.push_str(&format!(
                r#"<span class="inline-flex items-center px-3 py-1 rounded-full text-sm bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">{}</span>"#,
                tech
            ));
        }

        html.push_str("</div></div>");
        html
    }

    fn render_tls_summary(&self, data: &ReportData) -> String {
        let tls = &data.summary.tls_summary;

        if tls.total_tls_scans == 0 {
            return String::new();
        }

        let mut html = format!(
            r#"
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-6">TLS Certificate Analysis</h2>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div class="text-center">
                    <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">Certificates Analyzed</div>
                </div>
                <div class="text-center">
                    <div class="text-3xl font-bold text-yellow-600 dark:text-yellow-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">With Warnings</div>
                </div>
                <div class="text-center">
                    <div class="text-3xl font-bold text-red-600 dark:text-red-400">{}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">With Errors</div>
                </div>
            </div>
        "#,
            tls.total_tls_scans, tls.certificates_with_warnings, tls.certificates_with_errors
        );

        if !tls.expiring_soon.is_empty() {
            html.push_str(
                r#"
                <div class="mt-6">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Certificates Expiring Soon</h3>
                    <div class="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                        <div class="space-y-2">
                "#
            );

            for cert in &tls.expiring_soon {
                let urgency_class = if cert.days_until_expiry <= 7 {
                    "text-red-800 dark:text-red-200"
                } else if cert.days_until_expiry <= 14 {
                    "text-orange-800 dark:text-orange-200"
                } else {
                    "text-yellow-800 dark:text-yellow-200"
                };

                html.push_str(&format!(
                    r#"
                    <div class="flex justify-between items-center">
                        <span class="text-sm font-medium {}">{}</span>
                        <span class="text-sm {}">Expires in {} days</span>
                    </div>
                    "#,
                    urgency_class, cert.url, urgency_class, cert.days_until_expiry
                ));
            }

            html.push_str("</div></div></div>");
        }

        html.push_str("</div>");
        html
    }

    fn render_scan_results_table(&self, data: &ReportData) -> String {
        let mut html = String::from(
            r#"
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 class="text-xl font-semibold text-gray-900 dark:text-white">Scan Results</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-900">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">URL</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Technologies</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Security</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Scan Time</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
        "#,
        );

        for scan in &data.scans {
            let status_class = self.get_status_class(&scan.status);
            let status_text = if scan.status == "0" || scan.status == "Failed" {
                "Failed"
            } else {
                &scan.status
            };

            let security_indicator = if scan
                .content_findings
                .iter()
                .any(|f| f.severity == FindingSeverity::Critical)
            {
                r#"<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">Critical</span>"#
            } else if scan
                .content_findings
                .iter()
                .any(|f| f.severity == FindingSeverity::High)
            {
                r#"<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200">High Risk</span>"#
            } else if !scan.content_findings.is_empty() {
                r#"<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200">Issues Found</span>"#
            } else {
                r#"<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200">Clean</span>"#
            };

            let technologies = if scan.detections.is_empty() {
                r#"<span class="text-gray-500 dark:text-gray-400 italic">None detected</span>"#
                    .to_string()
            } else {
                scan.detections.iter()
                    .take(3)
                    .map(|d| {
                        let tech_name = if let Some((name, _)) = d.split_once(": ") {
                            name
                        } else {
                            d
                        };
                        format!(r#"<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 mr-1">{}</span>"#, tech_name)
                    })
                    .collect::<String>()
            };

            html.push_str(&format!(
                r#"
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">
                        <div class="max-w-xs truncate" title="{}">{}</div>
                    </td>
                    <td class="px-6 py-4 text-sm">
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs {}">{}</span>
                    </td>
                    <td class="px-6 py-4 text-sm">
                        <div class="flex flex-wrap">{}</div>
                    </td>
                    <td class="px-6 py-4 text-sm">{}</td>
                    <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{}</td>
                </tr>
                "#,
                scan.url,
                scan.url,
                status_class,
                status_text,
                technologies,
                security_indicator,
                scan.timestamp.format("%m/%d %H:%M")
            ));
        }

        html.push_str("</tbody></table></div></div>");
        html
    }

    fn get_status_class(&self, status: &str) -> &str {
        if status == "0" || status == "Failed" {
            "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200"
        } else if let Ok(code) = status.parse::<u16>() {
            match code {
                200..=299 => "bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200",
                300..=399 => {
                    "bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200"
                }
                400..=499 => {
                    "bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200"
                }
                500..=599 => "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200",
                _ => "bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200",
            }
        } else {
            "bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200"
        }
    }

    fn render_footer(&self) -> String {
        format!(
            r#"
        <footer class="bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 mt-12">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div class="flex justify-between items-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">
                        Generated by rprobe v{} | Professional Security Assessment Tool
                    </div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">
                        Report format: HTML | Theme: Auto-switching
                    </div>
                </div>
            </div>
        </footer>
        "#,
            env!("CARGO_PKG_VERSION")
        )
    }
}

impl ReportGenerator for HtmlGenerator {
    fn generate(&self, data: &ReportData, config: &ReportConfig) -> Result<String> {
        let theme_class = match config.theme {
            Theme::Dark => "dark",
            Theme::Light => "",
            Theme::Auto => "",
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en" class="{}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    fontFamily: {{
                        'sans': ['Inter', 'system-ui', 'sans-serif'],
                    }},
                }}
            }}
        }}
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    {}
    <style>
        @media print {{
            .no-print {{ display: none !important; }}
        }}
        .truncate-url {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
    </style>
</head>
<body class="bg-gray-50 dark:bg-gray-900 min-h-screen">
    {}
    
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {}
        {}
        {}
        {}
        {}
    </main>
    
    {}
</body>
</html>"#,
            theme_class,
            data.title,
            self.render_theme_toggle(),
            self.render_header(data),
            self.render_summary_cards(data),
            self.render_security_findings(data),
            self.render_technology_distribution(data),
            self.render_tls_summary(data),
            self.render_scan_results_table(data),
            self.render_footer()
        );
        Ok(html)
    }

    fn file_extension(&self) -> &'static str {
        "html"
    }

    fn content_type(&self) -> &'static str {
        "text/html"
    }

    fn supports_themes(&self) -> bool {
        true
    }

    fn supports_interactive(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::{ReportConfig, ReportEngine};
    use crate::storage::ScanRecord;
    use uuid::Uuid;

    fn create_test_scan() -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            url: "https://example.com".to_string(),
            status: "200".to_string(),
            detections: vec!["Nginx: Web Server".to_string()],
            content_findings: vec![],
            tls_info: std::collections::HashMap::new(),
            response_time_ms: Some(150),
            response_headers: std::collections::HashMap::new(),
            content_length: Some(1024),
            desync_results: vec![],
            screenshot_path: None,
            robots_txt_content: None,
            scan_config: crate::storage::ScanConfig {
                timeout: 10,
                http: true,
                https: true,
                detect_all: true,
                content_analysis: false,
                tls_analysis: false,
                comprehensive_tls: false,
                screenshot: false,
                download_robots: false,
                desync: false,
                plugin_name: None,
            },
        }
    }

    #[test]
    fn test_html_generation() {
        let generator = HtmlGenerator::new();
        let engine = ReportEngine::new();
        let data = engine.create_report_data(vec![create_test_scan()]);
        let config = ReportConfig::default();

        let result = generator.generate(&data, &config);
        assert!(result.is_ok());

        let html = result.unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("tailwindcss"));
        assert!(html.contains("rprobe Security Scan Report"));
        assert!(html.contains("https://example.com"));
    }

    #[test]
    fn test_theme_support() {
        let generator = HtmlGenerator::new();
        assert!(generator.supports_themes());
        assert!(generator.supports_interactive());
        assert_eq!(generator.file_extension(), "html");
        assert_eq!(generator.content_type(), "text/html");
    }
}
