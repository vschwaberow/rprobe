// File: mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

pub mod apachebasic;
pub mod apachetomcat;
pub mod cloudflarebasic;
pub mod laravel;
pub mod nginxbasic;
pub mod phpbasic;
pub mod splunk;
pub mod wordpress_advanced;
pub mod wordpressbasic;
pub mod xampp;
pub mod xheaders;
pub mod pattern_matcher;

use crate::httpinner::HttpInner;
use log::{debug, trace};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PluginResult {
    pub plugin_name: String,
    pub detection_info: String,
    pub confidence: u8,
    pub execution_time_ms: u128,
    pub category: PluginCategory,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginCategory {
    WebServer,
    ApplicationFramework,
    ContentManagementSystem,
    SecurityTechnology,
    DatabaseSystem,
    JavaApplicationServer,
    LoadBalancer,
    Other,
}

#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub category: PluginCategory,
    pub author: &'static str,
    pub priority: u8,
    pub enabled: bool,
}

pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError>;

    fn initialize(&mut self) -> Result<(), PluginError> {
        Ok(())
    }

    fn cleanup(&mut self) {}

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        http_inner.success()
    }

    fn name(&self) -> &'static str {
        self.metadata().name
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Invalid plugin configuration: {0}")]
    ConfigurationError(String),
    #[error("Plugin timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub enabled_categories: HashSet<PluginCategory>,
    pub disabled_plugins: HashSet<String>,
    pub max_execution_time_ms: u64,
    pub parallel_execution: bool,
    pub confidence_threshold: u8,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled_categories: HashSet::from([
                PluginCategory::WebServer,
                PluginCategory::ApplicationFramework,
                PluginCategory::ContentManagementSystem,
                PluginCategory::JavaApplicationServer,
                PluginCategory::SecurityTechnology,
            ]),
            disabled_plugins: HashSet::new(),
            max_execution_time_ms: 5000,
            parallel_execution: true,
            confidence_threshold: 1,
        }
    }
}

pub struct PluginHandler {
    plugins: Vec<Box<dyn Plugin>>,
    config: PluginConfig,
    plugin_registry: HashMap<String, usize>,
    execution_stats: HashMap<String, PluginStats>,
}

#[derive(Debug, Clone, Default)]
pub struct PluginStats {
    total_runs: u64,
    successful_detections: u64,
    total_execution_time_ms: u128,
    last_error: Option<String>,
}

impl PluginHandler {
    pub fn new() -> Self {
        Self::new_with_config(PluginConfig::default())
    }

    pub fn new_with_config(config: PluginConfig) -> Self {
        debug!("Creating PluginHandler with config: enabled_categories={:?}, max_execution_time={}ms, confidence_threshold={}", 
               config.enabled_categories, config.max_execution_time_ms, config.confidence_threshold);

        let mut handler = Self {
            plugins: Vec::new(),
            config,
            plugin_registry: HashMap::new(),
            execution_stats: HashMap::new(),
        };
        handler.register_known_plugins();
        handler
    }

    pub fn run(&mut self, http_inner: &HttpInner) -> Vec<PluginResult> {
        let start_time = Instant::now();
        let mut results = Vec::new();

        debug!(
            "Running plugin detection on URL: {} (status={}, body_size={})",
            http_inner.url(),
            http_inner.status(),
            http_inner.body().len()
        );

        let runnable_plugins: Vec<_> = self
            .plugins
            .iter()
            .enumerate()
            .filter(|(_, plugin)| {
                let metadata = plugin.metadata();

                if !metadata.enabled {
                    trace!("Plugin '{}' skipped: disabled", metadata.name);
                    return false;
                }

                if !self.config.enabled_categories.contains(&metadata.category) {
                    trace!(
                        "Plugin '{}' skipped: category {:?} not enabled",
                        metadata.name,
                        metadata.category
                    );
                    return false;
                }

                if self.config.disabled_plugins.contains(metadata.name) {
                    trace!("Plugin '{}' skipped: explicitly disabled", metadata.name);
                    return false;
                }

                if !plugin.should_run(http_inner) {
                    trace!(
                        "Plugin '{}' skipped: should_run returned false",
                        metadata.name
                    );
                    return false;
                }

                trace!(
                    "Plugin '{}' will run (category={:?}, priority={})",
                    metadata.name,
                    metadata.category,
                    metadata.priority
                );
                true
            })
            .collect();

        debug!(
            "Executing {} plugins (out of {} total registered)",
            runnable_plugins.len(),
            self.plugins.len()
        );

        for (_index, plugin) in runnable_plugins {
            let plugin_start = Instant::now();
            let metadata = plugin.metadata();

            trace!("Starting plugin '{}' execution", metadata.name);

            match plugin.run(http_inner) {
                Ok(Some(mut result)) => {
                    let execution_time = plugin_start.elapsed().as_millis();
                    result.execution_time_ms = execution_time;
                    let confidence = result.confidence;

                    debug!(
                        "Plugin '{}' detected: {} (confidence={}, time={}ms)",
                        metadata.name, result.detection_info, confidence, execution_time
                    );

                    if result.confidence >= self.config.confidence_threshold {
                        debug!(
                            "Plugin '{}' result accepted (confidence {} >= threshold {})",
                            metadata.name, confidence, self.config.confidence_threshold
                        );
                        results.push(result);

                        let stats = self
                            .execution_stats
                            .entry(metadata.name.to_string())
                            .or_default();
                        stats.successful_detections += 1;
                        stats.total_execution_time_ms += execution_time;
                    } else {
                        debug!(
                            "Plugin '{}' result rejected (confidence {} < threshold {})",
                            metadata.name, confidence, self.config.confidence_threshold
                        );
                    }
                }
                Ok(None) => {
                    let execution_time = plugin_start.elapsed().as_millis();
                    trace!(
                        "Plugin '{}' found no matches (time={}ms)",
                        metadata.name,
                        execution_time
                    );
                }
                Err(e) => {
                    let execution_time = plugin_start.elapsed().as_millis();
                    debug!(
                        "Plugin '{}' failed after {}ms: {}",
                        metadata.name, execution_time, e
                    );

                    let stats = self
                        .execution_stats
                        .entry(metadata.name.to_string())
                        .or_default();
                    stats.last_error = Some(e.to_string());
                }
            }

            let stats = self
                .execution_stats
                .entry(metadata.name.to_string())
                .or_default();
            stats.total_runs += 1;
        }

        results.sort_by(|a, b| {
            b.confidence.cmp(&a.confidence).then_with(|| {
                let plugin_a = self.find_plugin_by_name(&a.plugin_name);
                let plugin_b = self.find_plugin_by_name(&b.plugin_name);

                match (plugin_a, plugin_b) {
                    (Some(pa), Some(pb)) => pa.metadata().priority.cmp(&pb.metadata().priority),
                    _ => std::cmp::Ordering::Equal,
                }
            })
        });

        let total_time = start_time.elapsed().as_millis();
        debug!(
            "Plugin execution completed in {}ms: {} results (sorted by confidence)",
            total_time,
            results.len()
        );

        if !results.is_empty() {
            trace!("Plugin results summary:");
            for (i, result) in results.iter().enumerate() {
                trace!(
                    "  {}. {} - {} (confidence={})",
                    i + 1,
                    result.plugin_name,
                    result.detection_info,
                    result.confidence
                );
            }
        }

        results
    }

    pub fn run_legacy(&mut self, http_inner: &HttpInner) -> Vec<String> {
        self.run(http_inner)
            .into_iter()
            .map(|result| format!("{}: {}", result.plugin_name, result.detection_info))
            .collect()
    }

    pub fn list_detailed(&self) -> Vec<PluginMetadata> {
        self.plugins
            .iter()
            .map(|plugin| plugin.metadata())
            .collect()
    }

    pub fn list(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|plugin| plugin.name().to_string())
            .collect()
    }

    pub fn find_plugin_by_name(&self, name: &str) -> Option<&dyn Plugin> {
        self.plugin_registry
            .get(name)
            .and_then(|&index| self.plugins.get(index))
            .map(|plugin| plugin.as_ref())
    }

    pub fn run_plugin(
        &mut self,
        plugin_name: &str,
        http_inner: &HttpInner,
    ) -> Option<PluginResult> {
        debug!(
            "Running single plugin '{}' on URL: {}",
            plugin_name,
            http_inner.url()
        );

        if let Some(plugin) = self.find_plugin_by_name(plugin_name) {
            let start_time = Instant::now();

            match plugin.run(http_inner) {
                Ok(Some(mut result)) => {
                    let execution_time = start_time.elapsed().as_millis();
                    result.execution_time_ms = execution_time;
                    debug!(
                        "Single plugin '{}' completed in {}ms with confidence {}",
                        plugin_name, execution_time, result.confidence
                    );
                    Some(result)
                }
                Ok(None) => {
                    debug!("Single plugin '{}' found no matches", plugin_name);
                    None
                }
                Err(e) => {
                    debug!("Single plugin '{}' failed: {}", plugin_name, e);
                    None
                }
            }
        } else {
            debug!("Plugin '{}' not found in registry", plugin_name);
            None
        }
    }

    pub fn get_stats(&self) -> &HashMap<String, PluginStats> {
        &self.execution_stats
    }

    pub fn update_config(&mut self, config: PluginConfig) {
        self.config = config;
    }

    pub fn register_known_plugins(&mut self) {
        let plugins_to_register: Vec<Box<dyn Plugin>> = vec![
            Box::new(apachebasic::ApacheBasicPlugin),
            Box::new(nginxbasic::NginxBasicPlugin),
            Box::new(apachetomcat::ApacheTomcatPlugin),
            Box::new(cloudflarebasic::CloudflareBasicPlugin),
            Box::new(xheaders::XHeadersPlugin),
            Box::new(laravel::LaravelPlugin),
            Box::new(phpbasic::PHPBasicPlugin),
            Box::new(splunk::SplunkPlugin),
            Box::new(wordpress_advanced::WordPressAdvancedPlugin),
            Box::new(wordpressbasic::WordpressBasicPlugin),
            Box::new(xampp::XamppPlugin),
        ];

        for (index, plugin) in plugins_to_register.into_iter().enumerate() {
            let plugin_name = plugin.name().to_string();
            self.plugin_registry.insert(plugin_name.clone(), index);
            self.execution_stats
                .insert(plugin_name, PluginStats::default());
            self.plugins.push(plugin);
        }

        debug!("Registered {} plugins", self.plugins.len());
    }

    pub fn register_plugin(&mut self, plugin: Box<dyn Plugin>) {
        let plugin_name = plugin.name().to_string();
        let index = self.plugins.len();

        self.plugin_registry.insert(plugin_name.clone(), index);
        self.execution_stats
            .insert(plugin_name, PluginStats::default());
        self.plugins.push(plugin);
    }
}

impl Default for PluginHandler {
    fn default() -> Self {
        Self::new()
    }
}
