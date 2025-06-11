// File: mod.rs (plugins module)
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

pub mod apachebasic;
pub mod nginxbasic;
pub mod cloudflarebasic;
pub mod wordpressbasic;
pub mod laravel;
pub mod phpbasic;

// #[cfg(test)]
// mod tests;

use crate::httpinner::HttpInner;

pub trait Plugin {
    fn name(&self) -> &'static str;
    fn run(&self, http_inner: &HttpInner) -> Option<String>;
}

pub struct PluginHandler {
    plugins: Vec<Box<dyn Plugin + Send + Sync>>,
}

impl PluginHandler {
    pub fn new() -> Self {
        let mut handler = Self {
            plugins: Vec::new(),
        };
        handler.register_known_plugins();
        handler
    }

    pub fn run(&self, http_inner: &HttpInner) -> Vec<String> {
        self.plugins
            .iter()
            .filter_map(|plugin| {
                plugin
                    .run(http_inner)
                    .map(|result| format!("{}: {}", plugin.name(), result))
            })
            .collect()
    }

    pub fn list(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|plugin| plugin.name().to_string())
            .collect()
    }

    pub fn register_known_plugins(&mut self) {
        self.plugins.push(Box::new(apachebasic::ApacheBasicPlugin));
        self.plugins.push(Box::new(nginxbasic::NginxBasicPlugin));
        self.plugins.push(Box::new(cloudflarebasic::CloudflareBasicPlugin));
        self.plugins.push(Box::new(wordpressbasic::WordpressBasicPlugin));
        self.plugins.push(Box::new(phpbasic::PHPBasicPlugin));
        self.plugins.push(Box::new(laravel::LaravelPlugin));
    }
}