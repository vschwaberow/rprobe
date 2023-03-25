// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>


#![allow(dead_code)]
pub mod apachebasic;

use crate::httpinner::HttpInner;

pub trait Plugin {
    fn name(&self) -> String;
    fn description(&self) -> String;
    fn version(&self) -> String;
    fn author(&self) -> String;
    fn license(&self) -> String;
    fn run(&self, http_inner: &HttpInner) -> String;
}

pub struct PluginHandler {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginHandler {
    pub fn new() -> Self {
        let mut phandler = Self {
            plugins: Vec::new(),
        };
        phandler.register_known_plugins();
        phandler
    }

    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    pub fn list(&self) -> Vec<String> {
        let mut list = Vec::new();
        for plugin in &self.plugins {
            list.push(format!(
                "{} {} - {}",
                plugin.name(),
                plugin.version(),
                plugin.description()
            ));
        }
        list.sort();
        list
    }

    pub fn run(&self, http_inner: &HttpInner) -> String {
        let mut complete = String::new();
        for plugin in &self.plugins {
            let output = plugin.run(&http_inner);
            complete.push_str(&format!("{} ", output));
        }
        complete
    }

    pub fn register_known_plugins(&mut self) {
        self.register(Box::new(apachebasic::ApacheBasicPlugin::new()));
    }
}
