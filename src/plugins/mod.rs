/*
Copyright 2022 Volker Schwaberow <volker@schwaberow.de>
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
Author(s): Volker Schwaberow
*/

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
