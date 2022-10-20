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

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use std::collections::HashMap;

pub struct ApacheBasicPlugin {}

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> String {
        "apache_basic".to_string()
    }

    fn description(&self) -> String {
        "This plugin detects basic Apache web servers".to_string()
    }

    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn author(&self) -> String {
        "Volker Schwaberow".to_string()
    }

    fn license(&self) -> String {
        "MIT".to_string()
    }

    fn run(&self, http_inner: &HttpInner) -> String {
        let mut report_string: String = String::new();
        let sig = self.add_signatures();
        let mut found: Vec<String> = Vec::new();

        let value = sig.get("APACHE_BASIC").unwrap();
        value.iter().for_each(|x| {
            if http_inner.body().contains(x) {
                found.push("APACHE_BASIC".to_string());
            }
        });

        found.iter().for_each(|x| match x.as_str() {
            "APACHE_BASIC" => {
                let s = format!("{}", "Apache Server");
                report_string += &s;
            }
            _ => {}
        });

        report_string
    }
}

impl ApacheBasicPlugin {
    pub fn add_signatures(&self) -> HashMap<String, Vec<&str>> {
        let mut sig = HashMap::new();

        let mut sig_vector = Vec::new();
        sig_vector.push("<html><body><h1>It works!</h1></body></html>");
        sig_vector.push("<html>Apache is functioning normally</html>");
        sig_vector.push( "<body><center>This IP is being shared among many domains.<br>\nTo view the domain you are looking for, simply enter the domain name in the
         │  location bar of your web browser.<br>");
        sig_vector.push("<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>");
        sig_vector.push("This IP is being shared among many domains.");
        sig.insert("APACHE_BASIC".to_string(), sig_vector);
        sig
    }

    pub fn new() -> Self {
        Self {}
    }
}
