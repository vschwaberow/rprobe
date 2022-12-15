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
use fxhash::{FxHasher64, FxHasher};
use hashbrown::HashMap;
use regex::Regex;

const NAME: &str = "apache_basic";
const DESCRIPTION: &str = "This plugin detects basic Apache web servers";
const VERSION: &str = "0.1.0";
const AUTHOR: &str = "Volker Schwaberow";   
const LICENSE: &str = "MIT";

pub struct ApacheBasicPlugin {}

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> &str {
        NAME
    }

    fn description(&self) -> &str {
        DESCRIPTION
    }

    fn version(&self) -> &str {
        VERSION
    }

    fn author(&self) -> &str {
        AUTHOR
    }

    fn license(&self) -> &str {
        LICENSE
    }

    fn run(&self, http_inner: &HttpInner) -> String {
        let mut report_string: String = String::new();
        let sig = self.add_signatures();
        let mut found: Vec<String> = Vec::new();
        let mut signature = HashMap::with_hasher(FxHasher64::default());
    
        let value = sig.get(APACHE_BASIC2).unwrap();
        value.iter().for_each(|x| {
            let re = Regex::new(x).unwrap();
            signature.insert(x, "APACHE_BASIC");
            let server_header = http_inner.headers().get("Server").unwrap();
            if sig.contains_key(&hash) {
                found.push(sig.get(&hash).unwrap().to_string());
            }

        });
    
        report_string = found.join(", ");
        report_string
    }

}

impl ApacheBasicPlugin {

    pub fn add_signatures(&self) -> HashMap<u64, Vec<&str>> {
        let signatures = [
            (r"^Apache/(\d+\.\d+\.\d+)$", "APACHE_BASIC"),
            (r"^PHP/(\d+\.\d+\.\d+)$", "PHP"),
            (r"^mod_ssl$", "MOD_SSL"),
        ];
        let mut hash_signatures = HashMap::with_hasher(FxHasher64::default());
        for (re, name) in signatures.iter() {
            let re = Regex::new(re).unwrap();
            let hash = FxHasher::hash(re.as_str());
            hash_signatures.insert(hash, name);
        }
        hash_signatures
    }
    

    pub fn new() -> Self {
        Self {}
    }
}
