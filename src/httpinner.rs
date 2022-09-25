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
use reqwest::header::HeaderMap;

#[derive(Debug)]
pub struct HttpInner {
    body: String,
    headers: HeaderMap,
    status: u16,
    success: bool,
    url: String,
}

impl HttpInner {
    pub fn get_body(&self) -> &str {
        &self.body
    }

    pub fn get_headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn get_status(&self) -> u16 {
        self.status
    }

    pub fn get_success(&self) -> bool {
        self.success
    }

    pub fn get_url(&self) -> &str {
        &self.url
    }

    pub fn new() -> Self {
        HttpInner {
            body: "".to_string(),
            headers: HeaderMap::new(),
            status: 0,
            success: false,
            url: "".to_string(),
        }
    }

    pub fn new_with_all(
        headers: HeaderMap,
        body: String,
        status: u16,
        url: String,
        success: bool,
    ) -> Self {
        HttpInner {
            body,
            headers,
            status,
            success,
            url,
        }
    }

    pub fn set_body(&mut self, body: String) {
        self.body = body;
    }

    pub fn set_headers(&mut self, headers: HeaderMap) {
        self.headers = headers;
    }

    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    pub fn set_success(&mut self, success: bool) {
        self.success = success;
    }

    pub fn set_url(&mut self, url: String) {
        self.url = url;
    }
}
