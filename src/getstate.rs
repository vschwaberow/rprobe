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

#[derive(Debug, Clone, Copy)]
pub struct GetState {
    total_requests: u64,
    successful_requests: usize,
    failed_requests: usize,
    start_time: u64,
    end_time: u64,
}

impl GetState {
    pub fn new() -> GetState {
        GetState {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            start_time: 0,
            end_time: 0,
        }
    }

    pub fn add_success(&mut self) {
        self.successful_requests += 1;
    }

    pub fn add_failure(&mut self) {
        self.failed_requests += 1;
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn set_total_requests(&mut self, total_requests: u64) {
        self.total_requests = total_requests;
    }

    pub fn successful_requests(&self) -> usize {
        self.successful_requests
    }

    pub fn failed_requests(&self) -> usize {
        self.failed_requests
    }

    pub fn set_start_time(&mut self, start_time: u64) {
        self.start_time = start_time;
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    pub fn set_end_time(&mut self, end_time: u64) {
        self.end_time = end_time;
    }

    pub fn end_time(&self) -> u64 {
        self.end_time
    }
}
