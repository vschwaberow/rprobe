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

use std::io::{self, BufRead};
use tokio::runtime::Runtime;

struct GetState {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    total_time: u64,
    start_time: u64,
    end_time: u64,
}

fn main() {

    let mut tokio_state = GetState {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        total_time: 0,
        start_time: 0,
        end_time: 0,
    };

    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        println!("{} {} by {} under {} license.", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_AUTHORS"), env!("CARGO_PKG_LICENSE"));
        println!("Usage: {}", args[0]);
        std::process::exit(0);
    }

    let stdin = io::stdin();
    let lines = stdin.lock().lines();

    let mut lines_vec = Vec::new();

    for line in lines {
        let line_unwrap = line.unwrap();
        if line_unwrap.starts_with("https://") || line_unwrap.starts_with("http://") {
            let actual = line_unwrap.clone();
            lines_vec.push(actual);
        } else {
            let actual = line_unwrap.clone();
            lines_vec.push(format!("http://{}", actual));
            lines_vec.push(format!("https://{}", actual));
        }
    }

    tokio_state.total_requests = lines_vec.len() as u64;
    tokio_state.start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_millis() as u64;

    let  rt = Runtime::new().unwrap();

    rt.block_on(async {
        for line in lines_vec {
            let client = reqwest::Client::new();
            
            let request = client.get(line).build().unwrap();
            let response = client.execute(request).await;
            match response {
                Ok(response) => {
                    if response.status().is_success() {
                        println!("{}", response.url());
                        tokio_state.successful_requests += 1;
                    }
                },
                Err(_e) => {
                    tokio_state.failed_requests += 1;
                    continue;
                }
            }
        }
    });

    tokio_state.end_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_millis() as u64;
    tokio_state.total_time = tokio_state.end_time - tokio_state.start_time;
    println!("{} requests in {} ms, {} successful, {} failed", tokio_state.total_requests, tokio_state.total_time, tokio_state.successful_requests, tokio_state.failed_requests);

}


