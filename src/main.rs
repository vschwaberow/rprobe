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
mod getstate;

use getstate::GetState;
use std::io::{self, BufRead};

fn get_human_readable_time(time: u64) -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::from_timestamp((time / 1000) as i64, 0)
}

#[tokio::main]
async fn main() {

    let mut tokio_state = GetState::new();
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

    let mut tasks = Vec::new();

    for line in lines_vec {
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            
            let res = client.get(&line)
                .timeout(std::time::Duration::from_secs(5))
                .send().await;
            match res {
                Ok(_) => {
                    println!("{}", line);
                    return true;
                }
                Err(_) => {
                    return false;
                }
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        let rval = task.await.unwrap();   
        if rval {
            tokio_state.add_success();
        } else {
            tokio_state.add_failure();
        }

    }

    tokio_state.end_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_millis() as u64;

    println!("");
    println!("{} requests. Started at {} / Ended at {}. {} ms. Successful: {}. Failed: {}.", tokio_state.total_requests, get_human_readable_time(tokio_state.start_time), get_human_readable_time(tokio_state.end_time), tokio_state.end_time - tokio_state.start_time, tokio_state.successful_requests, tokio_state.failed_requests);

    
}


