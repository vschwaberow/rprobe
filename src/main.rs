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
mod http;

use atty::Stream;
use getstate::GetState;
use http::Http;
use std::env;
use std::io::{self, BufRead};


fn get_human_readable_time(time: u64) -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::from_timestamp((time / 1000) as i64, 0)
}

fn get_stdio_lines() -> Vec<String> {

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
    lines_vec
}

fn check_for_stdin() {
    if atty::is(Stream::Stdin) {
        print_help();
        std::process::exit(0);
    }
}

fn get_now() -> u64 {
    std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_millis() as u64
}

fn print_prg_info() {
    let prg_info = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let prg_authors = format!("(c) 2022 by {}", env!("CARGO_PKG_AUTHORS"));
    let prg_description = format!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("{} {}", prg_info, prg_authors);
    println!("{}", prg_description);
    println!("");
}

fn print_help() {
    print_prg_info();
    println!("Usage: cat domains.txt | rprobe [options]");
    println!("Options:");
    println!("  -h, --help\t\t\tPrint this help");
    println!("  -v, --version\t\t\tPrint version information");
    println!("  -t, --timeout\t\t\tSet timeout in seconds (default: 10)");
    println!("");
}

#[tokio::main]
async fn main() {

    let mut tokio_state = GetState::new();
    let mut timeout = 10;
    check_for_stdin();

    let args: Vec<String> = env::args().collect();

    for (index, arg) in args.iter().enumerate() {
        if arg == "-t" || arg == "--timeout" {
            timeout = args[index + 1].parse::<u64>().unwrap();
        } else if (arg == "-h" || arg == "--help") && args.len() == 2 {
            print_help();
            std::process::exit(0);
        } else if (arg == "-v" || arg == "--version") && args.len() == 2 {
            print_prg_info();
            std::process::exit(0);
        }
    }

    tokio_state.start_time = get_now();
    let mut http = Http::new(timeout, tokio_state);
    let lines_vec = get_stdio_lines();
    http.state_ptr.total_requests = lines_vec.len() as u64;

    let lines_vec2 = lines_vec.clone();
    http.work(lines_vec2).await;


    http.state_ptr.end_time = get_now();

    println!("");
    println!("{} requests. Started at {} / Ended at {}. {} ms. Successful: {}. Failed: {}.", http.state_ptr.total_requests, get_human_readable_time(http.state_ptr.start_time), get_human_readable_time(http.state_ptr.end_time), http.state_ptr.end_time - http.state_ptr.start_time, http.state_ptr.successful_requests, http.state_ptr.failed_requests);

    
}


