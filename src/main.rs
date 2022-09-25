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

mod config;
mod getstate;
mod http;
mod httpinner;
mod plugins;

use atty::Stream;
use config::ConfigParameter;
use getstate::GetState;
use http::Http;
use std::borrow::BorrowMut;
use std::env;
use std::io::{self, BufRead};
use std::rc::Rc;

fn get_human_readable_time(time: u64) -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::from_timestamp((time / 1000) as i64, 0)
}

fn get_stdio_lines(config_ptr: &ConfigParameter) -> Rc<Vec<String>> {
    let stdin = io::stdin();
    let lines = stdin.lock().lines();
    let mut lines_vec = Vec::new();
    lines.into_iter().for_each(|line| match line {
        Ok(line) => {
            if line.starts_with("https://") || line.starts_with("http://") {
                lines_vec.push(line);
            } else {
                if config_ptr.get_http() {
                    lines_vec.push(format!("http://{}", line.to_string()));
                }
                if config_ptr.get_https() {
                    lines_vec.push(format!("https://{}", line.to_string()));
                }
            }
        }
        Err(_) => {
            dbg!();
            println!("[!] Error reading line from stdin");
            std::process::exit(1);
        }
    });
    Rc::new(lines_vec)
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
        .unwrap()
        .as_millis() as u64
}

fn print_prg_info() {
    let prg_info = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let prg_authors = format!("(c) 2022 by {}", env!("CARGO_PKG_AUTHORS"));
    let prg_description = format!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("{} {}", prg_info, prg_authors);
    println!("{}", prg_description);
    println!();
}

fn print_help() {
    print_prg_info();
    println!("Usage: cat domains.txt | rprobe [options]");
    println!("Options:");
    println!("  -h, --help\t\t\tPrint this help");
    println!("  -v, --version\t\t\tPrint version information");
    println!("  -t, --timeout\t\t\tSet timeout in seconds (default: 10)");
    println!("  -n, --nohttp\t\t\tDo not probe http://");
    println!("  -N, --nohttps\t\t\tDo not probe https://");
    println!("  -S, --show-unresponsive\tShow unresponsive hosts");
    println!("  -s, --suppress-stats\t\tSuppress statistics");
    println!(" -da, --detect-all\t\tRun all detection plugins on hosts");
    println!();
}

#[tokio::main]
async fn main() {
    let mut tokio_state = GetState::new();
    let mut config_state = ConfigParameter::new();

    check_for_stdin();

    let args: Vec<String> = env::args().collect();

    args.iter().for_each(|arg| match arg.as_str() {
        "-h" | "--help" => {
            print_help();
            std::process::exit(0);
        }
        "-v" | "--version" => {
            print_prg_info();
            std::process::exit(0);
        }
        "-t" | "--timeout" => {
            let timeout = args
                .get(args.iter().position(|r| r == arg).unwrap() + 1)
                .unwrap();
            config_state.set_timeout(timeout.parse::<u64>().unwrap());
        }
        "-n" | "--nohttp" => {
            config_state.set_http(false);
        }
        "-N" | "--nohttps" => {
            config_state.set_https(false);
        }
        "-S" | "--show-unresponsive" => {
            config_state.set_print_failed(true);
        }
        "-s" | "--suppress-stats" => {
            config_state.set_suppress_stats(true);
        }
        "-da" | "--detect-all" => {
            config_state.set_detect_all(true);
        }
        _ => {}
    });

    if !config_state.get_http() && !config_state.get_https() {
        println!("Error: You can't use -n and -N at the same time");
        println!();
        print_help();
        std::process::exit(0);
    }

    tokio_state.set_start_time(get_now());
    let mut http = Http::new(tokio_state, config_state);

    let lines_vec = get_stdio_lines(&config_state);
    http.state_ptr.set_total_requests(lines_vec.len() as u64);

    let results = http.work(lines_vec).await;

    http.state_ptr.set_end_time(get_now());

    results.iter().for_each(|r| match r.get_success() {
        true => {
            if config_state.get_detect_all() {
                let plugins = plugins::PluginHandler::new();
                let scan_result = plugins.run(r);
                if !scan_result.is_empty() {
                    println!("{} {}", r.get_url(), scan_result);
                } else {
                    println!("{}", r.get_url());
                }
            } else {
                println!("{}", r.get_url());
            }
        }
        false => {
            if config_state.get_print_failed() {
                println!("{} - failed request.", r.get_url());
            }
        }
    });

    if !config_state.get_suppress_stats() {
        let hbor = http.borrow_mut();
        println!();
        println!(
            "{} requests. Started at {} / Ended at {}. {} ms. Successful: {}. Failed: {}.",
            hbor.state_ptr.get_total_requests(),
            get_human_readable_time(hbor.state_ptr.get_start_time()),
            get_human_readable_time(hbor.state_ptr.get_end_time()),
            hbor.state_ptr.get_end_time() - hbor.state_ptr.get_start_time(),
            hbor.state_ptr.get_successful_requests(),
            hbor.state_ptr.get_failed_requests()
        );
    }
}
