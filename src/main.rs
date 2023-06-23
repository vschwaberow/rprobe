// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

mod config;
mod getstate;
mod http;
mod httpinner;
mod plugins;

use atty::Stream;
use config::ConfigParameter;
use getstate::GetState;
use http::Http;
use std::env;
use std::io::{self, BufRead};
use std::rc::Rc;

fn get_human_readable_time(time: u64) -> chrono::NaiveDateTime {
    let dt = chrono::NaiveDateTime::from_timestamp_opt((time / 1000) as i64, 0);
    match dt {
        Some(dt) => dt,
        None => {
            println!("Error: Could not convert time");
            std::process::exit(1);
        }
    }
}

use std::collections::VecDeque;

fn get_stdio_lines(config_ptr: &ConfigParameter) -> Rc<Vec<String>> {
    let stdin = io::stdin();
    let lines = stdin.lock().lines();
    let mut lines_deque = VecDeque::new();
    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(_) => {
                println!("[!] Error reading line from stdin");
                std::process::exit(1);
            }
        };
        if line.starts_with("https://") || line.starts_with("http://") {
            lines_deque.push_back(line);
        } else {
            match (config_ptr.http(), config_ptr.https()) {
                (true, true) => {
                    lines_deque.push_back(format!("http://{}", line));
                    lines_deque.push_back(format!("https://{}", line));
                }
                (true, false) => lines_deque.push_back(format!("http://{}", line)),
                (false, true) => lines_deque.push_back(format!("https://{}", line)),
                (false, false) => (),
            }
        }
    }
    Rc::new(lines_deque.into_iter().collect())
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
    let prg_description = env!("CARGO_PKG_DESCRIPTION").to_string();
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
    println!("  -p, --plugins\t\t\tList available plugins");
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        "-p" | "--plugins" => {
            let plugins = plugins::PluginHandler::new();
            let l = plugins.list();
            println!("Available plugins:");
            l.iter().for_each(|p| println!("  {}", p));
            std::process::exit(0);
        }
        _ => {}
    });

    if !config_state.http() && !config_state.https() {
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

    results.iter().for_each(|r| match r.success() {
        true => {
            if config_state.detect_all() {
                let plugins = plugins::PluginHandler::new();
                let scan_result = plugins.run(r);
                if !scan_result.is_empty() {
                    println!("{} {}", r.url(), scan_result);
                } else {
                    println!("{}", r.url());
                }
            } else {
                println!("{}", r.url());
            }
        }
        false => {
            if config_state.print_failed() {
                println!("{} - failed request.", r.url());
            }
        }
    });

    if !config_state.suppress_stats() {
        let h = &mut http;
        println!(
            "{} requests. Started at {} / Ended at {}. {} ms. Successful: {}. Failed: {}.",
            h.state_ptr.total_requests(),
            get_human_readable_time(h.state_ptr.start_time()),
            get_human_readable_time(h.state_ptr.end_time()),
            h.state_ptr.end_time() - h.state_ptr.start_time(),
            h.state_ptr.successful_requests(),
            h.state_ptr.failed_requests()
        );
    }
    Ok(())
}
