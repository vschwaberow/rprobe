// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

mod config;
mod getstate;
mod http;
mod httpinner;
mod plugins;

use chrono::{DateTime, Utc};
use clap::{ArgGroup, Parser};
use config::ConfigParameter;
use getstate::GetState;
use http::Http;
use std::env;
use std::io::{self, BufRead, IsTerminal};
use std::num::NonZeroU32;
use std::rc::Rc;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    group(
        ArgGroup::new("protocol")
            .required(false)
            .args(["nohttp", "nohttps"])
    )
)]
struct Cli {
    #[arg(
        short = 't',
        long = "timeout",
        value_name = "SECONDS",
        default_value_t = 10
    )]
    timeout: u64,

    #[arg(short = 'n', long = "nohttp", conflicts_with = "nohttps")]
    nohttp: bool,

    #[arg(short = 'N', long = "nohttps", conflicts_with = "nohttp")]
    nohttps: bool,

    #[arg(short = 'S', long = "show-unresponsive")]
    show_unresponsive: bool,

    #[arg(short = 's', long = "suppress-stats")]
    suppress_stats: bool,

    #[arg(short = 'd', long = "detect-all")]
    detect_all: bool,

    #[arg(short = 'p', long = "plugins")]
    list_plugins: bool,

    #[arg(
        short = 'r',
        long = "rate-limit",
        value_name = "RATE",
        default_value_t = 10
    )]
    rate_limit: u32,
}

fn get_human_readable_time(time: u64) -> DateTime<Utc> {
    DateTime::from_timestamp((time / 1000) as i64, 0).unwrap_or_else(|| {
        eprintln!("Error: Could not convert time");
        std::process::exit(1);
    })
}

use std::collections::VecDeque;

fn get_stdio_lines(config_ptr: &ConfigParameter) -> Rc<Vec<String>> {
    let stdin = io::stdin();
    let lines = stdin.lock().lines();
    let mut lines_deque = VecDeque::new();
    for line in lines {
        let line = match line {
            Ok(line) => line.trim().to_string(),
            Err(_) => {
                println!("[!] Error reading line from stdin");
                std::process::exit(1);
            }
        };
        if !line.is_empty() {
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
    }
    Rc::new(lines_deque.into_iter().collect())
}

fn check_for_stdin() {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        print_prg_info();
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut tokio_state = GetState::new();
    let mut config_state = ConfigParameter::new();

    check_for_stdin();

    config_state.set_timeout(cli.timeout);

    if cli.nohttp {
        config_state.set_http(false);
    }

    if cli.nohttps {
        config_state.set_https(false);
    }

    if cli.show_unresponsive {
        config_state.set_print_failed(true);
    }

    if cli.suppress_stats {
        config_state.set_suppress_stats(true);
    }

    if cli.detect_all {
        config_state.set_detect_all(true);
    }

    if cli.list_plugins {
        let plugins = plugins::PluginHandler::new();
        let plugin_list = plugins.list();
        println!("Available plugins:");
        for plugin in plugin_list {
            println!("  {}", plugin);
        }
        std::process::exit(0);
    }

    if !config_state.http() && !config_state.https() {
        println!("Error: You can't use -n and -N at the same time");
        println!();
        print_prg_info();
        std::process::exit(0);
    }

    let rate_limit =
        NonZeroU32::new(cli.rate_limit).unwrap_or_else(|| NonZeroU32::new(10).unwrap());

    tokio_state.set_start_time(get_now());
    let mut http = Http::new(tokio_state, config_state, rate_limit);

    let lines_vec = get_stdio_lines(&config_state);
    http.state_ptr.set_total_requests(lines_vec.len() as u64);

    let results = http.work(lines_vec).await;

    http.state_ptr.set_end_time(get_now());

    for r in results.iter() {
        if r.success() {
            if config_state.detect_all() {
                let plugins = plugins::PluginHandler::new();
                let scan_result = plugins.run(r);
                if !scan_result.is_empty() {
                    println!("{} {}", r.url(), scan_result.join(", "));
                } else {
                    println!("{}", r.url());
                }
            } else {
                println!("{}", r.url());
            }
        } else {
            if config_state.print_failed() {
                println!("{} - failed request.", r.url());
            }
        }
    }

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
