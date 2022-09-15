# rprobe

This tool takes a domain list / host list from stdio and probes for running HTTP and HTTPS hosts.

## Install

````
cargo install rprobe
````
or clone the source code and run `cargo build --release` to build the binary.

## Usage

````
cat examples/urls_sample.txt | rprobe
cat examples/hosts_sample.txt | rprobe
````

````
rprobe --help

rprobe (c) 2022 by Volker Schwaberow <volker@schwaberow.de>
A simple tool to probe a remote host http or https connection

Usage: cat domains.txt | rprobe [options]
Options:
  -h, --help                    Print this help
  -v, --version                 Print version information
  -t, --timeout                 Set timeout in seconds (default: 10)
````

## Contribution 

If you want to contribute to this project, please feel free to do so. I am happy to accept pull requests. Any help is appreciated. If you have any questions, please feel free to contact me.
