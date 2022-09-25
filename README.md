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
  -n, --nohttp                  Do not probe http://
  -N, --nohttps                 Do not probe https://
  -S, --show-unresponsive       Show unresponsive hosts
  -s, --suppress-stats          Suppress statistics
 -da, --detect-all              Run all detection plugins on hosts

````

## Plugins

With version 0.5.0 I introduced a plugin probe system which allows to interpretate the response of a probe in a custom way.

Possible are fingerprints of the response body, the response code and the response headers. This allows to detect a lot of different services running on remote hosts. 

A basic Apache plugin is included in the source code. You can find it in the `plugins` directory.

## Contribution 

If you want to contribute to this project, please feel free to do so. I am happy to accept pull requests. Any help is appreciated. If you have any questions, please feel free to contact me.
