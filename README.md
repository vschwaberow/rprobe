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
  -t, --timeout <TIMEOUT>                  [default: 10]
  -n, --nohttp                             
  -N, --nohttps                            
  -S, --show-unresponsive                  
  -s, --suppress-stats                     
  -d, --detect-all                         
  -p, --plugins                            
  -r, --rate-limit <RATE_LIMIT>            [default: 10]
      --plugin <PLUGIN>                    Specify a plugin to use
      --report-format <REPORT_FORMAT>      [default: text]
      --report-filename <REPORT_FILENAME>  
      --download-robots                    
  -h, --help                               Print help
  -V, --version                            Print version

````

## Plugins

With version 0.5.0 I introduced a plugin probe system which allows to interpretate the response of a probe in a custom way.

Possible are fingerprints of the response body, the response code and the response headers. This allows to detect a lot of different services running on remote hosts. 

Several plugins are already included in the source code. 


## Contribution 

If you want to contribute to this project, please feel free to do so. I am happy to accept pull requests. Any help is appreciated. If you have any questions, please feel free to contact me.
