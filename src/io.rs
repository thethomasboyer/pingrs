/* Copyright 2020 Thomas Boyer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

//! Handle simple I/O tasks.

#![deny(missing_docs)]
#![warn(private_doc_tests)]

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    lookup_ip::LookupIp,
    Resolver,
};

pub fn get_target_from_cl() -> Result<IpAddr, String> {
    // collect CL args
    let args: Vec<String> = env::args().collect();

    // get the first (second :) one as a &String
    let arg: &String = args.get(1).expect("No CL argument given!");

    //
    match parse_ip_from_cl(arg) {
        Ok(ip) => Ok(ip),
        Err(s1) => match resolve_url_from_cl(arg) {
            Ok(ip) => Ok(ip),
            Err(s2) => Err(format!("unknown IP or URL ({} and {})", s1, s2)),
        },
    }
}

/// Attempt to parse an IP address (and validate it as one) from the command-line arguments.
// a bit messy but seems to get the job done for now
fn parse_ip_from_cl(arg: &String) -> Result<IpAddr, String> {
    // parse the first arg into a [u8; 4]
    let addr: Vec<&str> = arg.split(".").collect();

    // get the address' numbers
    let mut valid_addr = [0u8; 4];
    for i in 0..4 {
        // run through sliced IPv4 address' numbers
        let tmp_get: &str = match addr.get(i) {
            Some(s) => s,
            None => {
                let msg = format!(
                    "Couldn't get the number on position {} of given IP address",
                    i + 1
                );
                return Err(msg);
            }
        };

        // parse it to u8
        let tmp_parsed: u8 = match tmp_get.parse::<u8>() {
            Ok(num) => num,
            Err(err) => {
                let msg = format!(
                    "Couldn't parse to u8 the number on position {} of given IP address, with error: {}",
                    i+1, err
                );
                return Err(msg);
            }
        };

        // check if given args does not have additional characters
        match addr.get(4) {
            Some(_) => return Err("More than 5 '.'-separated numbers found".to_string()),
            None => (),
        }

        // 4 u8's = valid IPv4 address (RFC 791)
        valid_addr[i] = tmp_parsed;
    }

    // convert it to a std IP adress, for convenience and correctness
    let ip = IpAddr::V4(Ipv4Addr::from(valid_addr));
    Ok(ip)
}

fn resolve_url_from_cl(arg: &String) -> Result<IpAddr, String> {
    // use Cloudflare's resolver, otherwise switch to system conf
    let resolver = match Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default()) {
        Ok(res) => res,
        Err(err) => {
            println!("Could not use use Cloudfare's DNS resolver: {}", err);
            println!("Switching to default host system configuration");
            Resolver::from_system_conf()
                .expect("An error occured while using default host system configuration")
        }
    };

    // resolve URL
    let response: LookupIp;
    match resolver.lookup_ip(arg) {
        Ok(resp) => response = resp,
        Err(err) => {
            let msg = format!("Could not resolve given URL: {}", err);
            return Err(msg);
        }
    }

    // get the first Ipv4 address given
    let mut ip_addr = response.iter().next();
    while ip_addr != None {
        if ip_addr.unwrap().is_ipv4() {
            println!("(resolved {} as {})", arg, ip_addr.unwrap());
            return Ok(ip_addr.unwrap());
        } else {
            ip_addr = response.iter().next()
        }
    }

    return Err("No Ipv4 address found for this URL".to_string());
}
