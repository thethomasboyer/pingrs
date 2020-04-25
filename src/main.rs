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

//! References:
//! * [RFC 792](https://tools.ietf.org/html/rfc792)
//! * [a stackoverflow Q/A about byte-concatenation of integers](https://stackoverflow.com/questions/50243866/how-do-i-convert-two-u8-primitives-into-a-u16-primitive)
use pnet::packet::{ip::IpNextHeaderProtocols};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, icmp_packet_iter};
use std::{thread, time};

mod io;
mod network;

/* =================================
* implementation constants
* ================================== */
const BUFFER_SIZE: usize = 4096;

fn main() {
    // get IP to ping, either by CL args or stdin
    let ip = match io::parse_ip_from_cl() {
        Ok(addr) => addr,
        Err(s) => {
            println!("Error parsing CL arguments: {}", s);
            io::ask_ip_to_user()
        }
    };

    // working at layer 4 allows us not to manually define the IP headers.
    // ICMP is *technically* a layer 3 protocol, although, being encapsulated in
    // a IP header, its position is quite confusing (at least from author's perspective :)
    let layer = TransportChannelType::Layer4;
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let icmp = layer(protocol);

    // abstraction for receiving and sending packets
    let (mut tx, mut rx) = match transport_channel(BUFFER_SIZE, icmp) {
        Ok((ts, tr)) => (ts, tr),
        Err(err) => panic!("Error while creating transport channel: {:?}", err),
    };

    let mut counter = 0u16;
    println!("Starting the loops");

    // start sender/receiver threads
    // we'll go async when ready :)
    let sender_thread = thread::spawn(move ||
        loop {
            // build ICMP echo request (dumb, it's always the same)
            let echo_request = network::new_echo_request(counter);
    
            // send a echo request
            match tx.send_to(echo_request, ip) {
                Ok(i) => println!("-> {} bytes sent to {}", i, ip),
                Err(e) => println!("Error sending echo message: {}", e),
            }

            // increment counter without overloading
            counter = counter.wrapping_add(1);

            // pause
            thread::sleep(time::Duration::from_secs(1));
        }
    );

    let receiver_thread = thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut rx);
        loop {
            println!("DEBUG/// looping on receive");
            // listen to echo reply (actually any ICMP packet for now)
            match iter.next() {
                Ok(packet) => {
                    println!("Received a packet!");
                    let (_, ip_addr) = packet;
                    println!("{}", ip_addr);
                }
                Err(err) => println!("Error: {}", err),
            }

            // pause
            thread::sleep(time::Duration::from_secs(1));
        }
    }
    );

    sender_thread.join().expect("Error joining the sender loop");
    receiver_thread.join().expect("Error joining the receiver loop");
}
