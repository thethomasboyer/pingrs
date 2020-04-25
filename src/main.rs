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
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use std::{thread, time};

mod io;
mod network;

// buffer receiving packets
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
    let sending_layer = TransportChannelType::Layer4;
    let sending_protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let icmp = sending_layer(sending_protocol);

    // However, for receiving we'll be at layer 3, because we don't want to use the built-in ICMP
    // abstraction from pnet
    let receiving_layer = TransportChannelType::Layer3;
    let receiving_protocol = receiving_layer(IpNextHeaderProtocols::Icmp);

    // abstraction for sending packets
    let (mut tx, _) = match transport_channel(BUFFER_SIZE, icmp) {
        Ok((ts, tr)) => (ts, tr),
        Err(err) => panic!("Error while creating transport channel: {:?}", err),
    };

    // abstraction for receiving packets
    let (_, mut rx) = match transport_channel(BUFFER_SIZE, receiving_protocol) {
        Ok((ts, tr)) => (ts, tr),
        Err(err) => panic!("Error while creating transport channel: {:?}", err),
    };

    let mut counter = 0u16;
    println!("Starting the loops");

    // start sender/receiver threads
    // we'll go async when ready :)
    let sender_thread = thread::spawn(move || loop {
        // build ICMP echo request (dumb, it's always the same)
        let echo_request = network::new_echo_request(counter);

        // send a echo request
        match tx.send_to(echo_request, ip) {
            Ok(i) => println!("-> {} bytes sent to {} ->", i, ip),
            Err(e) => println!("Error sending echo message! {}", e),
        }

        // increment counter without overloading
        counter = counter.wrapping_add(1);

        // pause
        thread::sleep(time::Duration::from_secs(1));
    });

    let receiver_thread = thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            // listen to echo reply (actually any ICMP packet for now)
            match iter.next() {
                Ok(packet) => {
                    let (ip_packet, ip_addr) = packet;
                    let icmp_msg = match network::ICMPPacket::from_packet(ip_packet.payload()) {
                        Some(icmp_packet) => icmp_packet,
                        None => panic!("Error: failed to retreive packet!"),
                    };
                    println!("<- echo reply: {:?}, from ip: {} <-", icmp_msg, ip_addr);
                }
                Err(err) => println!("Error receiving echo message! {}", err),
            }

            // pause
            thread::sleep(time::Duration::from_secs(1));
        }
    });

    sender_thread.join().expect("Error joining the sender loop");
    receiver_thread
        .join()
        .expect("Error joining the receiver loop");
}
