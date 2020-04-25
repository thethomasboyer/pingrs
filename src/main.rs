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
//! * [a stackoverflow Q/A about byte-concatenation of integers]
//! (https://stackoverflow.com/questions/50243866/how-do-i-convert-two-u8-primitives-into-a-u16-primitive)
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, Ipv4TransportChannelIterator, TransportSender};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
    time::SystemTime,
    vec::Vec,
};

mod io;
mod network;

/// Link a request (identified by its sequence number) to the time it was sent.
#[allow(dead_code)] // looks like rustc can't tell it's being used. Or is it me?
struct TimeData {
    sequence_number: u16,
    time_of_request: SystemTime,
}

impl TimeData {
    /// Create a new TimeData instance.
    fn new(sequence_number: u16, time_of_request: SystemTime) -> Self {
        TimeData {
            sequence_number,
            time_of_request,
        }
    }
}

/// Send an echo request, and update the naive vec containing relevant time data.
fn send_echo_request(
    tx: &mut TransportSender,
    ip: IpAddr,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    counter: u16,
) -> () {
    // build ICMP echo request (dumb, it's always the same)
    let echo_request = network::new_echo_request(counter);
    let seq = echo_request.sequence_number;

    // send a echo request
    match tx.send_to(echo_request, ip) {
        Ok(_) => {
            let mut data = time_data.lock().unwrap();
            data.push(TimeData::new(seq, SystemTime::now()));
        }
        Err(e) => println!("Error sending echo message! {}", e),
    }
}

/// Interpret received ICMP packets as ICMPPacket instances, and print relevant info.
fn listen_to_echo_reply(
    iter: &mut Ipv4TransportChannelIterator,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
) -> () {
    match iter.next() {
        Ok(packet) => {
            let (ip_packet, ip_addr) = packet;

            // create a ICMPPacket instance from the raw bytes of the IP packet payload
            let icmp_msg = match network::ICMPPacket::from_packet(ip_packet.payload()) {
                Some(icmp_packet) => icmp_packet,
                None => panic!("Error: failed to retreive echo reply packet!"),
            };

            // pretty print
            print_info_about_reply(time_data, icmp_msg, ip_addr);
        }
        Err(err) => println!("Error receiving echo message! {}", err),
    }
}

/// Print source IP address, sequence number and time to receive reply ('time').
fn print_info_about_reply(
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    icmp_msg: network::ICMPPacket,
    ip_addr: IpAddr,
) {
    let time_data = Arc::clone(&time_data);
    let data = time_data.lock().unwrap();
    let seq = icmp_msg.sequence_number as usize;
    let time = match SystemTime::now().duration_since(data[seq].time_of_request) {
        Ok(n) => n.as_millis(),
        Err(_) => 0u128,
    };
    println!(
        "Echo reply from {}: ICMP seq n°{}, time: {}ms",
        ip_addr, icmp_msg.sequence_number, time
    );
}

fn main() {
    // get IP to ping by CL args
    let ip = match io::parse_ip_from_cl() {
        Ok(addr) => addr,
        Err(s) => {
            panic!("Error parsing CL arguments: {}", s);
        }
    };

    // This is actually a false (tx, rx) pair: they do not belong to the same channel!
    let (mut tx, mut rx) = network::create_transport_gates();

    // counter to identify packets and pair replies with their request
    let mut counter = 0u16;
    // naive 'database' to pair replies and requests, and compute time to receive reply ('time')
    let time_data: Arc<Mutex<Vec<TimeData>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    println!("Pinging {}", ip);

    // start sender thread
    {
        let time_data = Arc::clone(&time_data);
        let sender_thread = thread::spawn(move || loop {
            // ping every second
            send_echo_request(&mut tx, ip, &time_data, counter);

            // increment counter without overloading
            counter = counter.wrapping_add(1);

            // pause
            thread::sleep(Duration::from_secs(1));
        });
        handles.push(sender_thread);
    }

    // start receiver thread
    {
        let time_data = Arc::clone(&time_data);
        let receiver_thread = thread::spawn(move || {
            // iterate over on-the-go received IPv4 packets
            let mut iter = ipv4_packet_iter(&mut rx);
            loop {
                // listen to echo reply (actually any ICMP packet for now)
                listen_to_echo_reply(&mut iter, &time_data);

                // pause
                thread::sleep(Duration::from_secs(1));
            }
        });
        handles.push(receiver_thread);
    }

    for handle in handles {
        handle
            .join()
            .expect("Error joining one of the loops (sender or receiver)");
    }
}
