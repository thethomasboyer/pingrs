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

//! A concurrent implementation of `ping` in Rust.
//!
//! `pingrs` is a little command-line utility to ping hosts over the network.
//!
//! ### WIP:
//! * Currently only supports Ipv4 addresses, and cannot parse URLs
//! * Untested, unstable
//!
//! ### Notable reference:
//! * [RFC 792](https://tools.ietf.org/html/rfc792)

#![deny(missing_docs)]
#![warn(private_doc_tests)]

use crossbeam_channel;
use ctrlc;
use pnet::{
    packet::Packet,
    transport::{ipv4_packet_iter, Ipv4TransportChannelIterator, TransportSender},
};
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

// ========================================================================================
//                  structs to handle statistics printed at program end
// ========================================================================================

/// Link a request (identified by its sequence number) to the time it was sent.
#[allow(dead_code)] // looks like rustc can't tell it's being used. Or is it me?
struct TimeData {
    sequence_number: u16,
    time_of_request: SystemTime,
}

/// Data to be printed at programm end.
struct StatsData {
    ip: IpAddr,
    nb_req: u16,
    nb_rep: u16,
    loss: f32,
    min: u128,
    avg: f32,
    max: u128,
    mdev: f32,
}

impl StatsData {
    /// Compute relevant data and create a new StatsData with it.
    pub fn new(ip: IpAddr, sent_count: u16, rec_count: u16, live_dat: &mut LiveData) -> StatsData {
        let loss = 100f32 - 100f32 * (rec_count as f32) / (sent_count as f32);
        let mdev = 0f32;
        StatsData {
            ip,
            nb_req: sent_count,
            nb_rep: rec_count,
            loss,
            min: live_dat.min,
            avg: live_dat.avg,
            max: live_dat.max,
            mdev,
        }
    }
}

/// Data to be updated at each packet reception.
pub struct LiveData {
    min: u128,
    max: u128,
    avg: f32,
}

impl LiveData {
    /// Update a (the) [`LiveData`](struct.LiveData.html) instance with
    /// provided RTT and reception counter.
    fn update(&mut self, time: u128, rec_count_f32: f32) {
        if time < self.min {
            self.min = time
        } else if time > self.max {
            self.max = time
        }
        self.avg = (self.avg * (rec_count_f32) + (time as f32)) / (rec_count_f32 + 1.);
    }
}

// ========================================================================================
//                    network functions: send request and react to reply
// ========================================================================================

/// Send an [echo request](network/fn.new_echo_request.html),
/// and [`update`](struct.LiveData.html#method.update) data.
fn send_echo_request(
    tx: &mut TransportSender,
    ip: IpAddr,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    counter: u16,
) -> () {
    // build ICMP echo request
    let echo_request = network::new_echo_request(counter);
    let seq = echo_request.sequence_number;

    // send an echo request
    match tx.send_to(echo_request, ip) {
        Ok(_) => {
            let mut data = time_data.lock().unwrap();
            data.push(TimeData {
                sequence_number: seq,
                time_of_request: SystemTime::now(),
            });
        }
        Err(e) => println!("Error sending echo message: {}", e),
    }
}

/// Interpret received ICMP packets as [`ICMPPacket`] instances, and call
/// [`get_info_about_reply`](fn.get_info_about_reply.html).
///
/// [`ICMPPacket`]: network/struct.ICMPPacket.html
fn listen_to_echo_reply(
    iter: &mut Ipv4TransportChannelIterator,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    live_data: &mut LiveData,
    rec_count: u16,
) {
    // wait for next ICMP packet to be received
    match iter.next() {
        Ok(packet) => {
            let (ip_packet, ip_source_addr) = packet;

            // try to create a ICMPPacket from the raw bytes of the IP packet payload
            // (the received ICMP packet!)
            match network::ICMPPacket::from_packet(ip_packet.payload()) {
                Some(valid_icmp_packet) => get_info_about_reply(
                    time_data,
                    valid_icmp_packet,
                    ip_source_addr,
                    live_data,
                    rec_count,
                ), // print relevant info and update live data
                None => print!("Error reading echo reply packet"),
            };
        }
        Err(err) => {
            println!("Error receiving ICMP packet: {}", err);
        }
    }
}

/// Print source IP address, sequence number and RTT,
/// and [`update`](struct.LiveData.html#method.update) live data.
fn get_info_about_reply(
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    icmp_msg: network::ICMPPacket,
    ip_addr: IpAddr,
    live_data: &mut LiveData,
    rec_count: u16,
) {
    // access the position of the corresponding request in the TimeData vector
    let time_data = Arc::clone(&time_data);
    let data = time_data.lock().unwrap();
    let seq = icmp_msg.sequence_number as usize;

    // compute the RTT
    let time = match SystemTime::now().duration_since(data[seq].time_of_request) {
        Ok(n) => n.as_millis(),
        Err(_) => 0u128,
    };

    // update live data and print info about the received echo reply
    live_data.update(time, rec_count as f32);

    // pretty print
    println!(
        "Echo reply from {}: ICMP seq n°{}, RTT: {}ms",
        ip_addr, icmp_msg.sequence_number, time
    );
}

/// Print statistics on SIGINT call.
fn final_print(stats: StatsData) {
    println!("\n### {} PING statistics ###", stats.ip);
    println!(
        "Requests sent: {}\nReplies received: {}\nPacket loss: {}%",
        stats.nb_req, stats.nb_rep, stats.loss
    );
    println!(
        "RTT (ms): min: {} / avg: {} / max: {} / mdev: {}",
        stats.min, stats.avg, stats.max, stats.mdev
    );
    println!("(mdev isn't computed yet :)")
}

// ========================================================================================
//                                           main
// ========================================================================================

/// Start `pingrs`, handling threads and responding to SIGINT signal to print
/// final ping statistics.
fn main() {
    /***************************** get IP to ping by CL args *****************************/

    let ip = match io::parse_ip_from_cl() {
        Ok(addr) => addr,
        Err(s) => {
            panic!("Error parsing CL arguments: {}", s);
        }
    };

    /************************** create sender/receiver channels **************************/

    // This is actually a false (tx, rx) pair: they do not belong to the same channel!
    let (mut tx, mut rx) = network::create_transport_gates();

    /******************* initiate stats to be printed at programm end ********************/

    // count sent packets, and identify and pair replies with their request
    // using this number as a sequence number, returned unchanged by the reply
    let mut sent_count = 0u16;
    // count received packets
    let mut rec_count: u16 = 0u16;
    // initialise live data
    let mut live_data = LiveData {
        min: u128::MAX, // max RTT
        max: 0u128,     // min RTT
        avg: 0f32,      // average RTT
    };

    /******************************** handle concurrency *********************************/

    // naive 'database' to pair replies and requests,
    // and compute time to receive reply ('time')
    let time_data: Arc<Mutex<Vec<TimeData>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles: Vec<thread::JoinHandle<_>> = vec![];

    /******************************* set 'Ctrl+C' handler ********************************/

    let (sender, receiver) = crossbeam_channel::bounded(2);
    let (sender2, receiver2) = (sender.clone(), receiver.clone());
    ctrlc::set_handler(move || {
        let _ = sender.send(-1isize);
    })
    .expect("Error setting Ctrl-C handler");

    /*********************************** start pinging ***********************************/

    println!("### Pinging {} ###", ip);
    // start sender thread
    {
        let time_data = Arc::clone(&time_data);
        let sender_thread = thread::spawn(move || loop {
            // ping every second
            send_echo_request(&mut tx, ip, &time_data, sent_count);

            // increment counter without overloading
            if sent_count == u16::MAX - 1 {
                println!("Enough...");
                let _ = sender2.send(sent_count as isize);
                break;
            }
            sent_count += 1;
            println!("DEBUG /// {}", sent_count);

            // wait for SIGINT for 1s
            match receiver2.recv_timeout(Duration::from_secs(1)) {
                Ok(-1isize) => {
                    let _ = sender2.send(sent_count as isize);
                    break;
                }
                _ => (),
            }
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
                listen_to_echo_reply(&mut iter, &time_data, &mut live_data, rec_count);

                // increment counter without overloading
                if rec_count == u16::MAX - 1 {
                    println!("Enough...");
                    break;
                }
                rec_count += 1;

                // wait for SIGINT for 1s and print stats if received
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(count) => {
                        let stats = StatsData::new(ip, count as u16, rec_count, &mut live_data);
                        final_print(stats);
                        break;
                    }
                    _ => (),
                }
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
