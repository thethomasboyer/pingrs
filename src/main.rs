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
    pub fn new(
        ip: IpAddr,
        sent_counter: u16,
        rec_counter: u16,
        min: u128,
        max: u128,
        avg: f32,
    ) -> StatsData {
        let loss = 100f32 - 100f32 * (rec_counter as f32) / (sent_counter as f32);
        let mdev = 0f32;
        StatsData {
            ip,
            nb_req: sent_counter,
            nb_rep: rec_counter,
            loss,
            min,
            avg,
            max,
            mdev,
        }
    }
}

struct LiveData {
    min: u128,
    max: u128,
    avg: f32,
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
    min: u128,
    max: u128,
    avg: f32,
    rec_counter: u16,
) -> LiveData {
    match iter.next() {
        Ok(packet) => {
            let (ip_packet, ip_addr) = packet;

            // create a ICMPPacket instance from the raw bytes of the IP packet payload
            let icmp_msg = match network::ICMPPacket::from_packet(ip_packet.payload()) {
                Some(icmp_packet) => icmp_packet,
                None => panic!("Error: failed to retreive echo reply packet!"),
            };

            // pretty print
            get_info_about_reply(time_data, icmp_msg, ip_addr, min, max, avg, rec_counter)
        }
        Err(err) => {
            println!("Error receiving echo message! {}", err);
            LiveData { min, max, avg }
        }
    }
}

/// Print source IP address, sequence number and time to receive reply ('time').
fn get_info_about_reply(
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    icmp_msg: network::ICMPPacket,
    ip_addr: IpAddr,
    mut min: u128,
    mut max: u128,
    mut avg: f32,
    rec_counter: u16,
) -> LiveData {
    let time_data = Arc::clone(&time_data);
    let data = time_data.lock().unwrap();
    let seq = icmp_msg.sequence_number as usize;
    let time = match SystemTime::now().duration_since(data[seq].time_of_request) {
        Ok(n) => n.as_millis(),
        Err(_) => 0u128,
    };
    if time < min {
        min = time
    } else if time > max {
        max = time
    }
    println!(
        "Echo reply from {}: ICMP seq n°{}, RTT: {}ms",
        ip_addr, icmp_msg.sequence_number, time
    );
    avg = (avg * (rec_counter as f32) + (time as f32)) / ((rec_counter + 1) as f32);
    LiveData { min, max, avg }
}

/// Print statistics on CTRL+C call.
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
    println!("(mdev isn't computed)")
}

fn main() {
    /*** get IP to ping by CL args ***/
    /*********************************/
    let ip = match io::parse_ip_from_cl() {
        Ok(addr) => addr,
        Err(s) => {
            panic!("Error parsing CL arguments: {}", s);
        }
    };

    /*** create sender/receiver channels ***/
    /***************************************/
    // This is actually a false (tx, rx) pair: they do not belong to the same channel!
    let (mut tx, mut rx) = network::create_transport_gates();

    /*** initiate stats to be printed at programm end ***/
    /****************************************************/
    // count sent packets, and identify and pair replies with their request
    // using this number as a sequence number, returned unchanged by the reply
    let mut sent_counter = 0u16;
    // count replies
    let mut rec_counter: u16 = 0u16;
    // min RTT
    let mut min = u128::MAX;
    // max RTT
    let mut max = 0u128;
    // average RTT
    let mut avg = 0f32;

    /*** handle concurrency ***/
    /**************************/
    // naive 'database' to pair replies and requests, and compute time to receive reply ('time')
    let time_data: Arc<Mutex<Vec<TimeData>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles: Vec<thread::JoinHandle<_>> = vec![];

    /*** set 'Ctrl+C' handler ***/
    /****************************/
    let (sender, receiver) = crossbeam_channel::bounded(10);
    let (sender2, receiver2) = (sender.clone(), receiver.clone());
    ctrlc::set_handler(move || {
        let _ = sender.send(-1isize);
    })
    .expect("Error setting Ctrl-C handler");

    /*** start pinging ***/
    /*********************/
    println!("### Pinging {} ###", ip);
    // start sender thread
    {
        let time_data = Arc::clone(&time_data);
        let sender_thread = thread::spawn(move || loop {
            // ping every second
            send_echo_request(&mut tx, ip, &time_data, sent_counter);

            // increment counter without overloading
            sent_counter = sent_counter.wrapping_add(1);

            // wait for SIGINT for 1s
            match receiver2.recv_timeout(Duration::from_secs(1)) {
                Ok(-1isize) => {
                    let _ = sender2.send(sent_counter as isize);
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
                let live_data =
                    listen_to_echo_reply(&mut iter, &time_data, min, max, avg, rec_counter);
                min = live_data.min;
                max = live_data.max;
                avg = live_data.avg;

                // increment counter without overloading
                rec_counter = rec_counter.wrapping_add(1);

                // wait for SIGINT for 1s and print stats if received
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(count) => {
                        let stats = StatsData::new(ip, count as u16, rec_counter, min, max, avg);
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
