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
//! * Currently only supports Ipv4 addresses
//! * Reported RTTs may become unreliable on a long run
//!
//! ### Notable reference:
//! * [RFC 792](https://tools.ietf.org/html/rfc792)

#![warn(missing_docs)]
#![warn(intra_doc_link_resolution_failure)]

use crossbeam_channel;
use ctrlc;
use pnet::{
    packet::{ipv4::Ipv4Packet, Packet},
    transport::{ipv4_packet_iter, Ipv4TransportChannelIterator, TransportSender},
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
    time::Instant,
    vec::Vec,
};

mod io;
mod network;

/// Delay before sending each echo request, in *ms*.
///
/// Technically, it's the delay `pingrs` wait for a SIGINT, before starting again the
/// sending loop.
///
/// [`REPLY_SIGINT_DELAY`] + [`REPLY_TIMEOUT`] must **always** equal `PING_DELAY`,
/// otherwise everything *(RTT computation)* is broken (faster...)
const PING_DELAY: u64 = 999;
/// Delay before considering the last packet sent as lost, in *ms*.
///
/// [`REPLY_SIGINT_DELAY`] + `REPLY_TIMEOUT` must **always** equal [`PING_DELAY`],
/// otherwise everything *(RTT computation)* is broken (faster...)
///
const REPLY_TIMEOUT: u64 = 2 * PING_DELAY / 3;
/// Delay to wait for a SIGINT in the reply loop, in *ms*.
///
/// `REPLY_SIGINT_DELAY` + [`REPLY_TIMEOUT`] must **always** equal [`PING_DELAY`],
/// otherwise everything *(RTT computation)* is broken (faster...)
const REPLY_SIGINT_DELAY: u64 = PING_DELAY / 3;

// ========================================================================================
//                  structs to handle statistics printed at program end
// ========================================================================================

/// Link a request to the time it was sent.
#[allow(dead_code)] // looks like rustc can't tell it's being used. Or is it me?
struct TimeData {
    sequence_number: u16,
    /// Timestamp of the instant the request was sent.
    time_of_request: Instant,
    identifier: u16,
}

/// Data to be printed at programm end.
struct StatsData {
    ip: IpAddr,
    nb_req: u16,
    nb_rep: u16,
    loss: f32,
    min: Duration,
    avg: Duration,
    max: Duration,
    stdev: f32,
}

impl StatsData {
    /// Compute relevant data and create a new StatsData with it.
    fn new(ip: IpAddr, sent_count: u16, rec_count: u16, live_data: &mut LiveData) -> StatsData {
        let loss = 100f32 - 100f32 * (rec_count as f32) / (sent_count as f32);
        let stdev = (live_data.mean_sq - (live_data.avg.as_micros().pow(2) as f32)).sqrt();
        StatsData {
            ip,
            nb_req: sent_count,
            nb_rep: rec_count,
            loss,
            min: live_data.min,
            avg: live_data.avg,
            max: live_data.max,
            stdev,
        }
    }
}

/// Data to be updated at each packet reception.
pub struct LiveData {
    /// Minimum RTT.
    min: Duration,
    /// Maximum RTT.
    max: Duration,
    /// Rolling-average RTT.
    avg: Duration,
    /// Mean of squares of RTTs.
    mean_sq: f32,
}

impl LiveData {
    /// Update a (the) [`LiveData`](struct.LiveData.html) instance with
    /// provided RTT and reception counter.
    fn update(&mut self, time: Duration, rec_count: u16) {
        // update min and max
        if time < self.min {
            self.min = time
        } else if time > self.max {
            self.max = time
        }
        // update avg
        self.avg = (self.avg * (rec_count as u32) + time) / ((rec_count + 1) as u32);
        // update mean_sq
        // st_dev will not get better than µs-precision, no big deal
        let rtt_squrd = time.as_micros().pow(2) as f32;
        self.mean_sq = self.mean_sq.mul_add(rec_count as f32, rtt_squrd) / ((rec_count + 1) as f32);
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
    let identifier = echo_request.identifier;

    // send an echo request
    match tx.send_to(echo_request, ip) {
        Ok(_) => {
            let mut data = time_data.lock().unwrap();
            data.push(TimeData {
                sequence_number: seq,
                time_of_request: Instant::now(),
                identifier,
            });
        }
        Err(e) => println!("Error sending echo message: {}", e),
    }
}

/// Wait until the next received ICMP packet is successfully interpreted
/// as a [`ICMPPacket`](network/struct.ICMPPacket.html) instance and
/// successfully linked to a previous echo request sent by us. Then
/// call [`print_and_update`](fn.print_and_update.html).
///
/// Will block the thread for `reply_timeout` if no received packet meets
/// the aforementioned conditions.
fn wait_for_valid_echo_reply_with_timeout(
    iter: &mut Ipv4TransportChannelIterator,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
    live_data: &mut LiveData,
    rec_count: u16,
    reply_timeout: Duration,
) -> bool {
    // wait for next ICMP packet to be received, but for no more than reply_timeout
    let next_packet = iter.next_with_timeout(reply_timeout);
    // when received, save a timestamp
    let delay = Instant::now();
    // validate the received request
    // also, match madness, ft. indentation fury
    match next_packet {
        Ok(packet) => match packet {
            Some(p) => {
                let (ip_packet, ip_source_addr) = p;
                // check if reply can be linked to one of our requests
                match validate_ip_packet(ip_packet, time_data) {
                    Some(args) => {
                        let (seq, t) = args;
                        print_and_update(ip_source_addr, live_data, rec_count, seq, t);
                        return true;
                    }
                    None => match reply_timeout.checked_sub(delay.elapsed()) {
                        Some(d) => wait_for_valid_echo_reply_with_timeout(
                            iter, time_data, live_data, rec_count, d,
                        ),
                        None => {
                            eprintln!("Reached timeout waiting for echo request");
                            return false;
                        }
                    },
                }
            }
            None => {
                eprintln!("Reached timeout waiting for echo request");
                return false;
            }
        },
        Err(err) => {
            eprintln!("Error receiving ICMP packet: {}", err);
            return false;
        }
    }
}

// ========================================================================================
//                                          utils
// ========================================================================================

/// Check if a received echo reply corresponds to a sent echo request.
///
/// If true, return its sequence number and [`time_of_request`]
/// for printing purpose.
///
/// Link between replies and requests is made by comparing their (randomly-generated and
/// identically-returned) [`identifier`] field.
///
/// [`time_of_request`]: struct.TimeData.html#structfield.time_of_request
/// [`identifier`]: network/struct.ICMPPacket.html#structfield.identifier
fn validate_ip_packet(
    ip_packet: Ipv4Packet,
    time_data: &Arc<Mutex<Vec<TimeData>>>,
) -> Option<(usize, Instant)> {
    // build an ICMPPacket struct from raw bytes
    match network::ICMPPacket::from_packet(ip_packet.payload()) {
        Some(valid_icmp_packet) => {
            // access the position of the corresponding request in the TimeData vector
            let time_data = Arc::clone(&time_data);
            let data = time_data.lock().unwrap();
            let seq = valid_icmp_packet.sequence_number as usize;

            // check identifiers
            if data[seq].identifier != valid_icmp_packet.identifier {
                return None;
            } else {
                return Some((seq, data[seq].time_of_request));
            }
        }
        None => None,
    }
}

/// Print source IP address, sequence number and RTT,
/// and [`update`](struct.LiveData.html#method.update) live data.
fn print_and_update(
    ip_addr: IpAddr,
    live_data: &mut LiveData,
    rec_count: u16,
    seq: usize,
    t: std::time::Instant,
) {
    // compute the RTT
    let time = t.elapsed();

    // update live data
    live_data.update(time, rec_count);

    // pretty print
    println!(
        "Echo reply from {}: ICMP seq n°{}, RTT: {:?}",
        ip_addr,
        seq + 1,
        format_time(time)
    );
}

/// Print statistics on SIGINT call.
fn final_print(stats: StatsData) {
    println!("\n=== {} PING statistics ===", stats.ip);
    println!(
        "Requests sent: {}\nReplies received: {}\nPacket loss: {}%",
        stats.nb_req, stats.nb_rep, stats.loss
    );
    println!(
        "RTT: min: {:?} / avg: {:?} / max: {:?} / stdev: {:?}",
        format_time(stats.min),
        format_time(stats.avg),
        format_time(stats.max),
        format_time(Duration::from_micros(stats.stdev.round() as u64))
    );
}

/// Truncate a duration to µs precision, for displaying purpose.
fn format_time(d: Duration) -> Duration {
    let d_microsec_part = d.subsec_micros();
    let d_whole_sec = d.as_secs();
    Duration::new(d_whole_sec, d_microsec_part * 1000)
}

// ========================================================================================
//                                           main
// ========================================================================================

/// Start `pingrs`.
///
/// Handle threads and respond to SIGINT signals to print final ping statistics.
fn main() {
    /**************************** check loops synchronization ****************************/
    // this is fundamental, as reported RTTs will be complitely off without proper sync
    assert_eq!(
        PING_DELAY,
        REPLY_SIGINT_DELAY + REPLY_TIMEOUT,
        "Fatal error: sender and receiver loops are not synchronized"
    );
    /***************************** get IP to ping by CL args *****************************/

    let ip = match io::get_target_from_cl() {
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
        min: Duration::new(u64::MAX, 999_999_999), // max RTT
        max: Duration::new(0, 0),                  // min RTT
        avg: Duration::new(0, 0),                  // average RTT
        mean_sq: 0f32,                             // mean of squares of RTTs
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

    println!("=== Pinging {} ===", ip);
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

            // wait for SIGINT for PING_DELAY
            match receiver2.recv_timeout(Duration::from_millis(PING_DELAY)) {
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
                // listen to echo replies, stop if reply is valid or timeout is reached
                let received_valid_reply = wait_for_valid_echo_reply_with_timeout(
                    &mut iter,
                    &time_data,
                    &mut live_data,
                    rec_count,
                    Duration::from_millis(REPLY_TIMEOUT),
                );

                // increment counter without overloading
                if rec_count == u16::MAX - 1 {
                    println!("Enough...");
                    break;
                } else if received_valid_reply {
                    rec_count += 1;
                }

                // wait for SIGINT for SIGINT_DELAY and print stats if received
                match receiver.recv_timeout(Duration::from_millis(REPLY_SIGINT_DELAY)) {
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
