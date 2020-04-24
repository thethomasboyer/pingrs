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

    let mut counter = 0usize;
    println!("Starting the loops");

    // start sender/receiver threads
    // we'll go async when ready :)
    let sender_thread = thread::spawn(move ||
        loop {
            // build ICMP echo request (dumb, it's always the same)
            let echo_request = network::new_echo_request(0);
    
            // send a echo request
            match tx.send_to(echo_request, ip) {
                Ok(i) => println!("Sent an echo message, with size (?): {}", i),
                Err(e) => println!("Error sending echo message: {}", e),
            }

            // increment counter
            counter += 1;

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
