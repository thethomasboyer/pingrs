//! References:
//! * [RFC 792](https://tools.ietf.org/html/rfc792)
//! * [a stackoverflow Q/A about byte-concatenation of integers](https://stackoverflow.com/questions/50243866/how-do-i-convert-two-u8-primitives-into-a-u16-primitive)
#![allow(dead_code)]
#![allow(unused_imports)]
use std::net::IpAddr;
use pnet::packet::{ip::IpNextHeaderProtocols, Packet,  icmp::IcmpPacket};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, icmp_packet_iter};
use rand;
use std::{mem, slice, thread, time, process};
use internet_checksum;

mod io;

/* =================================
* constants for 'echo' ICMP messages
* as defined in RFC 792
* ================================== */
// type
const ECHO_REQUEST_TYPE: u8 = 8;
const ECHO_REPLY_TYPE: u8 = 0;
// code
const ECHO_CODE: u8 = 0;

/* =================================
* implementation constants
* ================================== */
const BUFFER_SIZE: usize = 4096;

/// Generic ICMP packet, without any additional data.
#[repr(C)] // see https://doc.rust-lang.org/reference/type-layout.html#the-c-representation
#[derive(Debug)] // keeping the 'rust' representation results in (even) more mess
struct ICMPPacket {
    tos: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence_number: u16,
}

impl ICMPPacket {
    /// Create a ICMPPacket struct from its field values, computing its checksum.
    fn new(tos: u8, code: u8, identifier: u16, sequence_number: u16) -> Option<Self> {
        if (tos != ECHO_REQUEST_TYPE && tos != ECHO_REPLY_TYPE) || code != ECHO_CODE {
            return None;
        } else {
            println!("DEBUG ICMPPacket::new /// tos: {}, code: {}", tos, code);
            Some(ICMPPacket {
                tos,
                code,
                checksum: compute_checksum(tos, code, identifier, sequence_number),
                identifier,
                sequence_number,
            })
        }
    }

    fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() != 8 {return None} // wrong lenght of received packet
        let identifier = concatenate_u8_into_u16(packet[5], packet[6]);
        let sequence_number = concatenate_u8_into_u16(packet[7], packet[8]);
        ICMPPacket::new(packet[1], packet[2], identifier, sequence_number)
    }
}


/// Concatenate a and b into a u16.
//         a                     b
//     +--------+           +--------+
//     |XXXXXXXX|           |YYYYYYYY|
//     +-------++           +-------++
//             |                    |
//    a as u16 |           b as u16 |
// +-----------+----+   +-----------+----+
// |00000000XXXXXXXX|   |00000000YYYYYYYY|
// +--------------+-+   +---------+------+
//                |               |
//  a as u16 << 8 |               |
// +--------------+-+             |
// |XXXXXXXX00000000|             |
// +-----------+----+             |
//             |                  |
//             +------->OR<-------+
//                       |
//                       |
//             +---------+------+
//             |XXXXXXXXYYYYYYYY|
//             +----------------+
fn concatenate_u8_into_u16(a: u8, b: u8) -> u16 {
    ((a as u16) << 8) | (b as u16)
}

fn split_u16_into_u8(int: u16) -> [u8; 2] {
    let left = (int >> 8) as u8;
    let right = ((int << 8) >> 8) as u8;
    [left, right]
}

fn restore_correct_order(p: &mut [u8]) -> &[u8] {
    let mut i = 2;
    while i < 8 {
        p.swap(i, i+1);
        i += 2;
    }
    println!("DEBUG/// {:?}", p);
    p
}

/// Custom implementation of the 'Packet' trait for ICMPPacket
/// in order to be able to send/receive it.
impl Packet for ICMPPacket {
    /// Retrieve the underlying buffer of the packet.
    fn packet(&self) -> &[u8] {
        // this is just about looking at the struct as a &[u8].
        // Because ICMPPacket struct *is actually* [u8; 8] (fixed lenght),
        // there may be a way not to use unsafe code here. 
        // ***searching...
        unsafe {
            // # SAFETY
            // mem::size_of::<ICMPPacket>() is a multiple of mem::size_of::<u8>(), 
            // so that's okay (right?)
            let p = slice::from_raw_parts_mut(
            self as *const _ as *mut u8, 
            8 //mem::size_of::<Self>()
            ); 
            // this gives us 'inverted' low and high parts of
            // u16, because we're little-endian!
            restore_correct_order(p)
        }
    }

    /// Retrieve the payload for the packet.
    fn payload(&self) -> &[u8] {
        &[] // there's no payload (for now!)
    }
}

/// Compute the checksum of a to-be created ICMPPacket without any data.
fn compute_checksum(tos: u8, code: u8, identifier: u16, sequence_number: u16) -> u16 {
    /* From RFC 792: "The checksum is the 16-bit ones's complement of the one's
    complement sum of the ICMP message starting with the ICMP Type.
    For computing the checksum, the checksum field should be zero. */
    let [id_1, id_2] = split_u16_into_u8(identifier);
    let [seq_1, seq_2] = split_u16_into_u8(sequence_number);
    let split = internet_checksum::checksum(&[tos, code, id_1, id_2, seq_1, seq_2]);
    concatenate_u8_into_u16(split[0], split[1])
}

/// Create an echo ICMP packet with given sequence number, and no data.
fn new_echo_request(sequence_number: u16) -> ICMPPacket {
    match ICMPPacket::new(
        ECHO_REQUEST_TYPE,
        ECHO_CODE,
        rand::random::<u16>(),
        sequence_number,
    ) {
        Some(p) => p,
        None => panic!("Error while creating ICMP packet!"),
    }
}

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
            let echo_request = new_echo_request(0);
    
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
