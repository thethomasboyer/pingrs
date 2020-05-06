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

//! Send and receive packets, wrap them around abstractions.
//!
//! Duplicates [`pnet`](https://docs.rs/pnet/0.25.0/pnet/) on some points,
//! but the idea was also to implement some packet handling!
//! *(Why would one re-code* `ping`*, after all?)*

#![warn(missing_docs)]
#![warn(intra_doc_link_resolution_failure)]

use internet_checksum;
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};
use std::slice;

/// Size of the `[u8]` buffer receiving packets.
const BUFFER_SIZE: usize = 4096;

// ========================================================================================
//              constants for 'echo' ICMP messages as defined in RFC 792
// ========================================================================================

// type of service
/// 'type' attribute for 'echo' requests. See [RFC 792](https://tools.ietf.org/html/rfc792).
const ECHO_REQUEST_TYPE: u8 = 8;
/// 'type' attribute for 'echo' replies. See [RFC 792](https://tools.ietf.org/html/rfc792).
const ECHO_REPLY_TYPE: u8 = 0;
/// 'code' attribute for 'echo' messages. See [RFC 792](https://tools.ietf.org/html/rfc792).
const ECHO_CODE: u8 = 0;

// ========================================================================================
//          own private implementation of a struct representing an ICMP packet
// ========================================================================================

/// Generic ICMP packet, without any additional payload.
///
/// Reference: [RFC 792](https://tools.ietf.org/html/rfc792)
#[repr(C)] // see https://doc.rust-lang.org/reference/type-layout.html#the-c-representation
#[derive(Debug)] // keeping the 'rust' representation results in (even) more mess
pub struct ICMPPacket {
    tos: u8,
    code: u8,
    checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
}

impl ICMPPacket {
    /// Create a [`ICMPPacket`](struct.ICMPPacket.html) struct from its field values,
    /// and computing its checksum.
    fn new(tos: u8, code: u8, identifier: u16, sequence_number: u16) -> Option<Self> {
        if (tos != ECHO_REQUEST_TYPE && tos != ECHO_REPLY_TYPE) || code != ECHO_CODE {
            return None;
        } else {
            Some(ICMPPacket {
                tos,
                code,
                checksum: compute_checksum(tos, code, identifier, sequence_number),
                identifier,
                sequence_number,
            })
        }
    }

    /// Create a [`ICMPPacket`](struct.ICMPPacket.html) struct from a raw buffer,
    /// with minimal checking: its lenght must be 8.
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() != 8 {
            return None;
        } // wrong lenght of received packet, because not sent by us, or wrongly returned
        let identifier = concatenate_u8_into_u16(packet[4], packet[5]);
        let sequence_number = concatenate_u8_into_u16(packet[6], packet[7]);
        ICMPPacket::new(packet[0], packet[1], identifier, sequence_number)
    }
}

// ========================================================================================
//          implementation of the 'Packet' trait from pnet for our custom trait
// ========================================================================================

/// Custom implementation of the
/// [`Packet`](https://docs.rs/pnet/0.25.0/pnet/packet/trait.Packet.html)
/// trait for [`ICMPPacket`](struct.ICMPPacket.html) in order to be able to send/receive it.
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
                8, //mem::size_of::<Self>()
            );
            // this gives us 'inverted' low and high parts of
            // u16, because we're little-endian!
            restore_correct_order(p)
        }
    }

    /// Retrieve the payload for the packet.
    ///
    /// Currently returns a empty array, since our custom [`ICMPPacket`] implementation
    /// does not have any additional payload.
    ///
    /// [`ICMPPacket`]: struct.ICMPPacket.html
    fn payload(&self) -> &[u8] {
        &[] // there's no payload (for now!)
    }
}

// ========================================================================================
//          create channels which will be in charge of sending and receiving data
// ========================================================================================

/// Create two channels, one at layer 4 to send requests, the other at layer 3
/// to receive replies.
///
/// Quite clunky.
pub fn create_transport_gates() -> (TransportSender, TransportReceiver) {
    // working at layer 4 allows us not to manually define the IP headers.
    // ICMP is *technically* a layer 3 protocol, although, being encapsulated in
    // a IP header, its position is quite confusing (at least from author's perspective :)
    let sending_protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let sender_channel = TransportChannelType::Layer4(sending_protocol);

    // However, for receiving we'll be at layer 3, because we want to minimize the use of the
    // built-in ICMP abstraction from pnet
    let receiver_channel = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);

    let (tx, _) = match transport_channel(BUFFER_SIZE, sender_channel) {
        Ok((ts, tr)) => (ts, tr),
        Err(err) => panic!("Error while creating transport channel: {:?}", err),
    };

    let (_, rx) = match transport_channel(BUFFER_SIZE, receiver_channel) {
        Ok((ts, tr)) => (ts, tr),
        Err(err) => panic!("Error while creating transport channel: {:?}", err),
    };

    (tx, rx)
}

// ========================================================================================
//                                          utils
// ========================================================================================

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
/// Concatenate two `u8`s into a `u16`, first argument is left-positionned.
fn concatenate_u8_into_u16(a: u8, b: u8) -> u16 {
    ((a as u16) << 8) | (b as u16)
}

/// Split a `u16` into two `u8`s, left bits form first returned integer.
fn split_u16_into_u8(int: u16) -> [u8; 2] {
    let left = (int >> 8) as u8;
    let right = ((int << 8) >> 8) as u8;
    [left, right]
}

/// Swap `n` and `n+1` values of an array which are in the range [2, 7]
/// (included), without any check.
///
/// Yes, there is a function for that.
fn restore_correct_order(p: &mut [u8]) -> &[u8] {
    let mut i = 2;
    while i < 8 {
        p.swap(i, i + 1);
        i += 2;
    }
    p
}

/// Compute the checksum of a to-be created [`ICMPPacket`] without any payload.
///
/// Some `u16` to `u8` parsing before using Google's [`internet_checksum`], that's all.
///
/// [`ICMPPacket`]: struct.ICMPPacket.html
/// [`internet_checksum`]: https://docs.rs/internet-checksum/0.2.0/internet_checksum/
pub fn compute_checksum(tos: u8, code: u8, identifier: u16, sequence_number: u16) -> u16 {
    let [id_1, id_2] = split_u16_into_u8(identifier);
    let [seq_1, seq_2] = split_u16_into_u8(sequence_number);
    let split = internet_checksum::checksum(&[tos, code, id_1, id_2, seq_1, seq_2]);
    concatenate_u8_into_u16(split[0], split[1])
}

/// Create an echo [`ICMPPacket`] with given sequence number, and no payload.
///
/// [`ICMPPacket`]: struct.ICMPPacket.html
pub fn new_echo_request(sequence_number: u16) -> ICMPPacket {
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
