use internet_checksum;
use pnet::packet::Packet;
use std::slice;
/* =================================
* constants for 'echo' ICMP messages
* as defined in RFC 792
* ================================== */
// type
const ECHO_REQUEST_TYPE: u8 = 8;
const ECHO_REPLY_TYPE: u8 = 0;
// code
const ECHO_CODE: u8 = 0;

/// Generic ICMP packet, without any additional data.
#[repr(C)] // see https://doc.rust-lang.org/reference/type-layout.html#the-c-representation
#[derive(Debug)] // keeping the 'rust' representation results in (even) more mess
pub struct ICMPPacket {
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
