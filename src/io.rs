use std::env;
use std::net::{IpAddr, Ipv4Addr};

pub fn parse_ip_from_cl() -> Result<IpAddr, String> {
    // collect CL args
    let args: Vec<String> = env::args().collect();

    // get the first one as a &String
    let raw_addr: &String = args.get(1).expect("No CL argument given!");

    // parse it into a [u8; 4]
    let addr: Vec<&str> = raw_addr.split(".").collect();

    // get the address' numbers
    let mut valid_addr = [0u8; 4];
    for i in 0..4 {
        // run through sliced IPv4 address' numbers
        let tmp_get: &str = match addr.get(i) {
            Some(s) => s,
            None => {
                let msg = format!(
                    "Couldn't get the number on position {} of given IP address",
                    i + 1
                );
                return Err(msg);
            }
        };
        // parse it to u8
        let tmp_parsed: u8 = match tmp_get.parse::<u8>() {
            Ok(num) => num,
            Err(err) => {
                let msg = format!(
                    "Couldn't parse to u8 the number on position {} of given IP address, with error: {}",
                    i+1, err
                );
                return Err(msg);
            }
        };

        // check if given args does not have additional characters
        match addr.get(4) {
            Some(_) => return Err("More than 5 '.'-separated numbers found".to_string()),
            None => (),
        }
        // 4 u8's = valid IPv4 address (RFC 791)
        valid_addr[i] = tmp_parsed;
    }

    // convert it to a std IP adress, for convenience and correctness
    let ip = IpAddr::V4(Ipv4Addr::from(valid_addr));
    Ok(ip)
}

pub fn ask_ip_to_user() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}
