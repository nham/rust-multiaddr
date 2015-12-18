extern crate byteorder;
extern crate rust_multihash;
extern crate varint;

use byteorder::{BigEndian, WriteBytesExt};
use rust_multihash::Multihash;
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use varint::{VarintWrite, VarintRead};

use protocols::{Protocol, ProtocolSize, ProtocolType};
use protocols::ProtocolType::*;

mod protocols;

#[derive(Debug)]
pub struct Multiaddr {
    bytes: Vec<u8>,
}

pub enum ParseError {
    InvalidCode(String),
    InvalidAddress(String),
    Other(String),
}

impl Multiaddr {
    pub fn from_string(s: &str) -> Result<Multiaddr, ParseError> {
        let bytes = try!(parse_str_to_bytes(s));
        Ok(Multiaddr { bytes: bytes })
    }

    pub fn from_bytes(b: Vec<u8>) -> Result<Multiaddr, ParseError> {
        try!(verify_multiaddr_bytes(&b[..]));
        Ok(Multiaddr { bytes: b })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..]
    }
}

fn parse_str_to_bytes(s: &str) -> Result<Vec<u8>, ParseError> {
    let s = s.trim_right_matches('/');
    let segs_vec: Vec<_> = s.split('/').collect();

    if segs_vec[0] != "" {
        return Err(ParseError::Other(format!("Multiaddr must begin with '/'")));
    }

    let mut segs = &segs_vec[1..];
    let mut ma = Cursor::new(Vec::new());

    while segs.len() > 0 {
        let p = try!(Protocol::from_str(segs[0]).map_err(|_| {
            ParseError::InvalidCode(format!("Invalid protocol: {}", segs[0]))
        }));

        segs = &segs[1..];

        if let ProtocolSize::Fixed(0) = p.size {
            continue;
        }

        // If we reach here, we are looking for an address
        if segs.len() == 0 {
            return Err(ParseError::InvalidAddress(format!(
                "Address not found for protocol {}",
                p.ty)));
        }

        let bytes = try!(address_string_to_bytes(segs[0], &p)
                             .map_err(|e| ParseError::InvalidAddress(e)));
        // I don't think these can fail?
        ma.write_unsigned_varint_32(p.ty.code()).unwrap();
        ma.write_all(&bytes[..]).unwrap();

        segs = &segs[1..];
    }

    Ok(ma.into_inner())
}

fn address_string_to_bytes(s: &str, proto: &Protocol) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    match proto.ty {
        IP4 => {
            match Ipv4Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip4 address: {}", e)),
                Ok(ip) => {
                    v.extend(ip.octets().iter());
                    Ok(v)
                }
            }
        }
        IP6 => {
            match Ipv6Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip6 address: {}", e)),
                Ok(ip) => {
                    // this seems ugly but I don't know how to do it better
                    for &seg in ip.segments().iter() {
                        try!(v.write_u16::<BigEndian>(seg)
                              .map_err(|e| format!("Error writing ip6 bytes: {}", e)));
                    }
                    Ok(v)
                }
            }
        }
        IPFS => {
            // verify string is a valid Multihash and convert it to bytes
            let mut bytes = try!(Multihash::from_base58_str(s)).into_bytes();
            let mut cursor = Cursor::new(v);
            cursor.write_unsigned_varint_32(bytes.len() as u32).unwrap();
            let mut v = cursor.into_inner();
            v.append(&mut bytes);
            Ok(v)
        }
        TCP | UDP | SCTP | DCCP => {
            match s.parse::<u16>() {
                Err(e) => Err(format!("Error parsing tcp/udp/sctp/dccp port number: {}", e)),
                Ok(port) => {
                    try!(v.write_u16::<BigEndian>(port)
                          .map_err(|e| format!("Error writing port bytes: {}", e)));
                    Ok(v)
                }
            }
        }
        ONION => unimplemented!(),

        // this function should not be called on the other protocols because they have no
        // address to parse
        _ => unreachable!(),
    }
}

fn verify_multiaddr_bytes(mut bytes: &[u8]) -> Result<(), ParseError> {
    // while not end of input:
    //   read varint (protocol type code)
    //   if fixed-length, read that number of bytes
    //   if variable length, read varint and then that number of bytes.
    //
    while bytes.len() > 0 {
        let code = try!(bytes.read_unsigned_varint_32().map_err(|e| {
            ParseError::InvalidCode(format!("Error reading varint: {}", e))
        }));
        let proto_type = try!(ProtocolType::from_code(code).map_err(|_| {
            ParseError::InvalidCode(format!("Invalid protocol type code: {}", code))
        }));
        let addr_size = match proto_type.size() {
            ProtocolSize::Fixed(0) => continue,
            ProtocolSize::Fixed(n) => n,
            ProtocolSize::Variable => {
                try!(bytes.read_unsigned_varint_32().map_err(|e| {
                    ParseError::InvalidAddress(format!("Error reading varint: {}", e))
                }))
            }
        };

        if bytes.len() < addr_size as usize {
            return Err(ParseError::InvalidAddress(format!(
                "Unexpected end of bytes, expected {} more, found {}",
                addr_size,
                bytes.len()
            )));
        }

        bytes = &bytes[addr_size as usize..];
    }
    Ok(())
}


#[cfg(test)]
mod test {
    use super::Multiaddr;

    #[test]
    fn test_fail_construct() {
        // Cases taken from go-multiaddr tests
        let cases = ["/ip4",
                     "/ip4",
                     "/ip4/::1",
                     "/ip4/fdpsofodsajfdoisa",
                     "/ip6",
                     "/udp",
                     "/tcp",
                     "/sctp",
                     "/udp/65536",
                     "/tcp/65536",
                     // "/onion/9imaq4ygg2iegci7:80",
                     // "/onion/aaimaq4ygg2iegci7:80",
                     // "/onion/timaq4ygg2iegci7:0",
                     // "/onion/timaq4ygg2iegci7:-1",
                     // "/onion/timaq4ygg2iegci7",
                     // "/onion/timaq4ygg2iegci@:666",
                     //
                     "/udp/1234/sctp",
                     "/udp/1234/udt/1234",
                     "/udp/1234/utp/1234",
                     "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
                     "/ip4/127.0.0.1/udp",
                     "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
                     "/ip4/127.0.0.1/tcp",
                     "/ip4/127.0.0.1/ipfs",
                     "/ip4/127.0.0.1/ipfs/tcp"];

        for case in &cases {
            assert!(Multiaddr::from_string(case).is_err());
        }
    }

    #[test]
    fn test_succeed_construct() {
        // Cases taken from go-multiaddr tests
        let cases = ["/ip4/1.2.3.4",
                     "/ip4/0.0.0.0",
                     "/ip6/::1",
                     "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
                     // "/onion/timaq4ygg2iegci7:1234"),
                     // "/onion/timaq4ygg2iegci7:80/http"),
                     "/udp/0",
                     "/tcp/0",
                     "/sctp/0",
                     "/udp/1234",
                     "/tcp/1234",
                     "/sctp/1234",
                     "/udp/65535",
                     "/tcp/65535",
                     "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
                     "/udp/1234/sctp/1234",
                     "/udp/1234/udt",
                     "/udp/1234/utp",
                     "/tcp/1234/http",
                     "/tcp/1234/https",
                     "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
                     "/ip4/127.0.0.1/udp/1234",
                     "/ip4/127.0.0.1/udp/0",
                     "/ip4/127.0.0.1/tcp/1234",
                     "/ip4/127.0.0.1/tcp/1234/",
                     "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
                     "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"];

        for case in &cases {
            assert!(Multiaddr::from_string(case).is_ok());
        }
    }
}
