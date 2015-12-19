extern crate byteorder;
extern crate rust_multihash;
extern crate varint;

use byteorder::{BigEndian, WriteBytesExt};
use rust_multihash::Multihash;
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use varint::{VarintWrite, VarintRead};

use protocol::Protocol;
use protocol::Protocol::*;

mod protocol;

#[derive(Debug)]
pub struct Multiaddr {
    bytes: Vec<u8>,
}

impl PartialEq for Multiaddr {
    fn eq(&self, other: &Multiaddr) -> bool {
        self.bytes.iter().eq(other.bytes.iter())
    }
}

impl Eq for Multiaddr { }

impl FromStr for Multiaddr {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = try!(parse_str_to_bytes(s));
        Ok(Multiaddr { bytes: bytes })
    }
}

#[derive(Debug)]
pub enum ParseError {
    InvalidCode(String),
    InvalidAddress(String),
    Other(String),
}

pub type ParseResult<T> = Result<T, ParseError>;

impl Multiaddr {
    pub fn from_bytes(b: Vec<u8>) -> ParseResult<Multiaddr> {
        try!(verify_multiaddr_bytes(&b[..]));
        Ok(Multiaddr { bytes: b })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..]
    }
}

pub trait ToMultiaddr {
    fn to_multiaddr(&self) -> ParseResult<Multiaddr>;
}

fn write_protocol(proto: Protocol, buf: &mut Vec<u8>) {
    buf.write_unsigned_varint_32(u16::from(proto) as u32).unwrap();
}

impl ToMultiaddr for Ipv4Addr {
    fn to_multiaddr(&self) -> ParseResult<Multiaddr> {
        let mut bytes = Vec::new();
        write_protocol(IP4, &mut bytes);
        write_ip4_to_vec(self, &mut bytes);
        Multiaddr::from_bytes(bytes)
    }
}

impl ToMultiaddr for Ipv6Addr {
    fn to_multiaddr(&self) -> ParseResult<Multiaddr> {
        let mut bytes = Vec::new();
        write_protocol(IP6, &mut bytes);
        write_ip6_to_vec(self, &mut bytes);
        Multiaddr::from_bytes(bytes)
    }
}

fn write_ip4_to_vec(ip: &Ipv4Addr, vec: &mut Vec<u8>) {
    vec.extend(ip.octets().iter());
}

fn write_ip6_to_vec(ip: &Ipv6Addr, vec: &mut Vec<u8>) {
    for &seg in ip.segments().iter() {
        vec.write_u16::<BigEndian>(seg).unwrap()
    }
}

fn parse_str_to_bytes(s: &str) -> ParseResult<Vec<u8>> {
    let s = s.trim_right_matches('/');
    let segs_vec: Vec<_> = s.split('/').collect();

    if segs_vec[0] != "" {
        // TODO: should this become InvalidCode instead of Other?
        return Err(ParseError::Other(format!("Multiaddr must begin with '/'")));
    }

    let mut segs = &segs_vec[1..];
    let mut ma = Cursor::new(Vec::new());

    while segs.len() > 0 {
        let p = try!(Protocol::from_str(segs[0]).map_err(|_| {
            ParseError::InvalidCode(format!("Invalid protocol: {}", segs[0]))
        }));

        segs = &segs[1..];

        if let protocol::Size::Fixed(0) = p.size() {
            continue;
        }

        // If we reach here, we are looking for an address
        if segs.len() == 0 {
            return Err(ParseError::InvalidAddress(format!(
                "Address not found for protocol {}",
                p)));
        }

        let bytes = try!(address_string_to_bytes(segs[0], &p)
                             .map_err(|e| ParseError::InvalidAddress(e)));
        // I don't think these can fail?
        ma.write_unsigned_varint_32(u16::from(p) as u32).unwrap();
        ma.write_all(&bytes[..]).unwrap();

        segs = &segs[1..];
    }

    Ok(ma.into_inner())
}

fn address_string_to_bytes(s: &str, proto: &Protocol) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    match *proto {
        IP4 => {
            match Ipv4Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip4 address: {}", e)),
                Ok(ip) => {
                    write_ip4_to_vec(&ip, &mut v);
                    Ok(v)
                }
            }
        }
        IP6 => {
            match Ipv6Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip6 address: {}", e)),
                Ok(ip) => {
                    write_ip6_to_vec(&ip, &mut v);
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
                    v.write_u16::<BigEndian>(port).unwrap();
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
        })) as u16;
        let proto_type = try!(Protocol::from_code(code).map_err(|_| {
            ParseError::InvalidCode(format!("Invalid protocol type code: {}", code))
        }));
        let addr_size = match proto_type.size() {
            protocol::Size::Fixed(0) => continue,
            protocol::Size::Fixed(n) => n,
            protocol::Size::Variable => {
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
    use super::{Multiaddr, ToMultiaddr};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

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
            assert!(Multiaddr::from_str(case).is_err());
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
            assert!(Multiaddr::from_str(case).is_ok());
        }
    }

    #[test]
    fn test_ip4_tomultiaddr() {
        let ip = Ipv4Addr::from_str("1.2.3.4").unwrap();
        assert_eq!(ip.to_multiaddr().unwrap(),
                   Multiaddr::from_str("/ip4/1.2.3.4").unwrap());
    }

    #[test]
    fn test_ip6_tomultiaddr() {
        let addrs = [
            "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
            "/ip6/::1"
        ];

        for addr in &addrs {
            let ip = Ipv6Addr::from_str(&addr[5..]).unwrap();
            assert_eq!(ip.to_multiaddr().unwrap(),
                       Multiaddr::from_str(addr).unwrap());
        }
    }
}
