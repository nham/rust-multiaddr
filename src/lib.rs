extern crate rust_multihash;
extern crate varint;

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
    bytes: Vec<u8>
}

pub type ParseError = String;

impl Multiaddr {
    pub fn from_string(s: &str) -> Result<Multiaddr, ParseError> {
        let s = s.trim_right_matches('/');
        let segs_vec: Vec<_> = s.split('/').collect();

        if segs_vec[0] != "" {
            return Err("Multiaddr must begin with '/'".to_string());
        }

        let mut segs = &segs_vec[1..];
        let mut ma = Cursor::new(Vec::new());

        while segs.len() > 0 {
            let p = try!(Protocol::from_str(segs[0]));

            segs = &segs[1..];

            if let ProtocolSize::Fixed(0) = p.size { continue }

            if segs.len() == 0 {
                return Err(format!("Address not found for protocol {}", p.ty));
            }

            let bytes = try!(address_string_to_bytes(segs[0], &p));
            try!(ma.write_unsigned_varint_32(p.ty.code())
                   .map_err(|e| format!("{}", e)));
            try!(ma.write_all(&bytes[..])
                   .map_err(|e| format!("{}", e)));

            segs = &segs[1..];
        }

        Ok(Multiaddr { bytes: ma.into_inner() })
    }

    pub fn from_bytes(b: Vec<u8>) -> Result<Multiaddr, ParseError> {
        try!(verify_multiaddr_bytes(&b[..]));
        Ok(Multiaddr { bytes: b })
    }

    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..] }
}

fn address_string_to_bytes(s: &str, proto: &Protocol) -> Result<Vec<u8>, ParseError> {
    let mut v = Vec::new();
    match proto.ty {
        IP4 => {
            match Ipv4Addr::from_str(s) {
                Err(_) => Err(format!("Error parsing ip4 address")),
                Ok(ip) => {
                    v.extend(ip.octets().iter());
                    Ok(v)
                }
            }
        }
        IP6 => {
            match Ipv6Addr::from_str(s) {
                Err(_) => Err(format!("Error parsing ip6 address")),
                Ok(ip) => {
                    // this seems ugly but I don't know how to do it better
                    for &seg in ip.segments().iter() {
                        v.extend(u16_to_u8s(seg).iter());
                    }
                    Ok(v)
                }
            }
        }
        IPFS => {
            // verify string is a valid Multihash and convert it to bytes
            let mut bytes = try!(Multihash::from_base58_str(s)).into_bytes();
            let mut cursor = Cursor::new(v);
            try!(cursor.write_unsigned_varint_32(bytes.len() as u32)
                       .map_err(|e| format!("Error: {}", e)));
            let mut v = cursor.into_inner();
            v.append(&mut bytes);
            Ok(v)
        }
        TCP | UDP | SCTP | DCCP => {
            match s.parse::<u16>() {
                Err(e) => Err(format!("Error parsing tcp/udp/sctp/dccp port number: {}", e)),
                Ok(port) => {
                    v.extend(u16_to_u8s(port).iter());
                    Ok(v)
                }
            }
        }
        ONION => {
            unimplemented!()
        }

        // this function should not be called on the other protocols because they have no
        // address to parse
        _ => unreachable!(),
    }
}

fn verify_multiaddr_bytes(mut bytes: &[u8]) -> Result<(), ParseError> {
    /*
     * while not end of input:
     *   read varint (protocol type code)
     *   if fixed-length, read that number of bytes
     *   if variable length, read varint and then that number of bytes.
     */
    while bytes.len() > 0 {
        let code = try!(bytes.read_unsigned_varint_32()
                              .map_err(|e| format!("{}", e)));
        let proto_type = try!(ProtocolType::from_code(code));
        let addr_size = match proto_type.size() {
            ProtocolSize::Fixed(0) => continue,
            ProtocolSize::Fixed(n) => n,
            ProtocolSize::Variable => try!(bytes.read_unsigned_varint_32()
                                                .map_err(|e| format!("{}", e))),
        };

        if bytes.len() < addr_size as usize {
            return Err(format!("Expected {} bytes, found {}", addr_size, bytes.len()));
        }

        bytes = &bytes[addr_size as usize..];
    }
    Ok(())
}

fn u16_to_u8s(x: u16) -> [u8; 2] {
    [(x >> 8) as u8, x as u8]
}


#[cfg(test)]
mod test {
    use super::Multiaddr;

    #[test]
    fn test_fail_construct() {
        // Cases taken from go-multiaddr tests
        assert!(Multiaddr::from_string("/ip4").is_err());
        assert!(Multiaddr::from_string("/ip4").is_err());
		assert!(Multiaddr::from_string("/ip4/::1").is_err());
		assert!(Multiaddr::from_string("/ip4/fdpsofodsajfdoisa").is_err());
		assert!(Multiaddr::from_string("/ip6").is_err());
		assert!(Multiaddr::from_string("/udp").is_err());
		assert!(Multiaddr::from_string("/tcp").is_err());
		assert!(Multiaddr::from_string("/sctp").is_err());
		assert!(Multiaddr::from_string("/udp/65536").is_err());
		assert!(Multiaddr::from_string("/tcp/65536").is_err());
        /*
		assert!(Multiaddr::from_string("/onion/9imaq4ygg2iegci7:80").is_err());
		assert!(Multiaddr::from_string("/onion/aaimaq4ygg2iegci7:80").is_err());
		assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci7:0").is_err());
		assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci7:-1").is_err());
		assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci7").is_err());
		assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci@:666").is_err());
        */
		assert!(Multiaddr::from_string("/udp/1234/sctp").is_err());
		assert!(Multiaddr::from_string("/udp/1234/udt/1234").is_err());
		assert!(Multiaddr::from_string("/udp/1234/utp/1234").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/udp").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/tcp").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/ipfs").is_err());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/ipfs/tcp").is_err());
    }

    #[test]
    fn test_succeed_construct() {
        // Cases taken from go-multiaddr tests
        assert!(Multiaddr::from_string("/ip4/1.2.3.4").is_ok());
		assert!(Multiaddr::from_string("/ip4/0.0.0.0").is_ok());
		assert!(Multiaddr::from_string("/ip6/::1").is_ok());
		assert!(Multiaddr::from_string("/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21").is_ok());
		//assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci7:1234").is_ok());
		//assert!(Multiaddr::from_string("/onion/timaq4ygg2iegci7:80/http").is_ok());
		assert!(Multiaddr::from_string("/udp/0").is_ok());
		assert!(Multiaddr::from_string("/tcp/0").is_ok());
		assert!(Multiaddr::from_string("/sctp/0").is_ok());
		assert!(Multiaddr::from_string("/udp/1234").is_ok());
		assert!(Multiaddr::from_string("/tcp/1234").is_ok());
		assert!(Multiaddr::from_string("/sctp/1234").is_ok());
		assert!(Multiaddr::from_string("/udp/65535").is_ok());
		assert!(Multiaddr::from_string("/tcp/65535").is_ok());
		assert!(Multiaddr::from_string("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").is_ok());
		assert!(Multiaddr::from_string("/udp/1234/sctp/1234").is_ok());
		assert!(Multiaddr::from_string("/udp/1234/udt").is_ok());
		assert!(Multiaddr::from_string("/udp/1234/utp").is_ok());
		assert!(Multiaddr::from_string("/tcp/1234/http").is_ok());
		assert!(Multiaddr::from_string("/tcp/1234/https").is_ok());
		assert!(Multiaddr::from_string("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/udp/1234").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/udp/0").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/tcp/1234").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/tcp/1234/").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC").is_ok());
		assert!(Multiaddr::from_string("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234").is_ok());
    }
}
