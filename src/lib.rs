extern crate rust_base58;
extern crate varint;

use rust_base58::FromBase58;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use varint::VarintWrite;

use protocols::{Protocol, ProtocolSize};
use protocols::ProtocolType::*;

mod protocols;

struct Multiaddr(Vec<u8>);

type ParseError = String;

impl Multiaddr {
    fn from_string(s: &str) -> Result<Multiaddr, ParseError> {
        let s = s.trim_right_matches('/');

        let mut segs_vec: Vec<_> = s.split('/').collect();

        if segs_vec[0] != "" {
            return Err("Multiaddr must begin with '/'".to_string());
        }

        let segs = &segs_vec[1..];

        while segs.len() > 0 {
            let p = try!(Protocol::from_str(segs[0]));

            segs = &segs[1..];

            if let ProtocolSize::Fixed(0) = p.size {
                continue
            }

            if segs.len() == 0 {
                return Err(format!("Address not found for protocol {}", p.ty));
            }

            match address_string_to_bytes(segs[0], p) {
            }

        }
        unimplemented!()
    }

    fn from_bytes(s: Vec<u8>) -> Result<Multiaddr, ParseError> {
    }

    fn as_slice(&self) -> &[u8] { &self.0[..] }
    fn into_vec(self) -> Vec<u8> { self.0 }
}

fn address_string_to_bytes(s: &str, proto: Protocol) -> Result<Vec<u8>, ParseError> {
    let mut v = Vec::new();
    match proto.ty {
        IP4 => {
            match Ipv4Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip4 address")),
                Ok(ip) => {
                    v.extend(ip.octets().iter());
                    Ok(v)
                }
            }
        }
        IP6 => {
            match Ipv6Addr::from_str(s) {
                Err(e) => Err(format!("Error parsing ip6 address")),
                Ok(ip) => {
                    // this seems ugly but I don't know how to do it better
                    for &seg in ip.segments().iter() {
                        v.extend([(seg >> 8) as u8, seg as u8].iter());
                    }
                    Ok(v)
                }
            }
        }
        IPFS => {
            match s.from_base58() {
                Err(e) => Err(format!("{}", e)),
                Ok(mut bytes) => {
                    let cursor = Cursor::new(v);
                    try!(cursor.write_unsigned_varint_32(bytes.len() as u32)
                               .map_err(|e| format!("Error: {}", e)));
                    let v = cursor.into_inner();
                    v.append(&mut bytes);
                    Ok(v)
                }
            }
        }
        _ => unimplemented!(),
    }
    
}
