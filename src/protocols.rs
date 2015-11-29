use std::fmt;

use self::ProtocolType::*;

pub enum ProtocolType {
    IP4 = 4,
    TCP = 6,
    UDP = 17,
    DCCP = 33,
    IP6 = 41,
    SCTP = 132,
    UTP = 301,
    UDT = 302,
    IPFS = 421,
    HTTP = 480,
    HTTPS = 443,
    ONION = 444,
}

// Size of address in bits
pub enum ProtocolSize {
    Fixed(u32),
    Variable,
}

impl ProtocolType {
    fn from_str(s: &str) -> Result<ProtocolType, String> {
        match s {
            "ip4"   => Ok(IP4),
            "tcp"   => Ok(TCP),
            "udp"   => Ok(UDP),
            "dccp"  => Ok(DCCP),
            "ip6"   => Ok(IP6),
            "sctp"  => Ok(SCTP),
            "utp"   => Ok(UTP),
            "udt"   => Ok(UDT),
            "ipfs"  => Ok(IPFS),
            "http"  => Ok(HTTP),
            "https" => Ok(HTTPS),
            "onion" => Ok(ONION),
            _ => Err(format!("Protocol '{}' not recognized", s))
        }
    }

    fn to_str(&self) -> &'static str {
        match *self {
            IP4 => "ip4",
            TCP => "tcp",
            UDP => "udp",
            DCCP => "dccp",
            IP6 => "ip6",
            SCTP => "sctp",
            UTP => "utp",
            UDT => "udt",
            IPFS => "ipfs",
            HTTP => "http",
            HTTPS => "https",
            ONION => "onion",
        }
    }

    fn size(&self) -> ProtocolSize {
        match *self {
            IP4 => ProtocolSize::Fixed(32),
            TCP => ProtocolSize::Fixed(16),
            UDP => ProtocolSize::Fixed(16),
            DCCP => ProtocolSize::Fixed(16),
            IP6 => ProtocolSize::Fixed(128),
            SCTP => ProtocolSize::Fixed(16),
            UTP => ProtocolSize::Fixed(0),
            UDT => ProtocolSize::Fixed(0),
            IPFS => ProtocolSize::Variable,
            HTTP => ProtocolSize::Fixed(0),
            HTTPS => ProtocolSize::Fixed(0),
            ONION => ProtocolSize::Fixed(80),
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

pub struct Protocol {
    pub ty: ProtocolType,
    pub size: ProtocolSize,
}

impl Protocol {
    pub fn from_str(s: &str) -> Result<Protocol, String> {
        let ty = try!(ProtocolType::from_str(s));
        Ok(Protocol { ty: ty, size: ty.size() })
    }
}
