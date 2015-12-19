use std::convert::From;
use std::fmt;
use std::str::FromStr;

use self::Protocol::*;

#[derive(Copy, Clone)]
pub enum Protocol {
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

impl From<Protocol> for u16 {
    fn from(p: Protocol) -> u16 {
        p as u16
    }
}

impl FromStr for Protocol {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
            _ => Err(()),
        }
    }
}

// Size of address in bits
pub enum Size {
    Fixed(u32),
    Variable,
}

impl Protocol {
    // bad duplication. not sure how to fix
    pub fn from_code(c: u16) -> Result<Protocol, ()> {
        match c {
            4   => Ok(IP4),
            6   => Ok(TCP),
            17  => Ok(UDP),
            33  => Ok(DCCP),
            41  => Ok(IP6),
            132 => Ok(SCTP),
            301 => Ok(UTP),
            302 => Ok(UDT),
            421 => Ok(IPFS),
            480 => Ok(HTTP),
            443 => Ok(HTTPS),
            444 => Ok(ONION),
            _ => Err(()),
        }
    }

    pub fn to_str(&self) -> &'static str {
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

    pub fn size(&self) -> Size {
        match *self {
            IP4 => Size::Fixed(4),
            TCP => Size::Fixed(2),
            UDP => Size::Fixed(2),
            DCCP => Size::Fixed(2),
            IP6 => Size::Fixed(16),
            SCTP => Size::Fixed(2),
            UTP => Size::Fixed(0),
            UDT => Size::Fixed(0),
            IPFS => Size::Variable,
            HTTP => Size::Fixed(0),
            HTTPS => Size::Fixed(0),
            ONION => Size::Fixed(10),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}
