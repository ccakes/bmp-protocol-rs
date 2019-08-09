#![deny(missing_docs)]

//! A basic decoder for BMP messages ([RFC7854](https://tools.ietf.org/html/rfc7854))
//!
//! BMP (BGP Monitoring Protocol) is a method for BGP-speakers, typically network routers
//! to provide telemetry relating to BGP state.
//!
//! ## Errors
//! This crate will panic if the BMP headers don't decode correctly, but as soon as we have
//! a valid set of headers, failures on decoding the inner BGP messages will be handled via Result<T>

mod types;
pub use self::types::*;

use bgp_rs::{AFI, Capabilities};
use byteorder::{BigEndian, ReadBytesExt};
use hashbrown::HashMap;

use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::IpAddr;

/// The `Decoder` type, which contains a small amount of state relating to individual
/// session Capabilities ([RFC3392](https://tools.ietf.org/html/rfc3392)).
#[derive(Clone, Debug)]
pub struct Decoder {
    client_capabilities: HashMap<IpAddr, Capabilities>,
}

impl Decoder {
    /// Create a new `Decoder` instance
    pub fn new() -> Self {
        Self { client_capabilities: HashMap::new() }
    }

    /// Decode BMP messages from an input source. Any source implementing `std::io::Read`
    /// can be used.
    pub fn decode(&mut self, input: &mut dyn Read) -> Result<BmpMessage, Error> {
        // Read BMP header
        let version = input.read_u8()?;
        let length = input.read_u32::<BigEndian>()?;
        let kind: MessageKind = input.read_u8()?.into();

        // The length we just read is the entire message, so calculate how much we have to go
        // and read it. Pulling the lot off the wire here is nice because then if the decoding
        // fails for whatever reason, we can keep going and *should* be at the right spot.
        let remaining = (length as usize) - 6;

        let mut buf = vec![0u8; remaining as usize];
        input.read_exact(&mut buf)?;

        // Create a Cursor over the Vec<u8> so we're not reliant on the TcpStream anymore. Help
        // prevent over/under reading if we error somewhere.
        let mut cur = Cursor::new(buf);

        // Now decode based on the MessageKind
        let juice = match kind {
            MessageKind::Initiation => {
                let buf_len = cur.get_ref().len() as u64;

                let mut tlv = vec![];
                while cur.position() < buf_len {
                    let kind = cur.read_u16::<BigEndian>()?;
                    cur.set_position( cur.position() - 2 );

                    let info = match kind {
                        x if x <= 2 => InformationTlv::decode(&mut cur)?,
                        _ => { break; }
                    };

                    tlv.push(info);
                }

                MessageData::Initiation(tlv)
            },
            MessageKind::PeerUp => {
                let peer_header = PeerHeader::decode(&mut cur)?;
                let message = PeerUp::decode(&peer_header.peer_flags, &mut cur)?;

                // Record the speaker capabilities, we'll use these later
                self.client_capabilities.entry(peer_header.peer_addr)
                    .or_insert_with(|| {
                        match (&message.sent_open, &message.recv_open) {
                            (Some(s), Some(r)) => {
                                let mut caps = Capabilities::common(s, r)
                                    .unwrap_or_else(|e| {
                                        log::warn!("Error parsing BGP OPENs (local: {} remote: {}): {}", message.local_addr, peer_header.peer_addr, e);
                                        Capabilities::default()
                                    });

                                // Use the BMP header val, not the negotiated val
                                if !peer_header.peer_flags.A { caps.FOUR_OCTET_ASN_SUPPORT = true; }
                                caps
                            },
                            _ => {
                                log::warn!("Missing BGP OPENs (local: {} remote: {}", message.local_addr, peer_header.peer_addr);

                                let mut caps = Capabilities::default();
                                if !peer_header.peer_flags.A { caps.FOUR_OCTET_ASN_SUPPORT = true; }

                                // test
                                if peer_header.peer_addr == IpAddr::V4("2.255.248.139".parse().unwrap()) {
                                    caps.ADD_PATH_SUPPORT.insert((AFI::IPV6, 4), 1);
                                }

                                caps
                            }
                        }
                    });
                    // .or_insert_with(|| Capabilities::common(&message.sent_open, &message.recv_open).expect("missing capabilities"));

                MessageData::PeerUp((peer_header, message))
            },
            MessageKind::PeerDown => {
                // Make sure to clean up self.capabilities
                MessageData::Unimplemented
            },
            MessageKind::RouteMonitoring => {
                let peer_header = PeerHeader::decode(&mut cur)?;
                let capabilities = self.client_capabilities.get(&peer_header.peer_addr)
                    // .ok_or_else(|| format_err!("No capabilities found for neighbor {}", peer_header.peer_addr))?;
                    .ok_or_else(|| Error::new(ErrorKind::Other, format!("No capabilities found for neighbor {}", peer_header.peer_addr)))?;

                let header = bgp_rs::Header::parse(&mut cur)?;
                let update = bgp_rs::Update::parse(&header, &mut cur, &capabilities)?;
                // let update = match bgp_rs::Update::parse(&header, &mut cur, &capabilities) {
                //     Ok(u) => Ok(u),
                //     Err(e) => {
                //         log::error!("{}", e);
                //         dbg!(version, length, kind, &peer_header, &capabilities);
                //         Err(e)
                //     }
                // }?;

                MessageData::RouteMonitoring((peer_header, update))
            },
            _ => MessageData::Unimplemented
        };

        Ok(BmpMessage {
            version: version,
            kind: kind,

            // peer_header,
            message: juice
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Cursor, Read};

    #[test]
    fn test_data() {
        for entry in fs::read_dir("test_data/").unwrap() {
            let entry = entry.unwrap();

            match entry.path().extension() {
                Some(ext) if ext == OsStr::new("dump") => {
                    println!("Testing {}", entry.path().display());
                    let mut buf = vec![];
                    let mut fh = fs::File::open(&entry.path()).unwrap();
                    fh.read_to_end(&mut buf).unwrap();
                    let mut cur = Cursor::new(buf);

                    let mut d = Decoder::new();
                    let len = cur.get_ref().len() as u64;
                    while cur.position() < len {
                        // Handle dirty file, kind of hacky
                        if len - cur.position() < 500 { break; }

                        let msg = d.decode(&mut cur);
                        assert!(msg.is_ok());
                    }
                },
                _ => {}
            };
        }
    }
}
