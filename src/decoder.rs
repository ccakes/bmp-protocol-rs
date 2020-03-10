use crate::types::*;

use bgp_rs::{AFI, SAFI, AddPathDirection, Capabilities};
use bytes::{Buf, BytesMut};
use hashbrown::HashMap;
use tokio_util::codec::Decoder as DecoderTrait;

use std::io::{Error, ErrorKind};
use std::net::IpAddr;

// We need at least 5 bytes worth of the message in order to get the length
const BMP_HEADER_LEN: usize = 5;

#[derive(Clone, Debug)]
enum DecoderState {
    Head,
    Data(usize)
}

#[derive(Clone, Debug)]
pub struct Decoder {
    client_capabilities: HashMap<IpAddr, Capabilities>,
    state: DecoderState,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            client_capabilities: HashMap::new(),
            state: DecoderState::Head,
        }
    }

    fn decode_length(&mut self, src: &mut BytesMut) -> std::io::Result<Option<usize>> {
        if src.len() < BMP_HEADER_LEN {
            return Ok(None);
        }

        let version = src.get_u8();
        let length = src.get_u32() as usize;

        src.reserve(length);

        Ok(Some(length))
    }

    fn decode_data(&mut self, length: usize, src: &mut BytesMut) -> std::io::Result<Option<BmpMessage>> {
        // The BytesMut should already have the required capacity reserved so if we haven't read
        // the entire message yet, just keep on reading!
        if src.len() < length {
            return Ok(None);
        }

        // Now we take the message while leaving anything else in the buffer
        let mut buf = src.split_to(length);

        // ..and decode it, starting from the very beginning
        let version = src.get_u8();
        let length = src.get_u32();
        let kind: MessageKind = src.get_u8().into();

        // Now decode based on the MessageKind
        let juice = match kind {
            MessageKind::Initiation => {
                let mut tlv = vec![];
                while buf.remaining() > 0 {
                    let kind = buf.get_u16();

                    let info = match kind {
                        x if x <= 2 => InformationTlv::decode(kind, &mut buf)?,
                        _ => { break; }
                    };

                    tlv.push(info);
                }

                MessageData::Initiation(tlv)
            },
            MessageKind::PeerUp => {
                let peer_header = PeerHeader::decode(&mut buf)?;
                let message = PeerUp::decode(&peer_header.peer_flags, &mut buf)?;

                // Record the speaker capabilities, we'll use these later
                self.client_capabilities.entry(peer_header.peer_addr)
                    .or_insert_with(|| {
                        match (&message.sent_open, &message.recv_open) {
                            (Some(s), Some(r)) => {
                                let local_caps = Capabilities::from_parameters(&s.parameters);
                                let remote_caps = Capabilities::from_parameters(&r.parameters);

                                let mut caps = Capabilities::common(&local_caps, &remote_caps)
                                    .unwrap_or_else(|e| {
                                        tracing::warn!("Error parsing BGP OPENs (local: {} remote: {}): {}", message.local_addr, peer_header.peer_addr, e);
                                        Capabilities::default()
                                    });

                                // Use the BMP header val, not the negotiated val
                                if !peer_header.peer_flags.A { caps.FOUR_OCTET_ASN_SUPPORT = true; }
                                caps
                            },
                            _ => {
                                tracing::warn!("Missing BGP OPENs (local: {} remote: {}", message.local_addr, peer_header.peer_addr);

                                let mut caps = Capabilities::default();
                                if !peer_header.peer_flags.A { caps.FOUR_OCTET_ASN_SUPPORT = true; }

                                // test
                                if peer_header.peer_addr == IpAddr::V4("2.255.248.139".parse().unwrap()) {
                                    caps.ADD_PATH_SUPPORT.insert((AFI::IPV6, SAFI::Mpls), AddPathDirection::ReceivePaths);
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
                let peer_header = PeerHeader::decode(&mut buf)?;
                let capabilities = self.client_capabilities.get(&peer_header.peer_addr)
                    // .ok_or_else(|| format_err!("No capabilities found for neighbor {}", peer_header.peer_addr))?;
                    .ok_or_else(|| Error::new(ErrorKind::Other, format!("No capabilities found for neighbor {}", peer_header.peer_addr)))?;

                let header = bgp_rs::Header::parse(&mut buf)?;
                let update = bgp_rs::Update::parse(&header, &mut buf, &capabilities)?;
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

        Ok(Some(
            BmpMessage {
                version: version,
                kind: kind,

                // peer_header,
                message: juice
            }
        ))
    }
}