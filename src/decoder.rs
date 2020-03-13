use crate::types::*;

use bgp_rs::Capabilities;
use bytes::{
    Buf,
    buf::BufExt,
    BytesMut
};
use hashbrown::HashMap;
use tokio_util::codec::Decoder;

use std::io::{Error, ErrorKind};
use std::net::IpAddr;

// We need at least 5 bytes worth of the message in order to get the length
const BMP_HEADER_LEN: usize = 5;

#[derive(Clone, Debug)]
enum DecoderState {
    Head,
    Data((u8, usize))
}

/// Decoder implementation for use with a FramedReader
#[derive(Clone, Debug)]
pub struct BmpDecoder {
    client_capabilities: HashMap<IpAddr, Capabilities>,
    state: DecoderState,
}

impl BmpDecoder {
    /// Create a new instance of the Decoder
    pub fn new() -> Self {
        Self {
            client_capabilities: HashMap::new(),
            state: DecoderState::Head,
        }
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> std::io::Result<Option<(u8, usize)>> {
        if src.len() < BMP_HEADER_LEN {
            return Ok(None);
        }

        let version = src.get_u8();
        let length = src.get_u32() as usize;
        let remaining = length - BMP_HEADER_LEN;

        src.reserve(remaining);

        Ok(Some((version, remaining)))
    }

    fn decode_data(&mut self, version: u8, length: usize, src: &mut BytesMut) -> std::io::Result<Option<BmpMessage>> {
        // The BytesMut should already have the required capacity reserved so if we haven't read
        // the entire message yet, just keep on reading!
        if src.len() < length {
            return Ok(None);
        }

        // Now we take the message while leaving anything else in the buffer
        let mut buf = src.split_to(length);

        // Now decode based on the MessageKind
        let kind: MessageKind = buf.get_u8().into();
        let message = match kind {
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

                let mut rdr = buf.reader();
                let header = bgp_rs::Header::parse(&mut rdr)?;
                let update = bgp_rs::Update::parse(&header, &mut rdr, &capabilities)?;
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

        Ok(
            Some(BmpMessage { version, kind, message })
        )
    }
}

impl Decoder for BmpDecoder {
    type Item = BmpMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> std::io::Result<Option<BmpMessage>> {
        let (version, length) = match self.state {
            DecoderState::Head => {
                match self.decode_head(src)? {
                    Some((ver, len)) => {
                        self.state = DecoderState::Data((ver, len));
                        (ver, len)
                    },
                    None => return Ok(None)
                }
            },
            DecoderState::Data((ver, len)) => (ver, len)
        };

        match self.decode_data(version, length, src)? {
            Some(message) => {
                self.state = DecoderState::Head;
                src.reserve(BMP_HEADER_LEN);

                Ok(Some(message))
            },
            None => Ok(None)
        }
    }
}