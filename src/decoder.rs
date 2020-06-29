use crate::{
    Error,
    Result,
    types::*,
};

use bgp_rs::Capabilities;
use bytes::{
    Buf,
    buf::BufExt,
    BytesMut
};
use hashbrown::HashMap;
use tokio_util::codec::Decoder;

use std::convert::TryInto;
use std::net::IpAddr;

// We need at least 5 bytes worth of the message in order to get the length
const BMP_HEADER_LEN: usize = 5;

/// Work out the common set of capabilities on a peering session
fn common_capabilities(source: &Capabilities, other: &Capabilities) -> Capabilities {
    // And (manually) build an intersection between the two
    let mut negotiated = Capabilities::default();

    negotiated.MP_BGP_SUPPORT = source
        .MP_BGP_SUPPORT
        .intersection(&other.MP_BGP_SUPPORT)
        .copied()
        .collect();
    negotiated.ROUTE_REFRESH_SUPPORT = source.ROUTE_REFRESH_SUPPORT & other.ROUTE_REFRESH_SUPPORT;
    negotiated.OUTBOUND_ROUTE_FILTERING_SUPPORT = source
        .OUTBOUND_ROUTE_FILTERING_SUPPORT
        .intersection(&other.OUTBOUND_ROUTE_FILTERING_SUPPORT)
        .copied()
        .collect();

    // Attempt at a HashMap intersection. We can be a bit lax here because this isn't a real BGP implementation
    // so we can not care too much about the values for now.
    negotiated.EXTENDED_NEXT_HOP_ENCODING = source
        .EXTENDED_NEXT_HOP_ENCODING
        .iter()
        // .filter(|((afi, safi), _)| other.EXTENDED_NEXT_HOP_ENCODING.contains_key(&(*afi, *safi)))
        .map(|((afi, safi), nexthop)| ((*afi, *safi), *nexthop))
        .collect();

    negotiated.BGPSEC_SUPPORT = source.BGPSEC_SUPPORT & other.BGPSEC_SUPPORT;

    negotiated.MULTIPLE_LABELS_SUPPORT = source
        .MULTIPLE_LABELS_SUPPORT
        .iter()
        .filter(|((afi, safi), _)| other.MULTIPLE_LABELS_SUPPORT.contains_key(&(*afi, *safi)))
        .map(|((afi, safi), val)| ((*afi, *safi), *val))
        .collect();

    negotiated.GRACEFUL_RESTART_SUPPORT = source
        .GRACEFUL_RESTART_SUPPORT
        .intersection(&other.GRACEFUL_RESTART_SUPPORT)
        .copied()
        .collect();
    negotiated.FOUR_OCTET_ASN_SUPPORT =
        source.FOUR_OCTET_ASN_SUPPORT & other.FOUR_OCTET_ASN_SUPPORT;

    negotiated.ADD_PATH_SUPPORT = source
        .ADD_PATH_SUPPORT
        .iter()
        .filter(|((afi, safi), _)| other.ADD_PATH_SUPPORT.contains_key(&(*afi, *safi)))
        .map(|((afi, safi), val)| ((*afi, *safi), *val))
        .collect();
    negotiated.EXTENDED_PATH_NLRI_SUPPORT = !negotiated.ADD_PATH_SUPPORT.is_empty();

    negotiated.ENHANCED_ROUTE_REFRESH_SUPPORT =
        source.ENHANCED_ROUTE_REFRESH_SUPPORT & other.ENHANCED_ROUTE_REFRESH_SUPPORT;
    negotiated.LONG_LIVED_GRACEFUL_RESTART =
        source.LONG_LIVED_GRACEFUL_RESTART & other.LONG_LIVED_GRACEFUL_RESTART;

    negotiated
}

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

    fn decode_head(&mut self, src: &mut BytesMut) -> Result<Option<(u8, usize)>> {
        if src.len() < BMP_HEADER_LEN {
            return Ok(None);
        }

        let version = src.get_u8();
        let length = src.get_u32() as usize;
        let remaining = length - BMP_HEADER_LEN;

        src.reserve(remaining);
        tracing::trace!(buf_capacity = %src.capacity());

        Ok(Some((version, remaining)))
    }

    fn decode_data(&mut self, version: u8, length: usize, src: &mut BytesMut) -> Result<Option<BmpMessage>> {
        // The BytesMut should already have the required capacity reserved so if we haven't read
        // the entire message yet, just keep on reading!
        if src.len() < length {
            return Ok(None);
        }

        // Now we take the message while leaving anything else in the buffer
        let mut buf = src.split_to(length);

        // Now decode based on the MessageKind
        let kind: MessageKind = buf.get_u8().try_into()?;
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
                                let local_caps = Capabilities::from_parameters(s.parameters.clone());
                                let remote_caps = Capabilities::from_parameters(r.parameters.clone());

                                let mut caps = common_capabilities(&local_caps, &remote_caps);

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
                let peer_header = PeerHeader::decode(&mut buf)?;
                let message = PeerDown::decode(&mut buf)?;

                self.client_capabilities.remove(&peer_header.peer_addr);

                MessageData::PeerDown((peer_header, message))
            },
            MessageKind::RouteMonitoring => {
                let peer_header = PeerHeader::decode(&mut buf)?;
                let capabilities = self.client_capabilities.get(&peer_header.peer_addr)
                    // .ok_or_else(|| format_err!("No capabilities found for neighbor {}", peer_header.peer_addr))?;
                    .ok_or_else(|| Error::decode(&format!("No capabilities found for neighbor {}", peer_header.peer_addr)))?;

                let mut rdr = buf.reader();
                let header = bgp_rs::Header::parse(&mut rdr)?;
                let update = bgp_rs::Update::parse(&header, &mut rdr, &capabilities)?;

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