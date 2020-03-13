use crate::{Error, Result};
use bytes::{
    Buf,
    buf::BufExt,
    BytesMut
};
use serde_derive::Serialize;

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// There are a few different types of BMP message, refer to RFC7xxx for details. This enum
/// encapsulates the different types
#[derive(Clone, Debug, Serialize)]
pub enum MessageData {
    /// Used to represent a message type I haven't implemented yet
    Unimplemented,
    /// Initiation message, this is sent once at the start of a BMP session to advertise speaker
    /// information
    Initiation(Vec<InformationTlv>),
    /// PeerUp messages are sent in bulk when a session is initially established, then over the life
    /// of the session as peers change status
    PeerUp((PeerHeader, PeerUp)),
    /// RouteMonitoring messages are state-compressed BGP messages
    RouteMonitoring((PeerHeader, bgp_rs::Update)),
}

/// BMP Message Types (RFC7854 Section 10.1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[repr(u8)]
pub enum MessageKind {
    /// Route Monitoring
    RouteMonitoring = 0,
    /// Statistics Report (unimplemented)
    StatisticsReport = 1,
    /// Peer Down (unimplemented)
    PeerDown = 2,
    /// Peer Up
    PeerUp = 3,
    /// Initiation
    Initiation = 4,
    /// Termination (unimplemented)
    Termination = 5,
    /// Route Mirroring (unimplemented)
    RouteMirroring = 6,

    // __Invalid
}

impl TryFrom<u8> for MessageKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(MessageKind::RouteMonitoring),
            1 => Ok(MessageKind::StatisticsReport),
            2 => Ok(MessageKind::PeerDown),
            3 => Ok(MessageKind::PeerUp),
            4 => Ok(MessageKind::Initiation),
            5 => Ok(MessageKind::Termination),
            6 => Ok(MessageKind::RouteMirroring),

            v @ _ => Err(
                Error::decode(&format!("invalid value for BMP Message Type: {}", v))
            ),
        }
    }
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageKind::RouteMonitoring => write!(f, "route_monitoring"),
            MessageKind::StatisticsReport => write!(f, "statistics_report"),
            MessageKind::PeerUp => write!(f, "peer_up"),
            MessageKind::PeerDown => write!(f, "peer_down"),
            MessageKind::Initiation => write!(f, "initiation"),
            MessageKind::Termination => write!(f, "termination"),
            MessageKind::RouteMirroring => write!(f, "route_mirroring"),
        }
    }
}

/// BMP Peer Types (RFC7854 Section 10.2)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[repr(u8)]
pub enum PeerType {
    /// Global Instance Peer
    GlobalInstance = 0,
    /// RD Instance Peer
    RdInstance = 1,
    /// Local Instance Peer
    LocalInstance = 2,
}

impl TryFrom<u8> for PeerType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(PeerType::GlobalInstance),
            1 => Ok(PeerType::RdInstance),
            2 => Ok(PeerType::LocalInstance),

            v @ _ => Err(
                Error::decode(&format!("invalid value for BMP Peer Type: {}", v))
            ),
        }
    }
}

impl fmt::Display for PeerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PeerType::GlobalInstance => write!(f, "global"),
            PeerType::RdInstance => write!(f, "rd"),
            PeerType::LocalInstance => write!(f, "local"),
        }
    }
}

/// BMP Peer Flags (RFC7854 Section 10.3)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[allow(non_snake_case)]
pub struct PeerFlags {
    /// Indicates whether the Peer address is an IPv6 addr
    pub V: bool,
    /// Indicates whether the message reflects post-policy
    pub L: bool,
    /// Indicates whether the message is using 2-byte AS_PATH format
    pub A: bool,
}

#[allow(non_snake_case)]
impl From<u8> for PeerFlags {
    fn from(value: u8) -> Self {
        let V = value & 0b10000000 == 0b10000000;
        let L = value & 0b01000000 == 0b01000000;
        let A = value & 0b00100000 == 0b00100000;

        Self { V, L, A}
    }
}

/// BMP Initiation Message TLVs (RFC7854 Section 10.5)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub enum InformationType {
    /// Generic String
    String,
    /// sysDescr
    SysDescr,
    /// sysName
    SysName,
}

impl TryFrom<u16> for InformationType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(InformationType::String),
            1 => Ok(InformationType::SysDescr),
            2 => Ok(InformationType::SysName),

            v @ _ => Err(
                Error::decode(&format!("invalid value for BMP Information Type: {}", v))
            ),
        }
    }
}

impl fmt::Display for InformationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InformationType::String => write!(f, "string"),
            InformationType::SysDescr => write!(f, "sys_descr"),
            InformationType::SysName => write!(f, "sys_name"),
        }
    }
}

/// Message contaner
#[derive(Clone, Debug, Serialize)]
pub struct BmpMessage {
    /// BMP version (should be 3)
    pub version: u8,
    /// Message type 
    pub kind: MessageKind,
    // pub peer_header: decoder::PeerHeader,

    /// Message data
    pub message: MessageData,
}

/// Per-Peer Header
///
/// The per-peer header follows the common header for most BMP messages.
/// The rest of the data in a BMP message is dependent on the MessageKind
/// field in the common header.
#[derive(Copy, Clone, Debug, Serialize)]
pub struct PeerHeader {
    /// Peer Type
    pub peer_type: PeerType,
    /// Peer Flags
    pub peer_flags: PeerFlags,
    /// Peer Distinguisher
    pub peer_distinguisher: (u32, u32),        // depends on PeerType, see RFC7854 for details
    /// Peer address (TCP address used in BGP session)
    pub peer_addr: IpAddr,
    /// Peer ASN
    pub peer_asn: u32,
    /// Peer BGP Router ID
    pub peer_bgp_id: Ipv4Addr,
    /// Timestamp (seconds since epoch)
    pub timestamp: u32,
    /// Optional milliseconds, to be added to `timestamp`
    pub timestamp_ms: u32,
}

impl PeerHeader {
    pub(super) fn decode(buf: &mut BytesMut) -> Result<Self> {
        let peer_type: PeerType = buf.get_u8().try_into()?;
        let peer_flags: PeerFlags = buf.get_u8().into();
        let peer_distinguisher = (buf.get_u32(), buf.get_u32());

        let peer_addr = match peer_flags.V {
            // IPv4
            false => {
                // Throw away 12 bytes
                buf.advance(12);
                IpAddr::V4( Ipv4Addr::from(buf.get_u32()) )
            },
            // IPv6
            true => {
                IpAddr::V6( Ipv6Addr::from(buf.get_u128()) )
            }
        };

        let peer_asn = match peer_flags.A {
            // 2 byte ASNs
            true => {
                // Throw away 2 bytes
                buf.advance(2);
                u32::from( buf.get_u16() )
            },
            // 4 byte ASNs
            false => buf.get_u32()
        };

        let peer_bgp_id = Ipv4Addr::from( buf.get_u32() );

        let timestamp = buf.get_u32();
        let timestamp_ms = buf.get_u32();

        Ok(Self {
            peer_type,
            peer_flags,
            peer_distinguisher,
            peer_addr,
            peer_asn,
            peer_bgp_id,
            timestamp,
            timestamp_ms,
        })
    }
}

/// Information TLV
///
/// The Information TLV is used by the Initiation and Peer Up messages.
#[derive(Clone, Debug, Serialize)]
pub struct InformationTlv {
    /// TLV message type
    pub information_type: InformationType,
    /// TLV message value 
    pub value: String,
}

impl InformationTlv {
    pub(super) fn decode(kind: u16, buf: &mut BytesMut) -> Result<Self> {
        let information_type = InformationType::try_from(kind)?;
        let len = buf.get_u16() as usize;

        let value = String::from_utf8((buf.bytes())[..len].to_vec()).unwrap();

        Ok(Self { information_type, value })
    }
}

/// Peer Up Notification
///
/// The Peer Up message is used to indicate that a peering session has
/// come up (i.e., has transitioned into the Established state).
#[derive(Clone, Debug, Serialize)]
pub struct PeerUp {
    /// Local IP address used in BGP TCP session
    pub local_addr: IpAddr,
    /// Local TCP port
    pub local_port: u16,
    /// Remote TCP port
    pub remote_port: u16,
    /// BGP OPEN message sent by the BMP speaker
    pub sent_open: Option<bgp_rs::Open>,
    /// BGP OPEN message received by the BMP speaker
    pub recv_open: Option<bgp_rs::Open>,
    /// Information TLVs
    pub information: Vec<InformationTlv>,
}

impl PeerUp {
    pub(super) fn decode(peer_flags: &PeerFlags, buf: &mut BytesMut) -> Result<Self> {
        let local_addr = match peer_flags.V {
            // IPv4
            false => {
                // Throw away 12 bytes
                buf.advance(12);
                IpAddr::V4( Ipv4Addr::from(buf.get_u32()) )
            },
            // IPv6
            true => {
                IpAddr::V6( Ipv6Addr::from(buf.get_u128()) )
            }
        };

        let local_port = buf.get_u16();
        let remote_port = buf.get_u16();

        // For at least some routers (ie adm-b1) the PeerUp messages are missing the
        // OPENs. Short-circuit here until I can figure out whats going on
        if buf.remaining() == 0 {
            return Ok(PeerUp {
                local_addr,
                local_port,
                remote_port,
                sent_open: None,
                recv_open: None,
                information: vec![]
            });
        }

        let mut rdr = buf.reader();

        let sent_hdr = bgp_rs::Header::parse(&mut rdr)?;
        assert!(sent_hdr.record_type == 1);
        let sent_open = Some(bgp_rs::Open::parse(&mut rdr)?);

        let recv_hdr = bgp_rs::Header::parse(&mut rdr)?;
        assert!(recv_hdr.record_type == 1);
        let recv_open = Some(bgp_rs::Open::parse(&mut rdr)?);

        let mut information = vec![];
        while buf.remaining() > 0 {
            let kind = buf.get_u16();
            information.push( InformationTlv::decode(kind, buf)? );
        }

        Ok(PeerUp {
            local_addr,
            local_port,
            remote_port,
            sent_open,
            recv_open,
            information
        })
    }
}
