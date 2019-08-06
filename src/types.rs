use byteorder::{BigEndian, ReadBytesExt};

use std::fmt;
use std::io::{Cursor, Error, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// There are a few different types of BMP message, refer to RFC7xxx for details. This enum
/// encapsulates the different types
#[derive(Clone, Debug)]
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
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

impl From<u8> for MessageKind {
    fn from(value: u8) -> Self {
        match value {
            0 => MessageKind::RouteMonitoring,
            1 => MessageKind::StatisticsReport,
            2 => MessageKind::PeerDown,
            3 => MessageKind::PeerUp,
            4 => MessageKind::Initiation,
            5 => MessageKind::Termination,
            6 => MessageKind::RouteMirroring,

            _ => panic!("invalid value for BMP Message Type"),
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PeerType {
    /// Global Instance Peer
    GlobalInstance = 0,
    /// RD Instance Peer
    RdInstance = 1,
    /// Local Instance Peer
    LocalInstance = 2,
}

impl From<u8> for PeerType {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerType::GlobalInstance,
            1 => PeerType::RdInstance,
            2 => PeerType::LocalInstance,

            _ => panic!("invalid value for BMP Peer Type"),
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum InformationType {
    /// Generic String
    String,
    /// sysDescr
    SysDescr,
    /// sysName
    SysName,
}

impl From<u16> for InformationType {
    fn from(value: u16) -> Self {
        match value {
            0 => InformationType::String,
            1 => InformationType::SysDescr,
            2 => InformationType::SysName,

            _ => panic!("invalid value for BMP Information Type"),
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
#[derive(Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
// #[derive(Clone, Debug)]
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
    pub(super) fn decode(cur: &mut Cursor<Vec<u8>>) -> Result<Self, Error> {
        let peer_type: PeerType = cur.read_u8()?.into();
        let peer_flags: PeerFlags = cur.read_u8()?.into();
        let peer_distinguisher = (cur.read_u32::<BigEndian>()?, cur.read_u32::<BigEndian>()?);

        let peer_addr = match peer_flags.V {
            // IPv4
            false => {
                // Throw away 12 bytes
                cur.read_exact(&mut [0u8; 12])?;
                IpAddr::V4( Ipv4Addr::from(cur.read_u32::<BigEndian>()?) )
            },
            // IPv6
            true => {
                IpAddr::V6( Ipv6Addr::from(cur.read_u128::<BigEndian>()?) )
            }
        };

        let peer_asn = match peer_flags.A {
            // 2 byte ASNs
            true => {
                // Throw away 2 bytes
                cur.read_exact(&mut [0u8; 2])?;
                u32::from( cur.read_u16::<BigEndian>()? )
            },
            // 4 byte ASNs
            false => cur.read_u32::<BigEndian>()?
        };

        let peer_bgp_id = Ipv4Addr::from( cur.read_u32::<BigEndian>()? );

        let timestamp = cur.read_u32::<BigEndian>()?;
        let timestamp_ms = cur.read_u32::<BigEndian>()?;

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
#[derive(Clone, Debug)]
pub struct InformationTlv {
    /// TLV message type
    pub information_type: InformationType,
    /// TLV message value 
    pub value: String,
}

impl InformationTlv {
    pub(super) fn decode(cur: &mut Cursor<Vec<u8>>) -> Result<Self, Error> {
        let information_type = InformationType::from( cur.read_u16::<BigEndian>()? );
        let len = cur.read_u16::<BigEndian>()?;

        let mut val_buf = vec![0u8; len as usize];
        cur.read_exact(&mut val_buf)?;
        let value = String::from_utf8(val_buf).unwrap();

        Ok(Self { information_type, value })
    }
}

/// Peer Up Notification
///
/// The Peer Up message is used to indicate that a peering session has
/// come up (i.e., has transitioned into the Established state).
#[derive(Clone, Debug)]
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
    pub(super) fn decode(peer_flags: &PeerFlags, cur: &mut Cursor<Vec<u8>>) -> Result<Self, Error> {
        let local_addr = match peer_flags.V {
            // IPv4
            false => {
                // Throw away 12 bytes
                cur.read_exact(&mut [0u8; 12])?;
                IpAddr::V4( Ipv4Addr::from(cur.read_u32::<BigEndian>()?) )
            },
            // IPv6
            true => {
                IpAddr::V6( Ipv6Addr::from(cur.read_u128::<BigEndian>()?) )
            }
        };

        let local_port = cur.read_u16::<BigEndian>()?;
        let remote_port = cur.read_u16::<BigEndian>()?;

        // For at least some routers (ie adm-b1) the PeerUp messages are missing the
        // OPENs. Short-circuit here until I can figure out whats going on
        if cur.position() == cur.get_ref().len() as u64 {
            return Ok(PeerUp {
                local_addr,
                local_port,
                remote_port,
                sent_open: None,
                recv_open: None,
                information: vec![]
            });
        }

        let sent_hdr = bgp_rs::Header::parse(cur)?;
        assert!(sent_hdr.record_type == 1);
        let sent_open = Some(bgp_rs::Open::parse(cur)?);

        let recv_hdr = bgp_rs::Header::parse(cur)?;
        assert!(recv_hdr.record_type == 1);
        let recv_open = Some(bgp_rs::Open::parse(cur)?);

        // Get the inner buffer length, then pull out TLVs until it's consumed
        let buf_len = cur.get_ref().len() as u64;

        let mut information = vec![];
        while cur.position() < buf_len {
            information.push( InformationTlv::decode(cur)? );
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
