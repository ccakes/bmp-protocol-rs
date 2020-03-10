#![deny(missing_docs)]

//! A basic decoder for BMP messages ([RFC7854](https://tools.ietf.org/html/rfc7854))
//!
//! BMP (BGP Monitoring Protocol) is a method for BGP-speakers, typically network routers
//! to provide telemetry relating to BGP state.
//!
//! ## Errors
//! This crate will panic if the BMP headers don't decode correctly, but as soon as we have
//! a valid set of headers, failures on decoding the inner BGP messages will be handled via Result<T>

mod decoder;
pub use decoder::BmpDecoder;
/// Some docs ay
pub mod types;
