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

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::{
        fs::File,
        stream::StreamExt,
    };
    use tokio_util::codec::FramedRead;

    use std::ffi::OsStr;
    use std::fs;

    #[tokio::test]
    async fn test_data() {
        for entry in fs::read_dir("test_data/").unwrap() {
            let entry = entry.unwrap();

            match entry.path().extension() {
                Some(ext) if ext == OsStr::new("dump") => {
                    println!("Testing {}", entry.path().display());
                    let fh = File::open(&entry.path()).await.unwrap();
                    let mut rdr = FramedRead::new(fh, BmpDecoder::new());

                    while let Some(msg) = rdr.next().await {
                        match msg {
                            Ok(_) => {},
                            Err(err) => panic!("Error: {}", err)
                        };
                    }
                },
                _ => {}
            };
        }
    }
}