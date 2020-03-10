# bmp-protocol

This crate implements a simple BMP packet decoder. It can decode BMP v3 packets and will use `bgp-rs`
to decode any BGP messages contained within the BMP data.

We provide a `Decoder` ready to be used with a `tokio_util::codec::FramedRead` instance to provide decoded BMP messages to a consumer. See [`bmp-client`](https://github.com/ccakes/bmp-client-rs) for a working example of this.

## Usage

```toml
# Cargo.toml
bmp-protocol = { git = "https://github.com/ccakes/bmp-protocol-rs" }
```

```rust
use bmp_protocol::BmpDecoder;
use tokio::fs::File;
use tokio_util::codec::FramedRead;

// Read a file created using bmp_play (https://github.com/paololucente/bmp_play)
// A more likely real-world use case would be reading from a TcpStream
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let fh = File::open(&entry.path()).await?;
    let mut reader = FramedRead::new(fh, BmpDecoder::new());

    while let Some(message) = reader.next().await {
        assert!(message.is_ok());
    }
}
```

## Contributing

Contributions are welcome, the library is currently incomplete and there are still BMP message types to
implement.