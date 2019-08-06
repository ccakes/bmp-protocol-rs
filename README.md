# bmp-protocol

This crate implements a simple BMP packet decoder. It can decode BMP v3 packets and will use `bgp-rs`
to decode any BGP messages contained within the BMP data.

Right now the only state it contains is an assessment of the established BGP peering and the negotiated
capabilities. These are used by `bgp-rs` to decode certain message types.

## Usage

```toml
# Cargo.toml
bmp-protocol = { git = "https://github.com/ccakes/bmp-protocol-rs" }
```

```rust
use bmp_protocol::Decoder;

// Read a file created using bmp_play (https://github.com/paololucente/bmp_play)
// A more likely real-world use case would be reading from a TcpStream
let mut fh = fs::File::open(&entry.path()).unwrap();
let mut d = Decoder::new();

loop {
    let msg = d.decode(&mut fh);

    assert!(msg.is_ok());
}
```

## Contributing

Contributions are welcome, the library is currently incomplete and there are still BMP message types to
implement.