use tokio::io::AsyncRead;

use tokio_util::codec::{
    FramedRead,
    LengthDelimitedCodec
};

pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_offset(1)
        .length_field_length(4)
        .num_skip(0)
        .new_codec()
}

pub fn from_reader<R: AsyncRead>(r: R) -> FramedRead<R, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .length_field_offset(1)
        .length_field_length(4)
        .num_skip(0)
        .new_read(r)
}