/// Our error type
#[derive(Debug)]
pub enum Error {
    /// Error during decoding a BMP message
    DecodeError(String),
    /// std::io::Error
    WireError(std::io::Error),

    /// Any boxed error that implement std::error::Error
    Unknown(Box<dyn std::error::Error + Send + Sync>)
}

unsafe impl Send for Error {}
unsafe impl Sync for Error {}

impl Error {
    /// Helper to create a DecodeError instance
    pub fn decode(msg: &str) -> Self {
        Self::DecodeError(msg.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DecodeError(error) => write!(f, "Decoding error: {}", error),
            Self::WireError(error) => write!(f, "IO error: {}", error),

            Self::Unknown(error) => write!(f, "Unknown error: {}", error),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::WireError(error)
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        match err {
            Error::WireError(e) => e,
            Error::DecodeError(e) => Self::new(
                std::io::ErrorKind::Other,
                format!("{}", e).as_str()
            ),
            Error::Unknown(e) => Self::new(
                std::io::ErrorKind::Other,
                format!("{}", e).as_str()
            ),
        }
    }
}

// impl Into<std::io::Error> for Error {
//     fn into(self) -> std::io::Error {
//         match self {
//             Self::WireError(e) => e,
//             Self::DecodeError(e) => std::io::Error::new(
//                 std::io::ErrorKind::Other,
//                 format!("{}", e).as_str()
//             ),
//             Self::Unknown(e) => std::io::Error::new(
//                 std::io::ErrorKind::Other,
//                 format!("{}", e).as_str()
//             ),
//         }
//     }
// }

impl From<Box<dyn std::error::Error + Sync + Send>> for Error {
    fn from(error: Box<dyn std::error::Error + Sync + Send>) -> Self {
        Self::Unknown(error)
    }
}