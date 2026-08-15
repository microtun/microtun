#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `microtun-ini` is a borrowing, allocation-free Serde deserializer for the
//! small INI dialect used by WireGuard and similar configuration files.
//!
//! The document is represented as a map of section names. A section is a map
//! of property names. Repeated sections deserialize into a sequence, and a
//! sequence-valued property combines repeated properties with comma-separated
//! items. Section and property names are matched ASCII case-insensitively when
//! deserializing structs; values are left unchanged.
//!
//! ```
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize, PartialEq)]
//! struct Config<'a> {
//!     #[serde(rename = "Interface", borrow)]
//!     interface: Interface<'a>,
//! }
//!
//! #[derive(Debug, Deserialize, PartialEq)]
//! struct Interface<'a> {
//!     #[serde(rename = "PrivateKey")]
//!     private_key: &'a str,
//!     #[serde(rename = "ListenPort")]
//!     listen_port: u16,
//! }
//!
//! let value: Config<'_> = microtun_ini::from_str(
//!     "[Interface]\nPrivateKey = secret\nListenPort = 51820\n",
//! ).unwrap();
//! assert_eq!(value.interface.listen_port, 51820);
//! ```

mod de;
mod error;
mod parser;

pub use de::Deserializer;
pub use error::{Error, ErrorKind};
#[cfg(feature = "heapless")]
pub use heapless;

/// The synthetic section name used for properties before the first header.
///
/// Use `#[serde(rename = "$root")]` on the corresponding top-level field.
pub const ROOT_SECTION: &str = "$root";

/// Deserializes a complete INI document from a borrowed string.
///
/// The parser itself never allocates. With the default `alloc` feature,
/// allocation-backed Serde targets such as `String` and `Vec` are available.
/// Disable default features and enable `heapless` to remain fully `no_alloc`.
pub fn from_str<'de, T>(input: &'de str) -> Result<T, Error>
where
    T: serde::Deserialize<'de>,
{
    let mut deserializer = Deserializer::new(input)?;
    T::deserialize(&mut deserializer)
}
