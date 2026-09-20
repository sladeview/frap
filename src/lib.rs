//! A pure Rust parser and encoder for APRS packets.
//!
//! FRAP is a Rust port of [`Ham::APRS::FAP`](https://metacpan.org/pod/Ham::APRS::FAP).
//! It parses TNC2/APRS-IS packets from UTF-8 strings or raw byte slices without
//! native dependencies. The original bytes are retained even when a payload
//! contains text that is not valid UTF-8.
//!
//! # Parsing
//!
//! [`parse`] returns an owned [`Packet`]. Its [`Packet::body`] is a
//! [`PacketBody`] variant describing the concrete APRS information field.
//!
//! ```
//! use frap::{PacketBody, parse};
//!
//! let packet = parse("2W0FWJ>APRS:>FRAP example")?;
//! assert_eq!(packet.source, "2W0FWJ");
//! assert!(matches!(packet.body, PacketBody::Status { .. }));
//! # Ok::<(), frap::ParseError>(())
//! ```
//!
//! Use [`parse_ref`] on hot paths to borrow envelope fields from the input.
//! Call [`PacketRef::into_owned`] when the packet must outlive that input.
//! [`ParseOptions`] enables strict AX.25 validation and damaged Mic-E recovery.
//!
//! # Encoding and utilities
//!
//! The crate encodes messages, objects, positions, and timestamps. It also
//! provides KISS/TNC2 conversion, duplicate-detection helpers, geographic
//! calculations, callsign validation, and APRS-IS passcode calculation.
//!
//! # Optional APRS-IS client
//!
//! Enable the `aprs-is` feature to expose `AprsIsConnection`, an asynchronous
//! Tokio-based APRS-IS client. Parsing itself does not require an async runtime.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "aprs-is")]
mod aprsis;
mod encode;
mod error;
mod frame;
mod packet;
mod position;
mod timestamp;
mod utilities;

#[cfg(feature = "aprs-is")]
#[cfg_attr(docsrs, doc(cfg(feature = "aprs-is")))]
pub use aprsis::AprsIsConnection;
pub use encode::{
    EncodeObjectOptions, EncodePositionOptions, TimestampFormat, encode_message, encode_object,
    encode_position, encode_timestamp, make_object, make_position, make_timestamp,
};
pub use error::{ErrorCode, ParseError};
pub use frame::{aprs_duplicate_parts, count_digihops, kiss_to_tnc2, tnc2_to_kiss};
/// FAP-compatible name for [`mice_message`].
pub use packet::mice_message as mice_mbits_to_message;
pub use packet::{
    Digipeater, DigipeaterRef, Format, Message, Packet, PacketBody, PacketRef, PacketType,
    ParseOptions, PositionReport, Telemetry, Weather, aprs_passcode, check_ax25_call, mice_message,
    parse, parse_ref, parse_ref_with_options, parse_with_options,
};
pub use timestamp::AprsTimestamp;
pub use utilities::{direction, distance};
