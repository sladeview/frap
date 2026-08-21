//! A pure Rust APRS packet parser inspired by Ham::APRS::FAP.
//!
//! `frap` parses TNC2/APRS-IS text packets without native dependencies.

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
