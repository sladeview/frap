use std::error::Error;
use std::fmt;

/// Stable, machine-readable parse failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The packet header is present but the information field is empty.
    PacketNoBody,
    /// The packet does not satisfy the general TNC2/APRS structure.
    PacketInvalid,
    /// The source callsign is not followed by the `>` separator.
    SourceNoSeparator,
    /// The source callsign is empty.
    SourceEmpty,
    /// The source callsign contains invalid characters.
    SourceInvalid,
    /// The destination callsign is empty.
    DestinationEmpty,
    /// The destination does not satisfy the required AX.25 form.
    DestinationInvalid,
    /// A strict AX.25 path contains more than eight digipeaters.
    PathTooLong,
    /// A digipeater path component is empty.
    DigipeaterEmpty,
    /// A digipeater callsign contains invalid characters.
    DigipeaterInvalid,
    /// The APRS data-type identifier is unsupported.
    TypeNotSupported,
    /// An uncompressed position is too short.
    PositionShort,
    /// A position contains invalid coordinates or syntax.
    PositionInvalid,
    /// Position ambiguity is inconsistent or invalid.
    PositionAmbiguity,
    /// The APRS symbol-table identifier is invalid.
    SymbolTableInvalid,
    /// A compressed position is too short.
    CompressedPositionShort,
    /// A compressed position contains invalid base-91 data.
    CompressedPositionInvalid,
    /// An object report is too short.
    ObjectShort,
    /// An object report has invalid syntax.
    ObjectInvalid,
    /// An item report is too short.
    ItemShort,
    /// An item report has invalid syntax.
    ItemInvalid,
    /// A message is too short to contain an addressee and separator.
    MessageShort,
    /// A message has invalid syntax.
    MessageInvalid,
    /// A message being encoded has no destination.
    MessageNoDestination,
    /// A message destination exceeds the APRS nine-character limit.
    MessageDestinationTooLong,
    /// A message ID is empty, too long, or non-alphanumeric.
    MessageIdInvalid,
    /// A reply-ack cannot be represented in the available message-ID space.
    MessageReplyAck,
    /// Message acknowledgement and rejection fields conflict.
    MessageAckReject,
    /// A message contains a carriage return or line feed.
    MessageNewline,
    /// Position or object data cannot be encoded with the supplied values.
    PositionEncodeInvalid,
    /// An NMEA sentence is too short.
    NmeaShort,
    /// An NMEA sentence is malformed or has an invalid checksum.
    NmeaInvalid,
    /// An NMEA RMC sentence reports that no navigation fix is available.
    NmeaNoFix,
    /// A telemetry report is malformed.
    TelemetryInvalid,
    /// A telemetry value exceeds FAP's conventional range but was preserved.
    TelemetryTooLarge,
    /// A weather report is malformed.
    WeatherInvalid,
    /// An experimental APRS packet format is not supported.
    ExperimentalUnsupported,
    /// A Mic-E information field is too short.
    MicEShort,
    /// A Mic-E destination field cannot be decoded.
    MicEDestinationInvalid,
    /// A Mic-E information field cannot be decoded.
    MicEInformationInvalid,
}

impl ErrorCode {
    /// Compatibility-style string identifier, based on FAP error names.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PacketNoBody => "packet_no_body",
            Self::PacketInvalid => "packet_inv",
            Self::SourceNoSeparator => "srccall_nogt",
            Self::SourceEmpty => "srccall_empty",
            Self::SourceInvalid => "srccall_badchars",
            Self::DestinationEmpty => "dstcall_empty",
            Self::DestinationInvalid => "dstcall_noax25",
            Self::PathTooLong => "dstpath_toomany",
            Self::DigipeaterEmpty => "digi_empty",
            Self::DigipeaterInvalid => "digicall_badchars",
            Self::TypeNotSupported => "type_not_supported",
            Self::PositionShort => "pos_short",
            Self::PositionInvalid => "loc_inv",
            Self::PositionAmbiguity => "loc_amb_inv",
            Self::SymbolTableInvalid => "sym_inv_table",
            Self::CompressedPositionShort => "comp_short",
            Self::CompressedPositionInvalid => "comp_inv",
            Self::ObjectShort => "obj_short",
            Self::ObjectInvalid => "obj_inv",
            Self::ItemShort => "item_short",
            Self::ItemInvalid => "item_inv",
            Self::MessageShort => "msg_short",
            Self::MessageInvalid => "msg_inv",
            Self::MessageNoDestination => "msg_no_dst",
            Self::MessageDestinationTooLong => "msg_dst_long",
            Self::MessageIdInvalid => "msg_id_inv",
            Self::MessageReplyAck => "msg_replyack",
            Self::MessageAckReject => "msg_ack_rej",
            Self::MessageNewline => "msg_cr",
            Self::PositionEncodeInvalid => "pos_enc_inv",
            Self::NmeaShort => "nmea_short",
            Self::NmeaInvalid => "nmea_invalid",
            Self::NmeaNoFix => "gprmc_nofix",
            Self::TelemetryInvalid => "tlm_inv",
            Self::TelemetryTooLarge => "tlm_large",
            Self::WeatherInvalid => "wx_inv",
            Self::ExperimentalUnsupported => "exp_unsupp",
            Self::MicEShort => "mice_short",
            Self::MicEDestinationInvalid => "mice_inv_dstcall",
            Self::MicEInformationInvalid => "mice_inv_infofield",
        }
    }
}

/// A parse error with a stable code and a specific explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Stable category suitable for programmatic matching.
    pub code: ErrorCode,
    /// Human-readable detail about the specific failure.
    pub message: String,
}

impl ParseError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frap: {}: {}", self.code.as_str(), self.message)
    }
}

impl Error for ParseError {}
