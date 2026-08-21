use std::error::Error;
use std::fmt;

/// Stable, machine-readable parse failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    PacketNoBody,
    PacketInvalid,
    SourceNoSeparator,
    SourceEmpty,
    SourceInvalid,
    DestinationEmpty,
    DestinationInvalid,
    PathTooLong,
    DigipeaterEmpty,
    DigipeaterInvalid,
    TypeNotSupported,
    PositionShort,
    PositionInvalid,
    PositionAmbiguity,
    SymbolTableInvalid,
    CompressedPositionShort,
    CompressedPositionInvalid,
    ObjectShort,
    ObjectInvalid,
    ItemShort,
    ItemInvalid,
    MessageShort,
    MessageInvalid,
    MessageNoDestination,
    MessageDestinationTooLong,
    MessageIdInvalid,
    MessageReplyAck,
    MessageAckReject,
    MessageNewline,
    PositionEncodeInvalid,
    NmeaShort,
    NmeaInvalid,
    NmeaNoFix,
    TelemetryInvalid,
    TelemetryTooLarge,
    WeatherInvalid,
    ExperimentalUnsupported,
    MicEShort,
    MicEDestinationInvalid,
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
    pub code: ErrorCode,
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
