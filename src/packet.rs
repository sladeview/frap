use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::{ErrorCode, ParseError};
use crate::position::{parse_compressed, parse_uncompressed};
use crate::timestamp::{AprsTimestamp, parse_timestamp};

const NON_ASCII_BYTE: char = '\u{7f}';
const EXCLUDED_FF_BYTE: char = '\u{1f}';

/// Length-preserving byte view used by the parser. Non-ASCII bytes become
/// reserved, non-APRS bytes that cannot be mistaken for protocol punctuation;
/// their final public rendering is handled in one place after parsing.
struct ParserView<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> ParserView<'a> {
    fn from_bytes(raw: &'a [u8]) -> Self {
        let bytes = if raw.is_ascii() {
            Cow::Borrowed(raw)
        } else {
            Cow::Owned(
                raw.iter()
                    .map(|byte| match *byte {
                        byte if byte.is_ascii() => byte,
                        0xff => EXCLUDED_FF_BYTE as u8,
                        _ => NON_ASCII_BYTE as u8,
                    })
                    .collect(),
            )
        };
        Self { bytes }
    }

    fn into_text(self) -> Cow<'a, str> {
        match self.bytes {
            Cow::Borrowed(bytes) => {
                Cow::Borrowed(std::str::from_utf8(bytes).expect("parser view is ASCII"))
            }
            Cow::Owned(bytes) => {
                Cow::Owned(String::from_utf8(bytes).expect("parser view is ASCII"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketType {
    Location,
    Object,
    Item,
    Message,
    TelemetryMessage,
    Status,
    Capabilities,
    Beacon,
    Weather,
    Telemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    Uncompressed,
    Compressed,
    MicE,
    Nmea,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digipeater {
    pub call: String,
    pub was_digipeated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigipeaterRef<'a> {
    pub call: Cow<'a, str>,
    pub was_digipeated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub destination: String,
    pub text: String,
    pub id: Option<String>,
    pub acknowledgement_id: Option<String>,
    pub rejection_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Telemetry {
    /// Sequence number for `T#` and inline base-91 telemetry. Legacy Mic-E
    /// hexadecimal telemetry does not carry one.
    pub sequence: Option<i32>,
    pub values: [Option<f64>; 5],
    pub bits: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Weather {
    pub wind_direction_deg: Option<f64>,
    pub wind_speed_ms: Option<f64>,
    pub wind_gust_ms: Option<f64>,
    pub temperature_c: Option<f64>,
    pub indoor_temperature_c: Option<f64>,
    pub humidity_percent: Option<u8>,
    pub indoor_humidity_percent: Option<u8>,
    pub pressure_mbar: Option<f64>,
    pub rain_1h_mm: Option<f64>,
    pub rain_24h_mm: Option<f64>,
    pub rain_since_midnight_mm: Option<f64>,
    pub snow_24h_mm: Option<f64>,
    pub luminosity_wm2: Option<u16>,
    pub water_level_m: Option<f64>,
    pub radiation_nsvh: Option<f64>,
    pub battery_voltage: Option<f64>,
    pub software: Option<String>,
}

/// Position-related data shared by locations, objects, and items.
#[derive(Debug, Clone, PartialEq)]
pub struct PositionReport {
    pub format: Option<Format>,
    pub latitude: f64,
    pub longitude: f64,
    pub ambiguity: Option<u8>,
    pub resolution_m: Option<f64>,
    pub symbol_table: Option<char>,
    pub symbol_code: Option<char>,
    pub speed_kmh: Option<f64>,
    pub course_deg: Option<u16>,
    pub altitude_m: Option<f64>,
    pub radio_range_km: Option<f64>,
    pub raw_timestamp: Option<String>,
    pub timestamp: Option<AprsTimestamp>,
    pub nmea_checksum_ok: Option<bool>,
    pub dao_datum: Option<char>,
    pub phg: Option<String>,
    pub mice_message_bits: Option<String>,
    pub mice_mangled: bool,
    pub weather: Option<Weather>,
    pub telemetry: Option<Telemetry>,
    pub comment: Option<String>,
}

/// Parsed APRS information field, represented by its concrete wire type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PacketBody {
    Location {
        position: Box<PositionReport>,
        messaging: bool,
    },
    Object {
        name: String,
        alive: bool,
        position: Box<PositionReport>,
    },
    Item {
        name: String,
        alive: bool,
        position: Box<PositionReport>,
    },
    Message(Message),
    TelemetryMessage(Message),
    Status {
        text: String,
        raw_timestamp: Option<String>,
        timestamp: Option<AprsTimestamp>,
    },
    Capabilities(BTreeMap<String, String>),
    Beacon {
        data: String,
    },
    Weather {
        weather: Box<Weather>,
        position: Option<Box<PositionReport>>,
        messaging: Option<bool>,
        telemetry: Option<Telemetry>,
        comment: Option<String>,
    },
    Telemetry(Telemetry),
}

/// Fully owned parsed APRS packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub original_bytes: Vec<u8>,
    pub original: String,
    pub header: String,
    pub information: String,
    pub source: String,
    pub destination: String,
    pub digipeaters: Vec<Digipeater>,
    pub body: PacketBody,
    pub warnings: Vec<ParseError>,
}

/// Parsed APRS packet borrowing envelope fields from its input where possible.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRef<'a> {
    pub original_bytes: &'a [u8],
    pub original: Cow<'a, str>,
    pub header: Cow<'a, str>,
    pub information: Cow<'a, str>,
    pub source: Cow<'a, str>,
    pub destination: Cow<'a, str>,
    pub digipeaters: Vec<DigipeaterRef<'a>>,
    pub body: PacketBody,
    pub warnings: Vec<ParseError>,
}

/// Private flat state used while the individual APRS syntaxes are decoded.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ParseState<'a> {
    original_bytes: &'a [u8],
    original: Cow<'a, str>,
    header: Cow<'a, str>,
    body: Cow<'a, str>,
    source: Cow<'a, str>,
    destination: Cow<'a, str>,
    digipeaters: Vec<DigipeaterRef<'a>>,
    pub packet_type: Option<PacketType>,
    pub format: Option<Format>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub position_ambiguity: Option<u8>,
    pub position_resolution_m: Option<f64>,
    pub symbol_table: Option<char>,
    pub symbol_code: Option<char>,
    pub speed_kmh: Option<f64>,
    pub course_deg: Option<u16>,
    pub altitude_m: Option<f64>,
    pub messaging: Option<bool>,
    pub radio_range_km: Option<f64>,
    pub raw_timestamp: Option<String>,
    pub timestamp: Option<AprsTimestamp>,
    pub object_name: Option<String>,
    pub item_name: Option<String>,
    pub alive: Option<bool>,
    pub message: Option<Message>,
    pub status: Option<String>,
    pub capabilities: BTreeMap<String, String>,
    pub telemetry: Option<Telemetry>,
    pub weather: Option<Weather>,
    pub nmea_checksum_ok: Option<bool>,
    pub dao_datum: Option<char>,
    pub phg: Option<String>,
    pub mice_message_bits: Option<String>,
    pub mice_mangled: bool,
    pub comment: Option<String>,
    warnings: Vec<ParseError>,
}

impl PacketRef<'_> {
    pub fn into_owned(self) -> Packet {
        Packet {
            original_bytes: self.original_bytes.to_vec(),
            original: self.original.into_owned(),
            header: self.header.into_owned(),
            information: self.information.into_owned(),
            source: self.source.into_owned(),
            destination: self.destination.into_owned(),
            digipeaters: self
                .digipeaters
                .into_iter()
                .map(|digipeater| Digipeater {
                    call: digipeater.call.into_owned(),
                    was_digipeated: digipeater.was_digipeated,
                })
                .collect(),
            body: self.body,
            warnings: self.warnings,
        }
    }
}

impl<'a> ParseState<'a> {
    fn take_position(&mut self) -> PositionReport {
        PositionReport {
            format: self.format,
            latitude: self.latitude.expect("successful position has latitude"),
            longitude: self.longitude.expect("successful position has longitude"),
            ambiguity: self.position_ambiguity,
            resolution_m: self.position_resolution_m,
            symbol_table: self.symbol_table,
            symbol_code: self.symbol_code,
            speed_kmh: self.speed_kmh,
            course_deg: self.course_deg,
            altitude_m: self.altitude_m,
            radio_range_km: self.radio_range_km,
            raw_timestamp: self.raw_timestamp.take(),
            timestamp: self.timestamp,
            nmea_checksum_ok: self.nmea_checksum_ok,
            dao_datum: self.dao_datum,
            phg: self.phg.take(),
            mice_message_bits: self.mice_message_bits.take(),
            mice_mangled: self.mice_mangled,
            weather: self.weather.take(),
            telemetry: self.telemetry.take(),
            comment: self.comment.take(),
        }
    }

    fn into_packet_ref(mut self) -> PacketRef<'a> {
        let packet_type = self.packet_type.expect("successful parse has packet type");
        let body = match packet_type {
            PacketType::Location => PacketBody::Location {
                messaging: self.messaging.unwrap_or(false),
                position: Box::new(self.take_position()),
            },
            PacketType::Object => PacketBody::Object {
                name: self.object_name.take().expect("object has a name"),
                alive: self.alive.expect("object has an alive state"),
                position: Box::new(self.take_position()),
            },
            PacketType::Item => PacketBody::Item {
                name: self.item_name.take().expect("item has a name"),
                alive: self.alive.expect("item has an alive state"),
                position: Box::new(self.take_position()),
            },
            PacketType::Message => {
                PacketBody::Message(self.message.take().expect("message has content"))
            }
            PacketType::TelemetryMessage => PacketBody::TelemetryMessage(
                self.message.take().expect("telemetry message has content"),
            ),
            PacketType::Status => PacketBody::Status {
                text: self.status.take().expect("status has text"),
                raw_timestamp: self.raw_timestamp.take(),
                timestamp: self.timestamp,
            },
            PacketType::Capabilities => {
                PacketBody::Capabilities(std::mem::take(&mut self.capabilities))
            }
            PacketType::Beacon => PacketBody::Beacon {
                data: self.body.to_string(),
            },
            PacketType::Weather => PacketBody::Weather {
                weather: Box::new(self.weather.take().expect("weather packet has weather")),
                position: if self.latitude.is_some() {
                    Some(Box::new(self.take_position()))
                } else {
                    None
                },
                messaging: self.messaging,
                telemetry: self.telemetry.take(),
                comment: self.comment.take(),
            },
            PacketType::Telemetry => {
                PacketBody::Telemetry(self.telemetry.take().expect("telemetry packet has data"))
            }
        };

        PacketRef {
            original_bytes: self.original_bytes,
            original: self.original,
            header: self.header,
            information: self.body,
            source: self.source,
            destination: self.destination,
            digipeaters: self.digipeaters,
            body,
            warnings: self.warnings,
        }
    }
}

macro_rules! packet_accessors {
    () => {
        pub const fn packet_type(&self) -> Option<PacketType> {
            Some(match &self.body {
                PacketBody::Location { .. } => PacketType::Location,
                PacketBody::Object { .. } => PacketType::Object,
                PacketBody::Item { .. } => PacketType::Item,
                PacketBody::Message(_) => PacketType::Message,
                PacketBody::TelemetryMessage(_) => PacketType::TelemetryMessage,
                PacketBody::Status { .. } => PacketType::Status,
                PacketBody::Capabilities(_) => PacketType::Capabilities,
                PacketBody::Beacon { .. } => PacketType::Beacon,
                PacketBody::Weather { .. } => PacketType::Weather,
                PacketBody::Telemetry(_) => PacketType::Telemetry,
            })
        }

        pub const fn packet_body(&self) -> &PacketBody {
            &self.body
        }

        pub fn position(&self) -> Option<&PositionReport> {
            match &self.body {
                PacketBody::Location { position, .. }
                | PacketBody::Object { position, .. }
                | PacketBody::Item { position, .. } => Some(position),
                PacketBody::Weather { position, .. } => position.as_deref(),
                _ => None,
            }
        }

        pub fn message(&self) -> Option<&Message> {
            match &self.body {
                PacketBody::Message(message) | PacketBody::TelemetryMessage(message) => {
                    Some(message)
                }
                _ => None,
            }
        }

        pub fn weather(&self) -> Option<&Weather> {
            match &self.body {
                PacketBody::Weather { weather, .. } => Some(weather),
                _ => self
                    .position()
                    .and_then(|position| position.weather.as_ref()),
            }
        }

        pub fn telemetry(&self) -> Option<&Telemetry> {
            match &self.body {
                PacketBody::Telemetry(telemetry) => Some(telemetry),
                PacketBody::Weather {
                    telemetry,
                    position,
                    ..
                } => telemetry.as_ref().or_else(|| {
                    position
                        .as_ref()
                        .and_then(|position| position.telemetry.as_ref())
                }),
                _ => self
                    .position()
                    .and_then(|position| position.telemetry.as_ref()),
            }
        }

        pub fn comment(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Weather {
                    comment, position, ..
                } => comment.as_deref().or_else(|| {
                    position
                        .as_ref()
                        .and_then(|position| position.comment.as_deref())
                }),
                _ => self
                    .position()
                    .and_then(|position| position.comment.as_deref()),
            }
        }

        pub fn format(&self) -> Option<Format> {
            self.position().and_then(|p| p.format)
        }
        pub fn latitude(&self) -> Option<f64> {
            self.position().map(|p| p.latitude)
        }
        pub fn longitude(&self) -> Option<f64> {
            self.position().map(|p| p.longitude)
        }
        pub fn position_ambiguity(&self) -> Option<u8> {
            self.position().and_then(|p| p.ambiguity)
        }
        pub fn position_resolution_m(&self) -> Option<f64> {
            self.position().and_then(|p| p.resolution_m)
        }
        pub fn symbol_table(&self) -> Option<char> {
            self.position().and_then(|p| p.symbol_table)
        }
        pub fn symbol_code(&self) -> Option<char> {
            self.position().and_then(|p| p.symbol_code)
        }
        pub fn speed_kmh(&self) -> Option<f64> {
            self.position().and_then(|p| p.speed_kmh)
        }
        pub fn course_deg(&self) -> Option<u16> {
            self.position().and_then(|p| p.course_deg)
        }
        pub fn altitude_m(&self) -> Option<f64> {
            self.position().and_then(|p| p.altitude_m)
        }
        pub fn radio_range_km(&self) -> Option<f64> {
            self.position().and_then(|p| p.radio_range_km)
        }
        pub fn nmea_checksum_ok(&self) -> Option<bool> {
            self.position().and_then(|p| p.nmea_checksum_ok)
        }
        pub fn dao_datum(&self) -> Option<char> {
            self.position().and_then(|p| p.dao_datum)
        }
        pub fn phg(&self) -> Option<&str> {
            self.position().and_then(|p| p.phg.as_deref())
        }
        pub fn mice_message_bits(&self) -> Option<&str> {
            self.position().and_then(|p| p.mice_message_bits.as_deref())
        }
        pub fn mice_mangled(&self) -> bool {
            self.position().is_some_and(|p| p.mice_mangled)
        }
        pub fn messaging(&self) -> Option<bool> {
            match &self.body {
                PacketBody::Location { messaging, .. } => Some(*messaging),
                PacketBody::Weather { messaging, .. } => *messaging,
                _ => None,
            }
        }
        pub fn raw_timestamp(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Status { raw_timestamp, .. } => raw_timestamp.as_deref(),
                _ => self.position().and_then(|p| p.raw_timestamp.as_deref()),
            }
        }
        pub fn timestamp(&self) -> Option<AprsTimestamp> {
            match &self.body {
                PacketBody::Status { timestamp, .. } => *timestamp,
                _ => self.position().and_then(|p| p.timestamp),
            }
        }
        pub fn object_name(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Object { name, .. } => Some(name),
                _ => None,
            }
        }
        pub fn item_name(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Item { name, .. } => Some(name),
                _ => None,
            }
        }
        pub fn alive(&self) -> Option<bool> {
            match &self.body {
                PacketBody::Object { alive, .. } | PacketBody::Item { alive, .. } => Some(*alive),
                _ => None,
            }
        }
        pub fn status(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Status { text, .. } => Some(text),
                _ => None,
            }
        }
        pub fn capabilities(&self) -> Option<&BTreeMap<String, String>> {
            match &self.body {
                PacketBody::Capabilities(values) => Some(values),
                _ => None,
            }
        }
    };
}

impl Packet {
    packet_accessors!();
}

impl PacketRef<'_> {
    packet_accessors!();
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// Enforce the eight-digipeater AX.25 path limit and AX.25 callsigns
    /// throughout the path.
    pub strict_ax25: bool,
    /// Repair the common Mic-E corruption where collapsed spaces remove a
    /// speed/course byte.
    pub accept_broken_mice: bool,
}

pub fn parse(raw: impl AsRef<[u8]>) -> Result<Packet, ParseError> {
    parse_with_options(raw, ParseOptions::default())
}

pub fn parse_with_options(
    raw: impl AsRef<[u8]>,
    options: ParseOptions,
) -> Result<Packet, ParseError> {
    parse_ref_with_options(raw.as_ref(), options).map(PacketRef::into_owned)
}

/// Parse a packet while borrowing input-backed fields whenever possible.
pub fn parse_ref(raw: &[u8]) -> Result<PacketRef<'_>, ParseError> {
    parse_ref_with_options(raw, ParseOptions::default())
}

/// Parse a borrowed packet with explicit parser options.
pub fn parse_ref_with_options(
    raw: &[u8],
    options: ParseOptions,
) -> Result<PacketRef<'_>, ParseError> {
    let parser_view = ParserView::from_bytes(raw).into_text();
    let (header, body, source, destination, digipeaters) = match parser_view {
        Cow::Borrowed(view) => {
            let (header, body) = split_packet(view)?;
            let fields = parse_header_fields(header, options)?;
            (
                Cow::Borrowed(header),
                Cow::Borrowed(body),
                fields.source,
                fields.destination,
                fields.digipeaters,
            )
        }
        Cow::Owned(view) => {
            let (header, body) = split_packet(&view)?;
            let fields = parse_header_fields(header, options)?;
            let source = Cow::Owned(fields.source.into_owned());
            let destination = Cow::Owned(fields.destination.into_owned());
            let digipeaters = fields
                .digipeaters
                .into_iter()
                .map(|digipeater| DigipeaterRef {
                    call: Cow::Owned(digipeater.call.into_owned()),
                    was_digipeated: digipeater.was_digipeated,
                })
                .collect();
            (
                Cow::Owned(header.to_owned()),
                Cow::Owned(body.to_owned()),
                source,
                destination,
                digipeaters,
            )
        }
    };
    let original = if raw.is_ascii() {
        Cow::Borrowed(std::str::from_utf8(raw).expect("ASCII is valid UTF-8"))
    } else {
        Cow::Owned(String::from_utf8_lossy(raw).into_owned())
    };
    let mut packet = ParseState {
        original_bytes: raw,
        original,
        header,
        body,
        source,
        destination,
        digipeaters,
        ..ParseState::default()
    };
    parse_body(&mut packet, options)?;
    sanitize_parser_placeholders(&mut packet);
    Ok(packet.into_packet_ref())
}

fn split_packet(view: &str) -> Result<(&str, &str), ParseError> {
    let (header, body) = view
        .split_once(':')
        .ok_or_else(|| ParseError::new(ErrorCode::PacketNoBody, "no packet body after header"))?;
    if body.is_empty() {
        return Err(ParseError::new(
            ErrorCode::PacketNoBody,
            "packet body is empty",
        ));
    }
    Ok((header, body))
}

struct HeaderFields<'a> {
    source: Cow<'a, str>,
    destination: Cow<'a, str>,
    digipeaters: Vec<DigipeaterRef<'a>>,
}

fn sanitize_parser_placeholders(packet: &mut ParseState<'_>) {
    fn sanitize(value: &mut String) {
        if value.contains([NON_ASCII_BYTE, EXCLUDED_FF_BYTE]) {
            *value = value.replace([NON_ASCII_BYTE, EXCLUDED_FF_BYTE], "?");
        }
    }
    fn sanitize_option(value: &mut Option<String>) {
        if let Some(value) = value {
            sanitize(value);
        }
    }

    fn sanitize_cow(value: &mut Cow<'_, str>) {
        if value.contains([NON_ASCII_BYTE, EXCLUDED_FF_BYTE]) {
            *value = Cow::Owned(value.replace([NON_ASCII_BYTE, EXCLUDED_FF_BYTE], "?"));
        }
    }

    sanitize_cow(&mut packet.header);
    sanitize_cow(&mut packet.body);
    sanitize_cow(&mut packet.source);
    sanitize_cow(&mut packet.destination);
    for digipeater in &mut packet.digipeaters {
        sanitize_cow(&mut digipeater.call);
    }
    sanitize_option(&mut packet.raw_timestamp);
    sanitize_option(&mut packet.object_name);
    sanitize_option(&mut packet.item_name);
    sanitize_option(&mut packet.status);
    sanitize_option(&mut packet.phg);
    sanitize_option(&mut packet.mice_message_bits);
    if let Some(comment) = &mut packet.comment {
        // Match FAP: 0xff is excluded from comments, other non-ASCII bytes are
        // exposed as `?`, and ordinary ASCII controls are removed.
        comment.retain(|character| {
            character != EXCLUDED_FF_BYTE
                && (character == NON_ASCII_BYTE || !character.is_ascii_control())
        });
        sanitize(comment);
    }
    if let Some(message) = &mut packet.message {
        sanitize(&mut message.destination);
        sanitize(&mut message.text);
        sanitize_option(&mut message.id);
        sanitize_option(&mut message.acknowledgement_id);
        sanitize_option(&mut message.rejection_id);
    }
    if let Some(telemetry) = &mut packet.telemetry {
        sanitize_option(&mut telemetry.bits);
    }
    if let Some(weather) = &mut packet.weather {
        sanitize_option(&mut weather.software);
    }
    packet.capabilities = std::mem::take(&mut packet.capabilities)
        .into_iter()
        .map(|(mut name, mut value)| {
            sanitize(&mut name);
            sanitize(&mut value);
            (name, value)
        })
        .collect();
    for warning in &mut packet.warnings {
        sanitize(&mut warning.message);
    }
}

fn parse_header_fields(
    header: &str,
    options: ParseOptions,
) -> Result<HeaderFields<'_>, ParseError> {
    let (source, rest) = header
        .split_once('>')
        .ok_or_else(|| ParseError::new(ErrorCode::SourceNoSeparator, "no '>' in packet header"))?;
    if source.is_empty() {
        return Err(ParseError::new(ErrorCode::SourceEmpty, "source is empty"));
    }
    let source = if options.strict_ax25 {
        check_ax25_call_ref(source)
            .ok_or_else(|| ParseError::new(ErrorCode::SourceInvalid, "invalid AX.25 source"))?
    } else if source.bytes().all(valid_loose_call_byte) {
        Cow::Borrowed(source)
    } else {
        return Err(ParseError::new(
            ErrorCode::SourceInvalid,
            "source contains invalid characters",
        ));
    };

    let mut path = rest.split(',');
    let destination = path.next().unwrap_or_default();
    if destination.is_empty() {
        return Err(ParseError::new(
            ErrorCode::DestinationEmpty,
            "destination is empty",
        ));
    }
    let destination = check_ax25_call_ref(destination).ok_or_else(|| {
        ParseError::new(
            ErrorCode::DestinationInvalid,
            "destination is not a valid AX.25 callsign",
        )
    })?;

    let path: Vec<_> = path.collect();
    if options.strict_ax25 && path.len() > 8 {
        return Err(ParseError::new(
            ErrorCode::PathTooLong,
            "AX.25 paths can contain at most eight digipeaters",
        ));
    }
    let mut digipeaters = Vec::with_capacity(path.len());
    for raw_digi in path {
        let (call, used) = raw_digi
            .strip_suffix('*')
            .map_or((raw_digi, false), |call| (call, true));
        if call.is_empty() {
            return Err(ParseError::new(
                ErrorCode::DigipeaterEmpty,
                "empty digipeater",
            ));
        }
        let valid = if options.strict_ax25 {
            check_ax25_call_ref(call)
        } else if call.bytes().all(valid_path_byte) {
            Some(Cow::Borrowed(call))
        } else {
            None
        };
        digipeaters.push(DigipeaterRef {
            call: valid.ok_or_else(|| {
                ParseError::new(ErrorCode::DigipeaterInvalid, "invalid digipeater")
            })?,
            was_digipeated: used,
        });
    }
    Ok(HeaderFields {
        source,
        destination,
        digipeaters,
    })
}

fn parse_body(packet: &mut ParseState<'_>, options: ParseOptions) -> Result<(), ParseError> {
    let body = std::mem::take(&mut packet.body);
    let result = parse_body_inner(packet, options, &body);
    packet.body = body;
    result
}

fn parse_body_inner(
    packet: &mut ParseState<'_>,
    options: ParseOptions,
    body: &str,
) -> Result<(), ParseError> {
    let identifier = body.as_bytes()[0];
    match identifier {
        b'!' | b'=' => {
            if let Some(ultw) = body.strip_prefix("!!") {
                packet.messaging = Some(false);
                return parse_ultw(packet, ultw, true);
            }
            packet.packet_type = Some(PacketType::Location);
            packet.messaging = Some(identifier == b'=');
            parse_position(packet, &body[1..])
        }
        b'/' | b'@' => {
            if body.len() < 8 {
                return Err(ParseError::new(
                    ErrorCode::PositionShort,
                    "timestamped position is too short",
                ));
            }
            packet.packet_type = Some(PacketType::Location);
            packet.messaging = Some(identifier == b'@');
            packet.raw_timestamp = Some(body[1..8].to_owned());
            packet.timestamp = parse_timestamp(&body[1..8]).ok();
            parse_position(packet, &body[8..])
        }
        b'\'' | b'`' => {
            let result = parse_mice(packet, body, false);
            if result.is_err() && options.accept_broken_mice {
                parse_mice(packet, body, true)
            } else {
                result
            }
        }
        b':' => parse_message(packet, body),
        b';' => parse_object(packet, body),
        b')' => parse_item(packet, body),
        b'>' => {
            packet.packet_type = Some(PacketType::Status);
            let status = &body[1..];
            if status.len() >= 7 && matches!(status.as_bytes()[6], b'z' | b'/') {
                packet.raw_timestamp = Some(status[..7].to_owned());
                packet.timestamp = parse_timestamp(&status[..7]).ok();
                packet.status = Some(status[7..].to_owned());
            } else {
                packet.status = Some(status.to_owned());
            }
            Ok(())
        }
        b'<' => {
            packet.packet_type = Some(PacketType::Capabilities);
            for capability in body[1..]
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let (name, value) = capability.split_once('=').unwrap_or((capability, ""));
                packet
                    .capabilities
                    .insert(name.to_owned(), value.to_owned());
            }
            Ok(())
        }
        b'$' if body.starts_with("$ULTW") => parse_ultw(packet, &body[5..], false),
        b'$' => parse_nmea(packet, body),
        b'T' if body.starts_with("T#") => parse_telemetry(packet, body),
        b'_' => {
            if body.len() < 9 {
                Err(ParseError::new(
                    ErrorCode::WeatherInvalid,
                    "positionless weather report is too short",
                ))
            } else {
                parse_weather(packet, &body[9..])
            }
        }
        b'{' if body.starts_with("{{") => Err(ParseError::new(
            ErrorCode::ExperimentalUnsupported,
            "unsupported experimental packet",
        )),
        _ if matches!(
            packet.destination.as_ref(),
            "ID" | "BEACON" | "UIDIGI" | "CQ"
        ) =>
        {
            packet.packet_type = Some(PacketType::Beacon);
            Ok(())
        }
        _ => {
            if let Some(index) = body.find('!')
                && index <= 39
            {
                packet.packet_type = Some(PacketType::Location);
                packet.messaging = Some(false);
                return parse_position(packet, &body[index + 1..]);
            }
            Err(ParseError::new(
                ErrorCode::TypeNotSupported,
                format!("unsupported data type identifier {:?}", identifier as char),
            ))
        }
    }
}

fn parse_mice(packet: &mut ParseState<'_>, body: &str, repair: bool) -> Result<(), ParseError> {
    let destination = packet.destination.split('-').next().unwrap_or("");
    if destination.len() < 6 {
        return Err(ParseError::new(
            ErrorCode::MicEDestinationInvalid,
            "Mic-E destination is too short",
        ));
    }
    let mut information = body.as_bytes()[1..].to_vec();
    if repair && information.len() >= 7 && information[4] == b' ' {
        information.insert(5, b' ');
        packet.mice_mangled = true;
    }
    if information.len() < 8 {
        return Err(ParseError::new(
            ErrorCode::MicEShort,
            "Mic-E information field is too short",
        ));
    }
    let mut digits = [None; 6];
    let mut message = String::new();
    for (index, byte) in destination.bytes().take(6).enumerate() {
        let (digit, message_bit) = match byte {
            b'0'..=b'9' => (Some(byte - b'0'), '0'),
            b'A'..=b'J' => (Some(byte - b'A'), '2'),
            b'K' => (None, '2'),
            b'L' => (None, '0'),
            b'P'..=b'Y' => (Some(byte - b'P'), '1'),
            b'Z' => (None, '1'),
            _ => {
                return Err(ParseError::new(
                    ErrorCode::MicEDestinationInvalid,
                    "invalid Mic-E destination character",
                ));
            }
        };
        digits[index] = digit;
        if index < 3 {
            message.push(message_bit);
        }
    }
    let first_ambiguous = digits.iter().position(Option::is_none).unwrap_or(6);
    if digits[first_ambiguous..].iter().any(Option::is_some) {
        return Err(ParseError::new(
            ErrorCode::MicEDestinationInvalid,
            "Mic-E ambiguity markers must be trailing",
        ));
    }
    let ambiguity = 6 - first_ambiguous;
    if ambiguity > 4 {
        return Err(ParseError::new(
            ErrorCode::MicEDestinationInvalid,
            "Mic-E position ambiguity exceeds four digits",
        ));
    }
    if ambiguity > 0 {
        digits[first_ambiguous] = Some(if ambiguity >= 4 { 3 } else { 5 });
        for digit in &mut digits[first_ambiguous + 1..] {
            *digit = Some(0);
        }
    }
    let digits = digits.map(|digit| digit.expect("ambiguity digits were centered"));
    let north = matches!(destination.as_bytes()[3], b'P'..=b'Z');
    let longitude_offset = if matches!(destination.as_bytes()[4], b'P'..=b'Z') {
        100
    } else {
        0
    };
    let west = matches!(destination.as_bytes()[5], b'P'..=b'Z');
    let mut latitude = f64::from(digits[0] * 10 + digits[1])
        + (f64::from(digits[2] * 10 + digits[3]) + f64::from(digits[4] * 10 + digits[5]) / 100.0)
            / 60.0;
    if !north {
        latitude = -latitude;
    }
    let mut lon_degrees = i32::from(information[0]) - 28 + longitude_offset;
    if (180..=189).contains(&lon_degrees) {
        lon_degrees -= 80;
    } else if (190..=199).contains(&lon_degrees) {
        lon_degrees -= 190;
    }
    let mut lon_minutes = i32::from(information[1]) - 28;
    if lon_minutes >= 60 {
        lon_minutes -= 60;
    }
    let hundredths = i32::from(information[2]) - 28;
    if lon_degrees < 0 || lon_minutes < 0 || hundredths < 0 {
        return Err(ParseError::new(
            ErrorCode::MicEInformationInvalid,
            "invalid Mic-E position bytes",
        ));
    }
    let centered_lon_minutes = match ambiguity {
        4 => 30.0,
        3 => f64::from(lon_minutes / 10 * 10 + 5),
        2 => f64::from(lon_minutes) + 0.5,
        1 => f64::from(lon_minutes) + f64::from(hundredths / 10 * 10 + 5) / 100.0,
        _ => f64::from(lon_minutes) + f64::from(hundredths) / 100.0,
    };
    let mut longitude = f64::from(lon_degrees) + centered_lon_minutes / 60.0;
    if west {
        longitude = -longitude;
    }
    let sp = i32::from(information[3]) - 28;
    let dc = i32::from(information[4]) - 28;
    let se = i32::from(information[5]) - 28;
    let mut speed = sp * 10 + dc / 10;
    let mut course = (dc % 10) * 100 + se;
    if speed >= 800 {
        speed -= 800;
    }
    if course >= 400 {
        course -= 400;
    }
    let table = information[7];
    if !(matches!(table, b'/' | b'\\') || table.is_ascii_alphanumeric()) {
        return Err(ParseError::new(
            ErrorCode::SymbolTableInvalid,
            "invalid Mic-E symbol table",
        ));
    }
    packet.packet_type = Some(PacketType::Location);
    packet.format = Some(Format::MicE);
    packet.latitude = Some(latitude);
    packet.longitude = Some(longitude);
    packet.position_ambiguity = Some(ambiguity as u8);
    packet.position_resolution_m = Some(match ambiguity {
        0 => 18.52,
        1 => 185.2,
        2 => 1_852.0,
        3 => 18_520.0,
        _ => 111_120.0,
    });
    packet.speed_kmh = (!packet.mice_mangled).then_some(f64::from(speed) * 1.852);
    packet.course_deg = (!packet.mice_mangled).then_some(course as u16);
    packet.symbol_code = Some(information[6] as char);
    packet.symbol_table = Some(table as char);
    packet.mice_message_bits = Some(message);
    let mut comment = String::from_utf8_lossy(&information[8..]).into_owned();
    parse_base91_telemetry(packet, &mut comment);
    if let Some(index) = comment.find('}')
        && index >= 3
        && comment.as_bytes()[index - 3..index]
            .iter()
            .all(|byte| (b'!'..=b'{').contains(byte))
    {
        let altitude = comment.as_bytes()[index - 3..index]
            .iter()
            .fold(0_i32, |value, byte| value * 91 + i32::from(*byte - 33))
            - 10_000;
        packet.altitude_m = Some(f64::from(altitude));
        comment.replace_range(index - 3..=index, "");
    }
    parse_mice_telemetry(packet, &mut comment);
    crate::position::apply_dao_comment(packet, &comment);
    Ok(())
}

pub(crate) fn parse_base91_telemetry(packet: &mut ParseState<'_>, comment: &mut String) {
    let pipes = comment
        .match_indices('|')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let selected = pipes
        .iter()
        .enumerate()
        .rev()
        .find_map(|(closing_position, &last)| {
            pipes[..closing_position].iter().rev().find_map(|&first| {
                let data = &comment[first + 1..last];
                ((4..=14).contains(&data.len())
                    && data.len().is_multiple_of(2)
                    && data.bytes().all(|byte| (b'!'..=b'{').contains(&byte)))
                .then_some((first, last))
            })
        });
    let Some((first, last)) = selected else {
        return;
    };
    let data = &comment[first + 1..last];
    let decode = |pair: &[u8]| i32::from(pair[0] - 33) * 91 + i32::from(pair[1] - 33);
    let pairs: Vec<_> = data.as_bytes().chunks_exact(2).collect();
    let mut telemetry = Telemetry {
        sequence: Some(decode(pairs[0])),
        ..Telemetry::default()
    };
    for (index, pair) in pairs.iter().skip(1).take(5).enumerate() {
        telemetry.values[index] = Some(f64::from(decode(pair)));
    }
    if let Some(pair) = pairs.get(6) {
        let value = decode(pair);
        telemetry.bits = Some(
            (0..8)
                .map(|bit| if value & (1 << bit) != 0 { '1' } else { '0' })
                .collect(),
        );
    }
    packet.telemetry = Some(telemetry);
    comment.replace_range(first..=last, "");
    *comment = comment.trim().to_owned();
}

fn parse_mice_telemetry(packet: &mut ParseState<'_>, comment: &mut String) {
    let Some(rest) = comment.strip_prefix('\'') else {
        return;
    };
    let length = if rest.len() >= 10 && rest[..10].bytes().all(|b| b.is_ascii_hexdigit()) {
        10
    } else if rest.len() >= 4 && rest[..4].bytes().all(|b| b.is_ascii_hexdigit()) {
        4
    } else {
        return;
    };
    let mut telemetry = Telemetry::default();
    if length == 4 {
        telemetry.values[0] = u8::from_str_radix(&rest[..2], 16).ok().map(f64::from);
        telemetry.values[1] = Some(0.0);
        telemetry.values[2] = u8::from_str_radix(&rest[2..4], 16).ok().map(f64::from);
    } else {
        for index in 0..5 {
            telemetry.values[index] = u8::from_str_radix(&rest[index * 2..index * 2 + 2], 16)
                .ok()
                .map(f64::from);
        }
    }
    packet.telemetry = Some(telemetry);
    *comment = rest[length..].trim_start().to_owned();
}

/// Convert Mic-E message bits to their standard status text.
pub fn mice_message(bits: &str) -> &'static str {
    match bits {
        "111" => "Off Duty",
        "110" => "En Route",
        "101" => "In Service",
        "100" => "Returning",
        "011" => "Committed",
        "010" => "Special",
        "001" => "Priority",
        "000" => "Emergency",
        _ => "Unknown",
    }
}

fn parse_nmea(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    let mut sentence = body.trim();
    if !sentence.starts_with("$GP") {
        return Err(ParseError::new(
            ErrorCode::NmeaInvalid,
            "NMEA sentence must start with $GP",
        ));
    }
    if let Some((without_checksum, checksum)) = sentence.split_once('*') {
        if checksum.len() == 2 {
            let expected = u8::from_str_radix(checksum, 16)
                .map_err(|_| ParseError::new(ErrorCode::NmeaInvalid, "invalid checksum"))?;
            let actual = without_checksum.as_bytes()[1..]
                .iter()
                .fold(0, |sum, byte| sum ^ byte);
            if actual != expected {
                return Err(ParseError::new(
                    ErrorCode::NmeaInvalid,
                    "NMEA checksum mismatch",
                ));
            }
            packet.nmea_checksum_ok = Some(true);
        }
        sentence = without_checksum;
    }
    let fields: Vec<_> = sentence.split(',').collect();
    packet.packet_type = Some(PacketType::Location);
    packet.format = Some(Format::Nmea);
    let (symbol_table, symbol_code) = symbol_from_destination(&packet.destination);
    packet.symbol_table = Some(symbol_table);
    packet.symbol_code = Some(symbol_code);
    match fields.first().copied() {
        Some("$GPRMC") => {
            if fields.len() < 10 {
                return Err(ParseError::new(ErrorCode::NmeaShort, "GPRMC is too short"));
            }
            if fields[2] != "A" {
                return Err(ParseError::new(
                    ErrorCode::NmeaNoFix,
                    "GPRMC has no valid fix",
                ));
            }
            nmea_coordinates(packet, fields[3], fields[4], fields[5], fields[6])?;
            packet.speed_kmh = fields[7].parse::<f64>().ok().map(|v| v * 1.852);
            packet.course_deg = Some(fields[8].parse::<f64>().ok().map_or(0, normalize_course));
            packet.raw_timestamp = Some(format!("{} {}", fields[9], fields[1]));
        }
        Some("$GPGGA") => {
            if fields.len() < 11 {
                return Err(ParseError::new(ErrorCode::NmeaShort, "GPGGA is too short"));
            }
            if fields[6] == "0" {
                return Err(ParseError::new(
                    ErrorCode::NmeaNoFix,
                    "GPGGA has no valid fix",
                ));
            }
            nmea_coordinates(packet, fields[2], fields[3], fields[4], fields[5])?;
            packet.altitude_m = fields[9].parse().ok();
        }
        Some("$GPGLL") => {
            if fields.len() < 5 {
                return Err(ParseError::new(ErrorCode::NmeaShort, "GPGLL is too short"));
            }
            nmea_coordinates(packet, fields[1], fields[2], fields[3], fields[4])?;
        }
        Some(kind) => {
            return Err(ParseError::new(
                ErrorCode::NmeaInvalid,
                format!("unsupported NMEA sentence {kind}"),
            ));
        }
        None => return Err(ParseError::new(ErrorCode::NmeaShort, "empty NMEA sentence")),
    }
    Ok(())
}

fn symbol_from_destination(destination: &str) -> (char, char) {
    let Some(encoded) = destination
        .strip_prefix("GPS")
        .or_else(|| destination.strip_prefix("SPC"))
    else {
        return ('/', '/');
    };
    let bytes = encoded.as_bytes();
    if bytes.len() == 3 {
        if matches!(bytes[0], b'C' | b'E')
            && bytes[1..].iter().all(u8::is_ascii_digit)
            && let Ok(number) = encoded[1..].parse::<u8>()
            && (1..95).contains(&number)
        {
            return (
                if bytes[0] == b'C' { '/' } else { '\\' },
                char::from(number + 32),
            );
        }
        if matches!(bytes[0], b'O' | b'A' | b'N' | b'D' | b'S' | b'Q')
            && bytes[2].is_ascii_alphanumeric()
            && let Some((_, code)) = destination_symbol(&encoded[..2])
        {
            return (bytes[2] as char, code);
        }
    } else if bytes.len() == 2
        && let Some(symbol) = destination_symbol(encoded)
    {
        return symbol;
    }
    ('/', '/')
}

fn destination_symbol(encoded: &str) -> Option<(char, char)> {
    let bytes = encoded.as_bytes();
    let &[first, second] = bytes else {
        return None;
    };
    let ranged = |start: u8, end: u8, symbol_start: u8| {
        (start..=end)
            .contains(&second)
            .then(|| char::from(symbol_start + second - start))
    };
    match first {
        b'B' => ranged(b'B', b'P', b'!').map(|code| ('/', code)),
        b'P' if second.is_ascii_digit() => Some(('/', second as char)),
        b'M' => ranged(b'R', b'X', b':').map(|code| ('/', code)),
        b'P' => ranged(b'A', b'Z', b'A').map(|code| ('/', code)),
        b'H' => ranged(b'S', b'X', b'[').map(|code| ('/', code)),
        b'L' => ranged(b'A', b'Z', b'a').map(|code| ('/', code)),
        b'J' => ranged(b'1', b'4', b'{').map(|code| ('/', code)),
        b'O' => ranged(b'B', b'P', b'!').map(|code| ('\\', code)),
        b'A' if second.is_ascii_digit() => Some(('\\', second as char)),
        b'N' => ranged(b'R', b'X', b':').map(|code| ('\\', code)),
        b'A' => ranged(b'A', b'Z', b'A').map(|code| ('\\', code)),
        b'D' => ranged(b'S', b'X', b'[').map(|code| ('\\', code)),
        b'S' => ranged(b'A', b'Z', b'a').map(|code| ('\\', code)),
        b'Q' => ranged(b'1', b'4', b'{').map(|code| ('\\', code)),
        _ => None,
    }
}

fn normalize_course(value: f64) -> u16 {
    let rounded = value.round() as i32;
    if rounded == 0 {
        360
    } else if !(0..=360).contains(&rounded) {
        0
    } else {
        rounded as u16
    }
}

fn nmea_coordinates(
    packet: &mut ParseState<'_>,
    latitude: &str,
    ns: &str,
    longitude: &str,
    ew: &str,
) -> Result<(), ParseError> {
    let (lat, lat_res) = nmea_coordinate(latitude, ns)?;
    let (lon, lon_res) = nmea_coordinate(longitude, ew)?;
    packet.latitude = Some(lat);
    packet.longitude = Some(lon);
    packet.position_resolution_m = Some(lat_res.max(lon_res));
    Ok(())
}

fn nmea_coordinate(value: &str, hemisphere: &str) -> Result<(f64, f64), ParseError> {
    let value = value.trim();
    let hemisphere = hemisphere.trim().to_ascii_uppercase();
    let Some((whole, fraction)) = value.split_once('.') else {
        return Err(ParseError::new(
            ErrorCode::NmeaInvalid,
            "invalid NMEA coordinate",
        ));
    };
    if !(3..=5).contains(&whole.len())
        || fraction.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ParseError::new(
            ErrorCode::NmeaInvalid,
            "invalid NMEA coordinate",
        ));
    }
    let degree_digits = whole.len() - 2;
    let degrees: f64 = whole[..degree_digits]
        .parse()
        .map_err(|_| ParseError::new(ErrorCode::NmeaInvalid, "invalid NMEA degrees"))?;
    let minutes: f64 = format!("{}.{}", &whole[degree_digits..], fraction)
        .parse()
        .map_err(|_| ParseError::new(ErrorCode::NmeaInvalid, "invalid NMEA minutes"))?;
    if minutes >= 60.0 {
        return Err(ParseError::new(
            ErrorCode::NmeaInvalid,
            "NMEA minutes out of range",
        ));
    }
    let mut coordinate = degrees + minutes / 60.0;
    match hemisphere.as_str() {
        "S" | "W" => coordinate = -coordinate,
        "N" | "E" => {}
        _ => {
            return Err(ParseError::new(
                ErrorCode::NmeaInvalid,
                "invalid hemisphere",
            ));
        }
    }
    let limit = if matches!(hemisphere.as_str(), "N" | "S") {
        89.999_999
    } else {
        179.999_999
    };
    if coordinate.abs() > limit {
        return Err(ParseError::new(
            ErrorCode::NmeaInvalid,
            "NMEA coordinate is out of range",
        ));
    }
    let decimals = fraction.len() as i32;
    let resolution = 1.852 * 1000.0 * 10_f64.powi(-decimals);
    Ok((coordinate, resolution))
}

fn parse_telemetry(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    let fields: Vec<_> = body[2..].splitn(8, ',').collect();
    if fields.len() < 2 {
        return Err(ParseError::new(
            ErrorCode::TelemetryInvalid,
            "telemetry has too few fields",
        ));
    }
    let sequence = fields[0]
        .parse()
        .map_err(|_| ParseError::new(ErrorCode::TelemetryInvalid, "invalid telemetry sequence"))?;
    let mut telemetry = Telemetry {
        sequence: Some(sequence),
        ..Telemetry::default()
    };
    if fields.len() < 7 {
        packet.warnings.push(ParseError::new(
            ErrorCode::TelemetryInvalid,
            "telemetry report is truncated; decoded the available fields",
        ));
    }
    for (index, field) in fields.iter().skip(1).take(5).enumerate() {
        let field = field.trim();
        if field.is_empty() {
            telemetry.values[index] = Some(0.0);
            continue;
        }
        if field == "-" || field.ends_with('.') {
            return Err(ParseError::new(
                ErrorCode::TelemetryInvalid,
                format!("invalid telemetry value {field}"),
            ));
        }
        match field.parse::<f64>() {
            Ok(value) => {
                telemetry.values[index] = Some(value);
                if !(-999_999.0..999_999.0).contains(&value) {
                    packet.warnings.push(ParseError::new(
                        ErrorCode::TelemetryTooLarge,
                        format!("telemetry value {field} is outside FAP's supported numeric range"),
                    ));
                }
            }
            Err(_) => {
                packet.warnings.push(ParseError::new(
                    ErrorCode::TelemetryInvalid,
                    format!("invalid telemetry value {field}; decoded the preceding fields"),
                ));
                break;
            }
        }
    }
    if let Some(field) = fields.get(6) {
        let mut bits = field
            .trim()
            .bytes()
            .take(8)
            .take_while(|byte| matches!(byte, b'0' | b'1'))
            .map(char::from)
            .collect::<String>();
        bits.extend(std::iter::repeat_n('0', 8 - bits.len()));
        telemetry.bits = Some(bits);
    }
    packet.packet_type = Some(PacketType::Telemetry);
    packet.telemetry = Some(telemetry);
    Ok(())
}

fn parse_weather(packet: &mut ParseState<'_>, data: &str) -> Result<(), ParseError> {
    packet.packet_type = Some(PacketType::Weather);
    let (weather, remainder) = crate::position::weather_from_comment(data);
    packet.weather = Some(weather);
    if !remainder.trim().is_empty() {
        packet.comment = Some(remainder.trim().to_owned());
    }
    Ok(())
}

fn parse_ultw(packet: &mut ParseState<'_>, data: &str, logging: bool) -> Result<(), ParseError> {
    let mut fields = Vec::new();
    for field in data.as_bytes().chunks(4) {
        if field.len() < 4 {
            break;
        }
        if field == b"----" {
            fields.push(None);
        } else {
            let raw = std::str::from_utf8(field).unwrap_or_default();
            let value = u16::from_str_radix(raw, 16)
                .ok()
                .map(|value| value as i16 as i32);
            if value.is_none() {
                break;
            }
            fields.push(value);
        }
    }
    if fields.is_empty() {
        return Err(ParseError::new(
            ErrorCode::WeatherInvalid,
            "ULTW weather report has no data",
        ));
    }
    let get = |index: usize| fields.get(index).copied().flatten();
    let wind = |value: i32| (f64::from(value) / 36.0 * 10.0).round() / 10.0;
    let temperature = |value: i32| (((f64::from(value) / 10.0 - 32.0) / 1.8) * 10.0).round() / 10.0;
    let mut weather = Weather::default();
    if logging {
        weather.wind_speed_ms = get(0).map(wind);
    } else {
        weather.wind_gust_ms = get(0).map(wind);
    }
    weather.wind_direction_deg = get(1).map(|value| (f64::from(value & 0xff) * 1.41176).round());
    weather.temperature_c = get(2).map(temperature);
    weather.rain_since_midnight_mm =
        get(3).map(|value| (f64::from(value) * 0.254 * 10.0).round() / 10.0);
    weather.pressure_mbar = get(4)
        .filter(|value| *value >= 10)
        .map(|v| f64::from(v) / 10.0);
    if logging {
        weather.indoor_temperature_c = get(5).map(temperature);
        weather.humidity_percent = get(6)
            .map(|value| (f64::from(value) / 10.0).round_ties_even() as i32)
            .filter(|value| (1..=100).contains(value))
            .map(|value| value as u8);
        weather.indoor_humidity_percent = get(7)
            .map(|value| (f64::from(value) / 10.0).round_ties_even() as i32)
            .filter(|value| (1..=100).contains(value))
            .map(|value| value as u8);
        if let Some(value) = get(10) {
            weather.rain_since_midnight_mm = Some((f64::from(value) * 0.254 * 10.0).round() / 10.0);
        }
        if let Some(value) = get(11) {
            weather.wind_speed_ms = Some(wind(value));
        }
    } else {
        weather.humidity_percent = get(8)
            .map(|value| (f64::from(value) / 10.0).round_ties_even() as i32)
            .filter(|value| (1..=100).contains(value))
            .map(|value| value as u8);
        if let Some(value) = get(11) {
            weather.rain_since_midnight_mm = Some((f64::from(value) * 0.254 * 10.0).round() / 10.0);
        }
        weather.wind_speed_ms = get(12).map(wind);
    }
    packet.packet_type = Some(PacketType::Weather);
    packet.weather = Some(weather);
    Ok(())
}

fn parse_position(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    match body.as_bytes().first() {
        Some(b'0'..=b'9' | b' ') => parse_uncompressed(packet, body),
        Some(_) => parse_compressed(packet, body),
        None => Err(ParseError::new(
            ErrorCode::PositionShort,
            "position body is empty",
        )),
    }
}

fn parse_message(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    if body.len() < 12 {
        return Err(ParseError::new(
            ErrorCode::MessageShort,
            "message packet is too short",
        ));
    }
    if body.as_bytes()[10] != b':' {
        return Err(ParseError::new(
            ErrorCode::MessageInvalid,
            "message addressee field is malformed",
        ));
    }
    let mut message = Message {
        destination: body[1..10].trim().to_owned(),
        ..Message::default()
    };
    let content = &body[11..];
    let response_id = |prefix: &str| {
        let id = content.strip_prefix(prefix)?.trim_end();
        (!id.is_empty()
            && id.len() <= 5
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'}'))
        .then(|| id.to_owned())
    };
    if let Some(id) = response_id("ack") {
        message.acknowledgement_id = Some(id);
    } else if let Some(id) = response_id("rej") {
        message.rejection_id = Some(id);
    } else if let Some((text, id)) = content.rsplit_once('{') {
        message.text = text.to_owned();
        let id = id.trim_end();
        if let Some((message_id, ack_id)) = id.split_once('}') {
            message.id = Some(message_id.to_owned());
            if !ack_id.is_empty() {
                message.acknowledgement_id = Some(ack_id.to_owned());
            }
        } else {
            message.id = Some(id.to_owned());
        }
    } else {
        message.text = content.to_owned();
    }
    let telemetry = ["PARM.", "UNIT.", "EQNS.", "BITS."].iter().any(|prefix| {
        message
            .text
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
    });
    packet.packet_type = Some(if telemetry {
        PacketType::TelemetryMessage
    } else {
        PacketType::Message
    });
    packet.message = Some(message);
    Ok(())
}

fn parse_object(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    if body.len() < 31 {
        return Err(ParseError::new(
            ErrorCode::ObjectShort,
            "object is too short",
        ));
    }
    packet.packet_type = Some(PacketType::Object);
    packet.object_name = Some(body[1..10].trim_end().to_owned());
    packet.alive = match body.as_bytes()[10] {
        b'*' => Some(true),
        b'_' => Some(false),
        other => {
            return Err(ParseError::new(
                ErrorCode::ObjectInvalid,
                format!("invalid object state {:?}", other as char),
            ));
        }
    };
    packet.raw_timestamp = Some(body[11..18].to_owned());
    packet.timestamp = parse_timestamp(&body[11..18]).ok();
    parse_position(packet, &body[18..])?;
    packet.packet_type = Some(PacketType::Object);
    Ok(())
}

fn parse_item(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    let end = body[1..]
        .bytes()
        .take(10)
        .position(|byte| matches!(byte, b'!' | b'_'))
        .map(|index| index + 1)
        .ok_or_else(|| ParseError::new(ErrorCode::ItemInvalid, "item name terminator not found"))?;
    let position = &body[end + 1..];
    if position.len() < 13 {
        return Err(ParseError::new(ErrorCode::ItemShort, "item is too short"));
    }
    packet.packet_type = Some(PacketType::Item);
    packet.item_name = Some(body[1..end].to_owned());
    packet.alive = Some(body.as_bytes()[end] == b'!');
    parse_position(packet, position)?;
    packet.packet_type = Some(PacketType::Item);
    Ok(())
}

/// Validate and normalize an AX.25 callsign (`CALL` or `CALL-SSID`).
pub fn check_ax25_call(call: &str) -> Option<String> {
    check_ax25_call_ref(call).map(Cow::into_owned)
}

fn check_ax25_call_ref(call: &str) -> Option<Cow<'_, str>> {
    let (base, ssid) = call
        .split_once('-')
        .map_or((call, None), |(base, ssid)| (base, Some(ssid)));
    if base.is_empty() || base.len() > 6 || !base.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    if let Some(ssid) = ssid
        && (ssid.is_empty()
            || ssid.len() > 2
            || !ssid.bytes().all(|byte| byte.is_ascii_digit())
            || ssid.parse::<u8>().ok()? > 15)
    {
        return None;
    }
    if call.bytes().any(|byte| byte.is_ascii_lowercase()) {
        Some(Cow::Owned(call.to_ascii_uppercase()))
    } else {
        Some(Cow::Borrowed(call))
    }
}

/// Compute the APRS-IS authentication passcode for a callsign.
pub fn aprs_passcode(callsign: &str) -> i16 {
    let base = callsign
        .split('-')
        .next()
        .unwrap_or(callsign)
        .to_ascii_uppercase();
    let mut hash: u16 = 0x73e2;
    for pair in base.as_bytes().chunks(2) {
        hash ^= u16::from(pair[0]) << 8;
        if let Some(second) = pair.get(1) {
            hash ^= u16::from(*second);
        }
    }
    (hash & 0x7fff) as i16
}

fn valid_loose_call_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~')
}

fn valid_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}
