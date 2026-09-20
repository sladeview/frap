use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::ParseError;
use crate::timestamp::AprsTimestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// High-level APRS packet classification.
pub enum PacketType {
    /// A station position report.
    Location,
    /// A named object report.
    Object,
    /// A named item report.
    Item,
    /// An APRS message, acknowledgement, or rejection.
    Message,
    /// A telemetry metadata message such as `PARM.`, `UNIT.`, `EQNS.`, or `BITS.`.
    TelemetryMessage,
    /// A station status report.
    Status,
    /// A station-capabilities report.
    Capabilities,
    /// A generic beacon whose destination is `BEACON`.
    Beacon,
    /// A positionless or positioned weather report.
    Weather,
    /// A telemetry data report.
    Telemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Position encoding found in an APRS packet.
pub enum Format {
    /// Human-readable degrees and decimal minutes.
    Uncompressed,
    /// Base-91 compressed coordinates.
    Compressed,
    /// Mic-E destination and information-field encoding.
    MicE,
    /// An NMEA GPS sentence.
    Nmea,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// An owned digipeater path component.
pub struct Digipeater {
    /// Normalized digipeater callsign, including an SSID when present.
    pub call: String,
    /// Whether a trailing `*` marks this path component as already used.
    pub was_digipeated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A digipeater path component that may borrow its callsign from the input.
pub struct DigipeaterRef<'a> {
    /// Digipeater callsign, including an SSID when present.
    pub call: Cow<'a, str>,
    /// Whether a trailing `*` marks this path component as already used.
    pub was_digipeated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// An APRS message or telemetry metadata message.
pub struct Message {
    /// Addressee, without the fixed-width padding used on the wire.
    pub destination: String,
    /// Message text, excluding message IDs and reply-ack data.
    pub text: String,
    /// Optional outgoing message ID.
    pub id: Option<String>,
    /// Message ID being acknowledged, including reply-ack data when present.
    pub acknowledgement_id: Option<String>,
    /// Message ID being rejected.
    pub rejection_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
/// Decoded APRS telemetry values.
pub struct Telemetry {
    /// Sequence number for `T#` and inline base-91 telemetry. Legacy Mic-E
    /// hexadecimal telemetry does not carry one.
    pub sequence: Option<i32>,
    /// Up to five analogue telemetry channels in wire order.
    pub values: [Option<f64>; 5],
    /// Eight digital channel states, represented in APRS bit order.
    pub bits: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
/// Decoded APRS weather measurements.
pub struct Weather {
    /// Wind direction in degrees clockwise from north.
    pub wind_direction_deg: Option<f64>,
    /// Sustained wind speed in metres per second.
    pub wind_speed_ms: Option<f64>,
    /// Wind-gust speed in metres per second.
    pub wind_gust_ms: Option<f64>,
    /// Outdoor temperature in degrees Celsius.
    pub temperature_c: Option<f64>,
    /// Indoor temperature in degrees Celsius.
    pub indoor_temperature_c: Option<f64>,
    /// Outdoor relative humidity as a percentage.
    pub humidity_percent: Option<u8>,
    /// Indoor relative humidity as a percentage.
    pub indoor_humidity_percent: Option<u8>,
    /// Barometric pressure in millibars (hectopascals).
    pub pressure_mbar: Option<f64>,
    /// Rainfall during the previous hour in millimetres.
    pub rain_1h_mm: Option<f64>,
    /// Rainfall during the previous 24 hours in millimetres.
    pub rain_24h_mm: Option<f64>,
    /// Rainfall since local midnight in millimetres.
    pub rain_since_midnight_mm: Option<f64>,
    /// Snowfall during the previous 24 hours in millimetres.
    pub snow_24h_mm: Option<f64>,
    /// Luminosity in watts per square metre.
    pub luminosity_wm2: Option<u16>,
    /// Water level in metres from the APRS `F` weather extension.
    pub water_level_m: Option<f64>,
    /// Radiation dose rate in nanosieverts per hour from the `X` extension.
    pub radiation_nsvh: Option<f64>,
    /// Weather-station battery voltage from the `V` extension.
    pub battery_voltage: Option<f64>,
    /// Weather software or station identifier left by the report.
    pub software: Option<String>,
}

/// Position-related data shared by locations, objects, and items.
#[derive(Debug, Clone, PartialEq)]
pub struct PositionReport {
    /// Position wire encoding, when it can be identified.
    pub format: Option<Format>,
    /// Latitude in signed decimal degrees.
    pub latitude: f64,
    /// Longitude in signed decimal degrees.
    pub longitude: f64,
    /// Number of ambiguous coordinate digits, from zero through four.
    pub ambiguity: Option<u8>,
    /// Approximate coordinate resolution in metres.
    pub resolution_m: Option<f64>,
    /// APRS symbol-table identifier.
    pub symbol_table: Option<char>,
    /// APRS symbol code.
    pub symbol_code: Option<char>,
    /// Speed in kilometres per hour.
    pub speed_kmh: Option<f64>,
    /// Course in degrees clockwise from north.
    pub course_deg: Option<u16>,
    /// Altitude in metres above mean sea level.
    pub altitude_m: Option<f64>,
    /// Estimated radio range in kilometres from an RNG or PHG extension.
    pub radio_range_km: Option<f64>,
    /// Original seven-character APRS timestamp.
    pub raw_timestamp: Option<String>,
    /// Decoded timestamp with inferred calendar components.
    pub timestamp: Option<AprsTimestamp>,
    /// Whether the supplied NMEA checksum was valid.
    pub nmea_checksum_ok: Option<bool>,
    /// Datum byte from a decoded DAO extension.
    pub dao_datum: Option<char>,
    /// Raw PHG or PHGRA extension.
    pub phg: Option<String>,
    /// Mic-E message bits as their three-bit textual representation.
    pub mice_message_bits: Option<String>,
    /// Whether optional recovery repaired a known damaged Mic-E packet form.
    pub mice_mangled: bool,
    /// Weather measurements attached to this position.
    pub weather: Option<Weather>,
    /// Inline or Mic-E telemetry attached to this position.
    pub telemetry: Option<Telemetry>,
    /// Remaining free-form position comment.
    pub comment: Option<String>,
}

/// Parsed APRS information field, represented by its concrete wire type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PacketBody {
    /// A station position report.
    Location {
        /// Decoded position and its extensions.
        position: Box<PositionReport>,
        /// Whether the data-type identifier advertises messaging support.
        messaging: bool,
    },
    /// A named APRS object.
    Object {
        /// Object name without fixed-width padding.
        name: String,
        /// Whether the object is live rather than killed.
        alive: bool,
        /// Object position and its extensions.
        position: Box<PositionReport>,
    },
    /// A named APRS item.
    Item {
        /// Item name.
        name: String,
        /// Whether the item is live rather than killed.
        alive: bool,
        /// Item position and its extensions.
        position: Box<PositionReport>,
    },
    /// An ordinary message, acknowledgement, or rejection.
    Message(Message),
    /// A `PARM.`, `UNIT.`, `EQNS.`, or `BITS.` telemetry metadata message.
    TelemetryMessage(Message),
    /// A station status report.
    Status {
        /// Status text after any timestamp.
        text: String,
        /// Original seven-character APRS timestamp.
        raw_timestamp: Option<String>,
        /// Decoded timestamp with inferred calendar components.
        timestamp: Option<AprsTimestamp>,
    },
    /// Station capabilities keyed by capability name.
    Capabilities(BTreeMap<String, String>),
    /// A generic destination-addressed beacon.
    Beacon {
        /// Uninterpreted beacon information field.
        data: String,
    },
    /// A positionless or positioned weather report.
    Weather {
        /// Decoded weather measurements.
        weather: Box<Weather>,
        /// Position accompanying the weather report, if present.
        position: Option<Box<PositionReport>>,
        /// Messaging capability for positioned weather data.
        messaging: Option<bool>,
        /// Inline telemetry accompanying the weather report.
        telemetry: Option<Telemetry>,
        /// Remaining free-form weather comment.
        comment: Option<String>,
    },
    /// A classic, Mic-E, or inline base-91 telemetry report.
    Telemetry(Telemetry),
}

/// Fully owned parsed APRS packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Exact bytes supplied to the parser.
    pub original_bytes: Vec<u8>,
    /// Lossy UTF-8 rendering of the complete packet.
    pub original: String,
    /// TNC2 header before the `:` separator.
    pub header: String,
    /// APRS information field after the `:` separator.
    pub information: String,
    /// Source callsign as represented by the parser.
    pub source: String,
    /// Destination address as represented by the parser.
    pub destination: String,
    /// Digipeater path components in wire order.
    pub digipeaters: Vec<Digipeater>,
    /// Type-safe decoded information field.
    pub body: PacketBody,
    /// Non-fatal compatibility or data-quality findings.
    pub warnings: Vec<ParseError>,
}

/// Parsed APRS packet borrowing envelope fields from its input where possible.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRef<'a> {
    /// Exact input bytes borrowed from the caller.
    pub original_bytes: &'a [u8],
    /// Complete packet, borrowed when the input is valid UTF-8.
    pub original: Cow<'a, str>,
    /// TNC2 header, borrowed when normalization was unnecessary.
    pub header: Cow<'a, str>,
    /// APRS information field, borrowed when normalization was unnecessary.
    pub information: Cow<'a, str>,
    /// Source callsign, borrowed when normalization was unnecessary.
    pub source: Cow<'a, str>,
    /// Destination address, borrowed when normalization was unnecessary.
    pub destination: Cow<'a, str>,
    /// Digipeater path components, borrowing callsigns where possible.
    pub digipeaters: Vec<DigipeaterRef<'a>>,
    /// Type-safe decoded information field.
    pub body: PacketBody,
    /// Non-fatal compatibility or data-quality findings.
    pub warnings: Vec<ParseError>,
}

/// Private flat state used while the individual APRS syntaxes are decoded.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ParseState<'a> {
    pub(super) original_bytes: &'a [u8],
    pub(super) original: Cow<'a, str>,
    pub(super) header: Cow<'a, str>,
    pub(super) body: Cow<'a, str>,
    pub(super) source: Cow<'a, str>,
    pub(super) destination: Cow<'a, str>,
    pub(super) digipeaters: Vec<DigipeaterRef<'a>>,
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
    pub(super) warnings: Vec<ParseError>,
}

impl PacketRef<'_> {
    /// Convert this borrowed packet into a fully owned [`Packet`].
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

    pub(super) fn into_packet_ref(mut self) -> PacketRef<'a> {
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
        /// Return the high-level type derived from [`Self::packet_body`].
        ///
        /// The return type remains optional for compatibility with the earlier
        /// flat packet model; a successfully parsed packet always returns
        /// `Some`.
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

        /// Return the concrete, type-safe APRS information field.
        pub const fn packet_body(&self) -> &PacketBody {
            &self.body
        }

        /// Return position data for a location, object, item, or positioned
        /// weather packet.
        pub fn position(&self) -> Option<&PositionReport> {
            match &self.body {
                PacketBody::Location { position, .. }
                | PacketBody::Object { position, .. }
                | PacketBody::Item { position, .. } => Some(position),
                PacketBody::Weather { position, .. } => position.as_deref(),
                _ => None,
            }
        }

        /// Return message data for an ordinary or telemetry metadata message.
        pub fn message(&self) -> Option<&Message> {
            match &self.body {
                PacketBody::Message(message) | PacketBody::TelemetryMessage(message) => {
                    Some(message)
                }
                _ => None,
            }
        }

        /// Return weather data attached directly to the packet or its position.
        pub fn weather(&self) -> Option<&Weather> {
            match &self.body {
                PacketBody::Weather { weather, .. } => Some(weather),
                _ => self
                    .position()
                    .and_then(|position| position.weather.as_ref()),
            }
        }

        /// Return telemetry attached directly to the packet, weather, or
        /// position.
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

        /// Return the remaining free-form position or weather comment.
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

        /// Return the position wire format, if this packet has a position.
        pub fn format(&self) -> Option<Format> {
            self.position().and_then(|p| p.format)
        }
        /// Return latitude in signed decimal degrees.
        pub fn latitude(&self) -> Option<f64> {
            self.position().map(|p| p.latitude)
        }
        /// Return longitude in signed decimal degrees.
        pub fn longitude(&self) -> Option<f64> {
            self.position().map(|p| p.longitude)
        }
        /// Return the number of ambiguous coordinate digits.
        pub fn position_ambiguity(&self) -> Option<u8> {
            self.position().and_then(|p| p.ambiguity)
        }
        /// Return the approximate position resolution in metres.
        pub fn position_resolution_m(&self) -> Option<f64> {
            self.position().and_then(|p| p.resolution_m)
        }
        /// Return the APRS symbol-table identifier.
        pub fn symbol_table(&self) -> Option<char> {
            self.position().and_then(|p| p.symbol_table)
        }
        /// Return the APRS symbol code.
        pub fn symbol_code(&self) -> Option<char> {
            self.position().and_then(|p| p.symbol_code)
        }
        /// Return speed in kilometres per hour.
        pub fn speed_kmh(&self) -> Option<f64> {
            self.position().and_then(|p| p.speed_kmh)
        }
        /// Return course in degrees clockwise from north.
        pub fn course_deg(&self) -> Option<u16> {
            self.position().and_then(|p| p.course_deg)
        }
        /// Return altitude in metres above mean sea level.
        pub fn altitude_m(&self) -> Option<f64> {
            self.position().and_then(|p| p.altitude_m)
        }
        /// Return the estimated radio range in kilometres.
        pub fn radio_range_km(&self) -> Option<f64> {
            self.position().and_then(|p| p.radio_range_km)
        }
        /// Return whether the supplied NMEA checksum was valid.
        pub fn nmea_checksum_ok(&self) -> Option<bool> {
            self.position().and_then(|p| p.nmea_checksum_ok)
        }
        /// Return the datum character from a DAO extension.
        pub fn dao_datum(&self) -> Option<char> {
            self.position().and_then(|p| p.dao_datum)
        }
        /// Return the raw PHG or PHGRA extension.
        pub fn phg(&self) -> Option<&str> {
            self.position().and_then(|p| p.phg.as_deref())
        }
        /// Return the three decoded Mic-E message bits.
        pub fn mice_message_bits(&self) -> Option<&str> {
            self.position().and_then(|p| p.mice_message_bits.as_deref())
        }
        /// Return whether damaged Mic-E recovery modified this packet.
        pub fn mice_mangled(&self) -> bool {
            self.position().is_some_and(|p| p.mice_mangled)
        }
        /// Return whether the position data-type identifier advertises
        /// messaging support.
        pub fn messaging(&self) -> Option<bool> {
            match &self.body {
                PacketBody::Location { messaging, .. } => Some(*messaging),
                PacketBody::Weather { messaging, .. } => *messaging,
                _ => None,
            }
        }
        /// Return the original seven-character APRS timestamp.
        pub fn raw_timestamp(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Status { raw_timestamp, .. } => raw_timestamp.as_deref(),
                _ => self.position().and_then(|p| p.raw_timestamp.as_deref()),
            }
        }
        /// Return the decoded timestamp with inferred calendar components.
        pub fn timestamp(&self) -> Option<AprsTimestamp> {
            match &self.body {
                PacketBody::Status { timestamp, .. } => *timestamp,
                _ => self.position().and_then(|p| p.timestamp),
            }
        }
        /// Return an object's name, or `None` for other packet types.
        pub fn object_name(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Object { name, .. } => Some(name),
                _ => None,
            }
        }
        /// Return an item's name, or `None` for other packet types.
        pub fn item_name(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Item { name, .. } => Some(name),
                _ => None,
            }
        }
        /// Return whether an object or item is live rather than killed.
        pub fn alive(&self) -> Option<bool> {
            match &self.body {
                PacketBody::Object { alive, .. } | PacketBody::Item { alive, .. } => Some(*alive),
                _ => None,
            }
        }
        /// Return station status text, or `None` for other packet types.
        pub fn status(&self) -> Option<&str> {
            match &self.body {
                PacketBody::Status { text, .. } => Some(text),
                _ => None,
            }
        }
        /// Return station capabilities keyed by capability name.
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
/// Options controlling parser validation and compatibility recovery.
pub struct ParseOptions {
    /// Enforce the eight-digipeater AX.25 path limit and AX.25 callsigns
    /// throughout the path.
    pub strict_ax25: bool,
    /// Repair the common Mic-E corruption where collapsed spaces remove a
    /// speed/course byte.
    pub accept_broken_mice: bool,
}
