use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::ParseError;
use crate::timestamp::AprsTimestamp;

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
