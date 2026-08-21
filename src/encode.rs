use std::time::{SystemTime, UNIX_EPOCH};

use crate::{ErrorCode, Message, ParseError};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncodePositionOptions {
    pub ambiguity: u8,
    pub messaging_capable: bool,
    pub dao: bool,
    /// Encode the position using APRS compressed base-91 coordinates.
    pub compressed: bool,
    /// An APRS `HHMMSSh` timestamp. The caller controls the time source.
    pub timestamp: Option<String>,
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampFormat {
    DayHourMinute,
    HourMinuteSecond,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncodeObjectOptions {
    pub alive: bool,
    /// Unix timestamp in seconds, or `None` to use the current time.
    pub timestamp: Option<i64>,
    pub speed_kmh: Option<f64>,
    pub course_deg: Option<f64>,
    pub altitude_m: Option<f64>,
    pub symbol: String,
    pub position: EncodePositionOptions,
}

impl Default for EncodeObjectOptions {
    fn default() -> Self {
        Self {
            alive: true,
            timestamp: None,
            speed_kmh: None,
            course_deg: None,
            altitude_m: None,
            symbol: "//".to_owned(),
            position: EncodePositionOptions::default(),
        }
    }
}

/// Create a UTC APRS timestamp from Unix seconds.
pub fn encode_timestamp(
    timestamp: Option<i64>,
    format: TimestampFormat,
) -> Result<String, ParseError> {
    let seconds = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });
    let days = seconds.div_euclid(86_400);
    let daytime = seconds.rem_euclid(86_400);
    let (_, _, day) = civil_from_days(days);
    let hour = daytime / 3_600;
    let minute = daytime % 3_600 / 60;
    let second = daytime % 60;
    Ok(match format {
        TimestampFormat::DayHourMinute => format!("{day:02}{hour:02}{minute:02}z"),
        TimestampFormat::HourMinuteSecond => format!("{hour:02}{minute:02}{second:02}h"),
    })
}

/// FAP-compatible name for [`encode_timestamp`].
pub fn make_timestamp(
    timestamp: Option<i64>,
    format: TimestampFormat,
) -> Result<String, ParseError> {
    encode_timestamp(timestamp, format)
}

/// Encode an APRS object information field.
pub fn encode_object(
    name: &str,
    latitude: f64,
    longitude: f64,
    options: &EncodeObjectOptions,
) -> Result<String, ParseError> {
    if name.is_empty() || name.len() > 9 || !name.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(ParseError::new(
            ErrorCode::PositionEncodeInvalid,
            "object name must contain 1..=9 printable ASCII bytes",
        ));
    }
    let mut position_options = options.position.clone();
    position_options.timestamp = None;
    position_options.messaging_capable = false;
    let position = encode_position(
        latitude,
        longitude,
        options.speed_kmh,
        options.course_deg,
        options.altitude_m,
        &options.symbol,
        &position_options,
    )?;
    Ok(format!(
        ";{name:<9}{}{}{}",
        if options.alive { '*' } else { '_' },
        encode_timestamp(options.timestamp, TimestampFormat::DayHourMinute)?,
        &position[1..]
    ))
}

/// FAP-compatible name for [`encode_object`].
pub fn make_object(
    name: &str,
    latitude: f64,
    longitude: f64,
    options: &EncodeObjectOptions,
) -> Result<String, ParseError> {
    encode_object(name, latitude, longitude, options)
}

pub fn encode_message(message: &Message) -> Result<String, ParseError> {
    if message.destination.is_empty() {
        return Err(ParseError::new(
            ErrorCode::MessageNoDestination,
            "message destination is required",
        ));
    }
    if message.destination.len() > 9 {
        return Err(ParseError::new(
            ErrorCode::MessageDestinationTooLong,
            "message destination exceeds 9 characters",
        ));
    }
    if [
        &message.destination,
        &message.text,
        message.id.as_deref().unwrap_or(""),
        message.acknowledgement_id.as_deref().unwrap_or(""),
        message.rejection_id.as_deref().unwrap_or(""),
    ]
    .iter()
    .any(|field| field.contains(['\r', '\n']))
    {
        return Err(ParseError::new(
            ErrorCode::MessageNewline,
            "message contains CR/LF",
        ));
    }
    if message.acknowledgement_id.is_some() && message.rejection_id.is_some()
        || !message.text.is_empty() && message.rejection_id.is_some()
    {
        return Err(ParseError::new(
            ErrorCode::MessageAckReject,
            "incompatible message acknowledgement/rejection fields",
        ));
    }
    if let Some(id) = &message.id
        && (id.is_empty() || id.len() > 5 || !id.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err(ParseError::new(
            ErrorCode::MessageIdInvalid,
            "invalid message ID",
        ));
    }
    let content = if let Some(rejection) = &message.rejection_id {
        format!("rej{rejection}")
    } else if let Some(ack) = &message.acknowledgement_id
        && message.id.is_none()
        && message.text.is_empty()
    {
        format!("ack{ack}")
    } else {
        let mut content = message.text.clone();
        if let Some(id) = &message.id {
            content.push('{');
            content.push_str(id);
            if let Some(ack) = &message.acknowledgement_id {
                if id.len() + ack.len() + 1 > 5 {
                    return Err(ParseError::new(
                        ErrorCode::MessageReplyAck,
                        "reply-ack is too long to embed",
                    ));
                }
                content.push('}');
                content.push_str(ack);
            }
        }
        content
    };
    Ok(format!(":{:<9}:{content}", message.destination))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_position(
    latitude: f64,
    longitude: f64,
    speed_kmh: Option<f64>,
    course_deg: Option<f64>,
    altitude_m: Option<f64>,
    symbol: &str,
    options: &EncodePositionOptions,
) -> Result<String, ParseError> {
    let symbol = if symbol.is_empty() { "//" } else { symbol };
    if !(-89.99999..=89.99999).contains(&latitude)
        || !(-179.99999..=179.99999).contains(&longitude)
        || symbol.len() != 2
    {
        return Err(ParseError::new(
            ErrorCode::PositionEncodeInvalid,
            "invalid coordinates or symbol",
        ));
    }
    let bytes = symbol.as_bytes();
    if !(matches!(bytes[0], b'/' | b'\\') || bytes[0].is_ascii_alphanumeric())
        || !(0x21..=0x7b).contains(&bytes[1]) && bytes[1] != b'}'
    {
        return Err(ParseError::new(
            ErrorCode::PositionEncodeInvalid,
            "invalid symbol",
        ));
    }
    if options.ambiguity > 4 {
        return Err(ParseError::new(
            ErrorCode::PositionEncodeInvalid,
            "ambiguity must be 0..=4",
        ));
    }
    if options.compressed && (options.ambiguity != 0 || options.dao) {
        return Err(ParseError::new(
            ErrorCode::PositionEncodeInvalid,
            "compressed positions cannot use ambiguity or DAO",
        ));
    }
    let identifier = match (&options.timestamp, options.messaging_capable) {
        (Some(_), true) => '@',
        (Some(_), false) => '/',
        (None, true) => '=',
        (None, false) => '!',
    };
    let mut result = identifier.to_string();
    if let Some(timestamp) = &options.timestamp {
        if timestamp.len() != 7 || !timestamp.is_ascii() {
            return Err(ParseError::new(
                ErrorCode::PositionEncodeInvalid,
                "timestamp must be a 7-character APRS timestamp",
            ));
        }
        result.push_str(timestamp);
    }
    if options.compressed {
        let table = match bytes[0] {
            b'0'..=b'9' => b'a' + bytes[0] - b'0',
            table => table,
        };
        result.push(table as char);
        append_base91_4(&mut result, (380_926.0 * (90.0 - latitude)) as u32);
        append_base91_4(&mut result, (190_463.0 * (180.0 + longitude)) as u32);
        result.push(bytes[1] as char);
        if let (Some(speed), Some(course)) = (speed_kmh, course_deg)
            && speed >= 0.0
            && course > 0.0
            && course <= 360.0
        {
            let mut course_value = ((course + 2.0) / 4.0) as u8;
            if course_value > 89 {
                course_value = 0;
            }
            let speed_value =
                ((speed / 1.852 + 1.0).ln() / 1.08_f64.ln() + 0.5).clamp(0.0, 89.0) as u8;
            result.push((course_value + 33) as char);
            result.push((speed_value + 33) as char);
            result.push('A');
        } else {
            result.push_str("  A");
        }
        append_altitude_and_comment(&mut result, altitude_m, &options.comment);
        return Ok(result);
    }

    let dao = options.dao && options.ambiguity == 0;
    let (mut lat, lat_dao) = encoded_coordinate(latitude, 2, dao);
    let (mut lon, lon_dao) = encoded_coordinate(longitude, 3, dao);
    apply_ambiguity(&mut lat, options.ambiguity);
    apply_ambiguity(&mut lon, options.ambiguity);
    lat.push(if latitude < 0.0 { 'S' } else { 'N' });
    lon.push(if longitude < 0.0 { 'W' } else { 'E' });
    result.push_str(&format!(
        "{lat}{}{lon}{}",
        bytes[0] as char, bytes[1] as char
    ));
    if let (Some(speed), Some(course)) = (speed_kmh, course_deg)
        && speed >= 0.0
        && course >= 0.0
    {
        result.push_str(&format!(
            "{:03.0}/{:03.0}",
            if course > 360.0 { 0.0 } else { course },
            (speed / 1.852).min(999.0)
        ));
    }
    append_altitude_and_comment(&mut result, altitude_m, &options.comment);
    if dao {
        let lat_char = (f64::from(lat_dao) / 1.1 + 0.5) as u8 + 33;
        let lon_char = (f64::from(lon_dao) / 1.1 + 0.5) as u8 + 33;
        result.push_str(&format!("!w{}{}!", lat_char as char, lon_char as char));
    }
    Ok(result)
}

/// FAP-compatible name for [`encode_position`].
#[allow(clippy::too_many_arguments)]
pub fn make_position(
    latitude: f64,
    longitude: f64,
    speed_kmh: Option<f64>,
    course_deg: Option<f64>,
    altitude_m: Option<f64>,
    symbol: &str,
    options: &EncodePositionOptions,
) -> Result<String, ParseError> {
    encode_position(
        latitude, longitude, speed_kmh, course_deg, altitude_m, symbol, options,
    )
}

fn append_base91_4(output: &mut String, value: u32) {
    for divisor in [91_u32.pow(3), 91_u32.pow(2), 91, 1] {
        output.push(((value / divisor % 91) as u8 + 33) as char);
    }
}

fn append_altitude_and_comment(output: &mut String, altitude_m: Option<f64>, comment: &str) {
    if let Some(altitude) = altitude_m.filter(|value| value.is_finite()) {
        let feet = altitude / 0.3048;
        let encoded_altitude = if feet >= 0.0 {
            format!("/A={feet:06.0}")
        } else {
            format!("/A=-{:05.0}", -feet)
        };
        output.push_str(&encoded_altitude);
    }
    output.push_str(comment);
}

fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

fn encoded_coordinate(value: f64, degrees: usize, dao: bool) -> (String, u8) {
    let value = value.abs();
    let whole = value.floor() as u16;
    let minutes = (value - f64::from(whole)) * 60.0;
    let scaled = if dao {
        (minutes * 10_000.0).round() as u32
    } else {
        (minutes * 100.0).round() as u32 * 100
    }
    .min(599_999);
    let digits = format!("{scaled:06}");
    (
        format!("{whole:0degrees$}{}.{}", &digits[..2], &digits[2..4]),
        digits[4..6].parse().unwrap_or_default(),
    )
}

fn apply_ambiguity(coordinate: &mut String, ambiguity: u8) {
    let mut bytes = coordinate.as_bytes().to_vec();
    let digit_indices: Vec<_> = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| byte.is_ascii_digit().then_some(index))
        .collect();
    for index in digit_indices.into_iter().rev().take(usize::from(ambiguity)) {
        bytes[index] = b' ';
    }
    *coordinate = String::from_utf8(bytes).expect("ASCII coordinate");
}
