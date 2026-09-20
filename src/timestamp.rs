use std::time::{SystemTime, UNIX_EPOCH};

use crate::{ErrorCode, ParseError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A decoded APRS timestamp.
///
/// APRS timestamps omit some calendar components. FRAP fills those components
/// from the current date and adjusts day-based timestamps across month
/// boundaries when necessary.
pub struct AprsTimestamp {
    /// Four-digit calendar year inferred for the timestamp.
    pub year: i32,
    /// Calendar month in the range `1..=12`.
    pub month: u8,
    /// Day of month in the range `1..=31`.
    pub day: u8,
    /// Hour in the range `0..=23`.
    pub hour: u8,
    /// Minute in the range `0..=59`.
    pub minute: u8,
    /// Second in the range `0..=59`.
    pub second: u8,
    /// Whether the source timestamp explicitly used UTC.
    pub utc: bool,
}

pub(crate) fn parse_timestamp(raw: &str) -> Result<AprsTimestamp, ParseError> {
    if raw.len() != 7 || !raw[..6].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseError::new(
            ErrorCode::PacketInvalid,
            "invalid APRS timestamp",
        ));
    }
    let now = current_utc();
    let number = |range: std::ops::Range<usize>| {
        raw[range]
            .parse::<u8>()
            .map_err(|_| ParseError::new(ErrorCode::PacketInvalid, "invalid timestamp digits"))
    };
    let mut result = match raw.as_bytes()[6] {
        b'h' => AprsTimestamp {
            hour: number(0..2)?,
            minute: number(2..4)?,
            second: number(4..6)?,
            ..now
        },
        b'z' | b'/' => AprsTimestamp {
            day: number(0..2)?,
            hour: number(2..4)?,
            minute: number(4..6)?,
            second: 0,
            utc: raw.as_bytes()[6] == b'z',
            ..now
        },
        _ => {
            return Err(ParseError::new(
                ErrorCode::PacketInvalid,
                "unknown timestamp suffix",
            ));
        }
    };
    if result.hour > 23 || result.minute > 59 || result.second > 59 || result.day == 0 {
        return Err(ParseError::new(
            ErrorCode::PacketInvalid,
            "timestamp out of range",
        ));
    }
    if matches!(raw.as_bytes()[6], b'z' | b'/') && result.day > now.day.saturating_add(1) {
        if result.month == 1 {
            result.month = 12;
            result.year -= 1;
        } else {
            result.month -= 1;
        }
    }
    Ok(result)
}

fn current_utc() -> AprsTimestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let daytime = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    AprsTimestamp {
        year,
        month,
        day,
        hour: (daytime / 3600) as u8,
        minute: (daytime % 3600 / 60) as u8,
        second: (daytime % 60) as u8,
        utc: true,
    }
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
