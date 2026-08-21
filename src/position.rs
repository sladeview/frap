use crate::error::{ErrorCode, ParseError};
use crate::packet::{Format, PacketType, ParseState, Weather};

pub(crate) fn parse_uncompressed(
    packet: &mut ParseState<'_>,
    body: &str,
) -> Result<(), ParseError> {
    if body.len() < 19 {
        return Err(ParseError::new(
            ErrorCode::PositionShort,
            "uncompressed position is too short",
        ));
    }
    let (latitude, ambiguity) = coordinate(&body[..8], 2, b'N', b'S', None)?;
    let (longitude, _) = coordinate(&body[9..18], 3, b'E', b'W', Some(ambiguity))?;
    let table = body.as_bytes()[8];
    if !(matches!(table, b'/' | b'\\') || table.is_ascii_alphanumeric()) {
        return Err(ParseError::new(
            ErrorCode::SymbolTableInvalid,
            "invalid symbol table",
        ));
    }
    packet.format = Some(Format::Uncompressed);
    packet.latitude = Some(latitude);
    packet.longitude = Some(longitude);
    packet.position_ambiguity = Some(ambiguity);
    packet.position_resolution_m = Some(match ambiguity {
        0 => 18.52,
        1 => 185.2,
        2 => 1_852.0,
        3 => 18_520.0,
        _ => 111_120.0,
    });
    packet.symbol_table = Some(table as char);
    packet.symbol_code = Some(body.as_bytes()[18] as char);
    parse_position_comment(packet, &body[19..]);
    Ok(())
}

fn coordinate(
    value: &str,
    degree_digits: usize,
    positive: u8,
    negative: u8,
    forced_ambiguity: Option<u8>,
) -> Result<(f64, u8), ParseError> {
    let bytes = value.as_bytes();
    let expected = degree_digits + 6;
    if bytes.len() != expected || bytes[degree_digits + 2] != b'.' {
        return Err(ParseError::new(
            ErrorCode::PositionInvalid,
            "malformed uncompressed coordinate",
        ));
    }
    let hemisphere = bytes[expected - 1].to_ascii_uppercase();
    if !matches!(hemisphere, h if h == positive || h == negative) {
        return Err(ParseError::new(
            ErrorCode::PositionInvalid,
            "invalid coordinate hemisphere",
        ));
    }

    let degrees: f64 = value[..degree_digits]
        .parse()
        .map_err(|_| ParseError::new(ErrorCode::PositionInvalid, "invalid degrees"))?;
    let degree_limit = if degree_digits == 2 { 89.0 } else { 179.0 };
    if degrees > degree_limit {
        return Err(ParseError::new(
            ErrorCode::PositionInvalid,
            "degrees are outside the valid range",
        ));
    }

    let minute_bytes = &bytes[degree_digits..expected - 1];
    if !matches!(minute_bytes[0], b'0'..=b'7' | b' ')
        || !matches!(minute_bytes[1], b'0'..=b'9' | b' ')
        || minute_bytes[2] != b'.'
        || !minute_bytes[3..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b' '))
    {
        return Err(ParseError::new(
            ErrorCode::PositionInvalid,
            "invalid coordinate minutes",
        ));
    }

    let compact = [
        minute_bytes[0],
        minute_bytes[1],
        minute_bytes[3],
        minute_bytes[4],
    ];
    let natural_ambiguity = compact
        .iter()
        .rev()
        .take_while(|byte| **byte == b' ')
        .count() as u8;
    if compact[..compact.len() - usize::from(natural_ambiguity)].contains(&b' ') {
        return Err(ParseError::new(
            ErrorCode::PositionAmbiguity,
            "invalid position ambiguity",
        ));
    }

    let ambiguity = forced_ambiguity.unwrap_or(natural_ambiguity);
    let significant = 4_usize.saturating_sub(usize::from(ambiguity));
    if compact[..significant].contains(&b' ') {
        return Err(ParseError::new(
            ErrorCode::PositionAmbiguity,
            "spaces occur within significant coordinate digits",
        ));
    }
    let mut centered = compact;
    match ambiguity {
        0 => {}
        1 => centered[3] = b'5',
        2 => centered[2..].copy_from_slice(b"50"),
        3 => centered[1..].copy_from_slice(b"500"),
        4 => centered.copy_from_slice(b"3000"),
        _ => {
            return Err(ParseError::new(
                ErrorCode::PositionAmbiguity,
                "position ambiguity exceeds four digits",
            ));
        }
    }
    let minutes_text = [centered[0], centered[1], b'.', centered[2], centered[3]];
    let minutes: f64 = std::str::from_utf8(&minutes_text)
        .expect("coordinate parser constructs ASCII")
        .parse()
        .map_err(|_| ParseError::new(ErrorCode::PositionInvalid, "invalid minutes"))?;
    let mut result = degrees + minutes / 60.0;
    if hemisphere == negative {
        result = -result;
    }
    Ok((result, ambiguity))
}

pub(crate) fn parse_compressed(packet: &mut ParseState<'_>, body: &str) -> Result<(), ParseError> {
    if body.len() < 13 {
        return Err(ParseError::new(
            ErrorCode::CompressedPositionShort,
            "compressed position is too short",
        ));
    }
    if !body.as_bytes()[1..=12]
        .iter()
        .all(|byte| (33..=123).contains(byte) || *byte == b' ')
    {
        return Err(ParseError::new(
            ErrorCode::CompressedPositionInvalid,
            "compressed position contains an invalid base-91 byte",
        ));
    }
    let bytes = body.as_bytes();
    let lat_value = base91(&bytes[1..5])?;
    let lon_value = base91(&bytes[5..9])?;
    packet.format = Some(Format::Compressed);
    packet.latitude = Some(90.0 - lat_value as f64 / 380_926.0);
    packet.longitude = Some(-180.0 + lon_value as f64 / 190_463.0);
    packet.position_resolution_m = Some(0.291);
    packet.symbol_table = Some(match bytes[0] {
        b'a'..=b'j' => char::from(b'0' + bytes[0] - b'a'),
        table => table as char,
    });
    packet.symbol_code = Some(bytes[9] as char);

    let course = bytes[10] as i16 - 33;
    let speed = bytes[11] as i16 - 33;
    let compression_type = bytes[12] as i16 - 33;
    if course >= 0 && speed >= 0 {
        if compression_type & 0x18 == 0x10 {
            packet.altitude_m = Some(1.002_f64.powi((course * 91 + speed) as i32) * 0.3048);
        } else if course <= 89 {
            packet.course_deg = Some(if course == 0 { 360 } else { course as u16 * 4 });
            packet.speed_kmh = Some((1.08_f64.powi(speed as i32) - 1.0) * 1.852);
        } else if course == 90 {
            packet.radio_range_km = Some(2.0 * 1.08_f64.powi(speed as i32) * 1.609_344);
        }
    }
    if packet.symbol_code == Some('_') {
        let (weather, mut comment) = weather_from_comment(&body[13..]);
        crate::packet::parse_base91_telemetry(packet, &mut comment);
        packet.packet_type = Some(PacketType::Weather);
        packet.weather = Some(weather);
        packet.comment = (!comment.trim().is_empty()).then(|| comment.trim().to_owned());
    } else {
        parse_position_comment(packet, &body[13..]);
    }
    Ok(())
}

fn parse_position_comment(packet: &mut ParseState<'_>, original: &str) {
    if packet.symbol_code == Some('_') {
        let (weather, mut comment) = weather_from_comment(original);
        crate::packet::parse_base91_telemetry(packet, &mut comment);
        packet.packet_type = Some(PacketType::Weather);
        packet.weather = Some(weather);
        packet.comment = (!comment.trim().is_empty()).then(|| comment.trim().to_owned());
        return;
    }
    let mut comment = original.to_owned();
    if let Some(data) = comment.strip_prefix("PHG")
        && data.len() >= 4
        && data.as_bytes()[0].is_ascii_digit()
        && data.as_bytes()[2..4].iter().all(u8::is_ascii_digit)
    {
        let length = if data.len() >= 6
            && data.as_bytes()[4].is_ascii_alphanumeric()
            && data.as_bytes()[5] == b'/'
        {
            5
        } else {
            4
        };
        packet.phg = Some(data[..length].to_owned());
        comment = data[length..].to_owned();
    }
    if let Some(data) = comment.strip_prefix("RNG")
        && data.len() >= 4
        && let Ok(miles) = data[..4].parse::<f64>()
    {
        packet.radio_range_km = Some(miles * 1.609_344);
        comment = data[4..].to_owned();
    }
    if comment.len() >= 7
        && comment.as_bytes()[3] == b'/'
        && comment[..3]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b' '))
        && comment[4..7]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b' '))
    {
        packet.course_deg = Some(
            comment[..3]
                .parse::<u16>()
                .ok()
                .filter(|course| (1..=360).contains(course))
                .unwrap_or(0),
        );
        packet.speed_kmh = comment[4..7].parse::<f64>().ok().map(|speed| speed * 1.852);
        comment = comment[7..].to_owned();
    }
    if let Some(index) = comment.find("/A=")
        && comment.len() >= index + 9
        && let Ok(feet) = comment[index + 3..index + 9].parse::<f64>()
    {
        packet.altitude_m = Some(feet * 0.3048);
        comment.replace_range(index..index + 9, "");
    }
    crate::packet::parse_base91_telemetry(packet, &mut comment);
    parse_dao(packet, &comment);
}

fn parse_dao(packet: &mut ParseState<'_>, original: &str) {
    // FAP removes inline telemetry before scanning for !DAO!. Telemetry's
    // base-91 payload can itself contain sequences which resemble !DAO!.
    let mut comment = strip_inline_telemetry(original);
    let selected = {
        let bytes = comment.as_bytes();
        (0..bytes.len().saturating_sub(4))
            .filter(|index| bytes[*index] == b'!' && bytes[*index + 4] == b'!')
            .filter_map(|index| {
                let datum = bytes[index + 1];
                let d1 = bytes[index + 2];
                let d2 = bytes[index + 3];
                let value =
                    if datum.is_ascii_uppercase() && d1.is_ascii_digit() && d2.is_ascii_digit() {
                        Some((
                            datum,
                            Some((
                                f64::from(d1 - b'0') * 0.001,
                                f64::from(d2 - b'0') * 0.001,
                                1.852,
                            )),
                        ))
                    } else if datum.is_ascii_lowercase()
                        && (b'!'..=b'{').contains(&d1)
                        && (b'!'..=b'{').contains(&d2)
                    {
                        Some((
                            datum,
                            Some((
                                f64::from(d1 - 33) / 91.0 * 0.01,
                                f64::from(d2 - 33) / 91.0 * 0.01,
                                0.1852,
                            )),
                        ))
                    } else if (b'!'..=b'{').contains(&datum) && d1 == b' ' && d2 == b' ' {
                        Some((datum, None))
                    } else {
                        None
                    };
                value.map(|value| (index, value))
            })
            .next_back()
    };
    if let Some((index, (datum, adjustment))) = selected {
        packet.dao_datum = Some((datum as char).to_ascii_uppercase());
        if let Some((lat_minutes, lon_minutes, resolution)) = adjustment {
            packet.position_resolution_m = Some(resolution);
            if let Some(latitude) = packet.latitude.as_mut() {
                *latitude += lat_minutes / 60.0 * latitude.signum();
            }
            if let Some(longitude) = packet.longitude.as_mut() {
                *longitude += lon_minutes / 60.0 * longitude.signum();
            }
        }
        comment.replace_range(index..index + 5, "");
    }
    let comment = comment.trim().trim_start_matches('/');
    packet.comment = (!comment.is_empty()).then(|| comment.to_owned());
}

pub(crate) fn apply_dao_comment(packet: &mut ParseState<'_>, comment: &str) {
    parse_dao(packet, comment);
}

fn strip_inline_telemetry(comment: &str) -> String {
    let pipes = comment
        .match_indices('|')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    for (closing_position, &last) in pipes.iter().enumerate().rev() {
        for &first in pipes[..closing_position].iter().rev() {
            let payload = &comment[first + 1..last];
            if (4..=14).contains(&payload.len())
                && payload.len().is_multiple_of(2)
                && payload.bytes().all(|byte| (b'!'..=b'{').contains(&byte))
            {
                return format!("{}{}", &comment[..first], &comment[last + 1..]);
            }
        }
    }
    comment.to_owned()
}

pub(crate) fn weather_from_comment(data: &str) -> (Weather, String) {
    let mut weather = Weather::default();
    let mut rest = data.strip_prefix('_').unwrap_or(data);
    let field_sequence_started;
    if rest.len() >= 7 && rest.as_bytes()[3] == b'/' {
        weather.wind_direction_deg = parse_weather_number(&rest[..3]).map(f64::from);
        weather.wind_speed_ms = parse_weather_number(&rest[4..7]).map(|v| f64::from(v) * 0.44704);
        rest = &rest[7..];
        field_sequence_started = true;
    } else if rest.len() >= 8 && rest.starts_with('c') && rest.as_bytes()[4] == b's' {
        weather.wind_direction_deg = parse_weather_number(&rest[1..4]).map(f64::from);
        weather.wind_speed_ms = parse_weather_number(&rest[5..8]).map(|v| f64::from(v) * 0.44704);
        rest = &rest[8..];
        field_sequence_started = true;
    } else {
        field_sequence_started = false;
    }
    let mut remaining = rest.to_owned();
    let mut cursor = 0;
    let mut field_sequence_cursor = field_sequence_started.then_some(0);
    let mut seen_numeric_field = [false; 256];
    let mut preserved_comment_placeholders = Vec::new();
    let mut consumed_legacy_voltage = false;
    let mut consumed_raw_rain_counter = false;
    let mut leading_placeholder_separator_capacity = 0;
    while cursor < remaining.len() {
        if remaining.as_bytes()[cursor] == b'|'
            && let Some(end) = inline_telemetry_end(&remaining, cursor)
        {
            cursor = end;
            continue;
        }
        let candidate = &remaining[cursor..];
        let identifier = candidate.as_bytes()[0];
        // Perl FAP recognizes these legacy weather tokens but deliberately
        // exposes neither value. It removes only the first occurrence of each
        // from the returned weather comment.
        if identifier == b'v' && !consumed_legacy_voltage {
            let sign_width = usize::from(matches!(candidate.as_bytes().get(1), Some(b'+' | b'-')));
            let digit_count = candidate[1 + sign_width..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            if digit_count != 0 {
                remaining.replace_range(cursor..cursor + 1 + sign_width + digit_count, "");
                consumed_legacy_voltage = true;
                continue;
            }
        }
        if identifier == b'#' && !consumed_raw_rain_counter {
            let digit_count = candidate[1..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            if digit_count != 0 {
                remaining.replace_range(cursor..cursor + 1 + digit_count, "");
                consumed_raw_rain_counter = true;
                continue;
            }
            let placeholder_count = candidate[1..]
                .bytes()
                .take_while(|byte| matches!(byte, b'.' | b' '))
                .count()
                .min(5);
            if cursor == 0 && placeholder_count != 0 {
                remaining.replace_range(cursor..cursor + 1 + placeholder_count, "");
                leading_placeholder_separator_capacity = 5 - placeholder_count;
                continue;
            }
        }
        let (default_width, signed) = match identifier {
            b'c' | b's' | b'g' | b'r' | b'p' | b'P' | b'L' | b'l' | b'X' | b'V' => (3, false),
            b't' => (3, true),
            b'h' => (2, false),
            b'b' => (5, false),
            b'F' => (4, true),
            _ => {
                cursor += 1;
                continue;
            }
        };
        if seen_numeric_field[usize::from(identifier)] {
            cursor += 1;
            continue;
        }
        let sign_width = usize::from(signed && candidate.as_bytes().get(1) == Some(&b'-'));
        let digit_count = candidate[1 + sign_width..]
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if identifier == b't' && field_sequence_cursor == Some(cursor) {
            let initial_temperature_width = candidate[1 + sign_width..]
                .bytes()
                .take_while(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b' '))
                .count();
            if initial_temperature_width > digit_count
                && candidate[1 + sign_width..1 + sign_width + initial_temperature_width]
                    .bytes()
                    .any(|byte| byte.is_ascii_digit())
            {
                remaining.replace_range(
                    cursor..cursor + 1 + sign_width + initial_temperature_width,
                    "",
                );
                field_sequence_cursor = Some(cursor);
                continue;
            }
        }
        // A one-digit `h` embedded in a word is common in callsigns and
        // hostnames (for example, `dh5dy.de`). Keep standalone short humidity
        // fields and fields in an established weather sequence, but leave this
        // lexical lookalike in the comment.
        if identifier == b'h'
            && digit_count == 1
            && cursor != 0
            && remaining.as_bytes()[cursor - 1].is_ascii_alphabetic()
            && candidate
                .as_bytes()
                .get(2)
                .is_some_and(u8::is_ascii_alphabetic)
            && !seen_numeric_field.iter().copied().any(|seen| seen)
        {
            cursor += 1;
            continue;
        }
        let next_after_digits = candidate.as_bytes().get(1 + sign_width + digit_count);
        if matches!(identifier, b'F' | b'X' | b'V')
            && field_sequence_cursor != Some(cursor)
            && cursor != 0
        {
            cursor += 1;
            continue;
        }
        let snow_embedded_in_word = identifier == b's'
            && digit_count != 0
            && !seen_numeric_field.iter().copied().any(|seen| seen)
            && ((cursor != 0 && remaining.as_bytes()[cursor - 1].is_ascii_alphabetic())
                || next_after_digits.is_some_and(|byte| {
                    byte.is_ascii_alphabetic()
                        && !matches!(
                            byte,
                            b'c' | b'g'
                                | b't'
                                | b'r'
                                | b'p'
                                | b'P'
                                | b'h'
                                | b'b'
                                | b'L'
                                | b'l'
                                | b'F'
                                | b'X'
                                | b'V'
                        )
                }));
        if snow_embedded_in_word {
            cursor += 1;
            continue;
        }
        let luminosity_lookalike = matches!(identifier, b'L' | b'l')
            && digit_count != 0
            && cursor != 0
            && !seen_numeric_field.iter().copied().any(|seen| seen)
            && (digit_count < 3 || remaining.as_bytes()[cursor - 1].is_ascii_alphabetic());
        if luminosity_lookalike {
            cursor += 1;
            continue;
        }
        let direction_embedded_in_word = identifier == b'c'
            && digit_count != 0
            && cursor != 0
            && remaining.as_bytes()[cursor - 1].is_ascii_alphabetic();
        if direction_embedded_in_word {
            cursor += 1;
            continue;
        }
        let gust_embedded_in_word = identifier == b'g'
            && digit_count != 0
            && ((cursor != 0 && remaining.as_bytes()[cursor - 1].is_ascii_alphabetic())
                || next_after_digits.is_some_and(|byte| {
                    byte.is_ascii_alphabetic()
                        && !matches!(
                            byte,
                            b'c' | b's'
                                | b't'
                                | b'r'
                                | b'p'
                                | b'P'
                                | b'h'
                                | b'b'
                                | b'L'
                                | b'l'
                                | b'F'
                                | b'X'
                                | b'V'
                        )
                }));
        if gust_embedded_in_word {
            cursor += 1;
            continue;
        }
        let numeric_width = match identifier {
            b'g' => digit_count,
            b't' => digit_count.min(4),
            b'r' | b'p' | b'P' | b'h' | b'L' | b'l' | b's' => digit_count.min(3),
            b'b' if (4..=5).contains(&digit_count) => digit_count,
            b'b' => 0,
            _ => 0,
        };
        let placeholder_count = candidate[1..]
            .bytes()
            .take_while(|byte| matches!(byte, b'.' | b' '))
            .count();
        let placeholder_end = 1 + placeholder_count;
        let protects_visibility = identifier == b's'
            && candidate.as_bytes().get(placeholder_end) == Some(&b'V')
            && candidate
                .as_bytes()
                .get(placeholder_end + 1)
                .is_some_and(u8::is_ascii_digit);
        if protects_visibility && cursor != 0 {
            cursor += 1;
            continue;
        }
        // FAP's scanner can pass over an incomplete placeholder without losing
        // the field letter from the returned comment. Keep removing it from our
        // scanning buffer so later field detection is unchanged, but restore it
        // afterward when it was actually the end of a word (`Buenos Aires`,
        // `sensor`, `ASL`, and so on).
        let placeholder_in_comment = placeholder_count != 0 && cursor != 0;
        let placeholder_width = placeholder_count.min(5);
        let width = if numeric_width != 0 {
            sign_width + numeric_width
        } else if placeholder_width != 0 {
            placeholder_width
        } else {
            default_width
        };
        if candidate.len() < width + 1 {
            cursor += 1;
            continue;
        }
        let field = &candidate[1..=width];
        let value = if signed {
            field.trim().parse::<i32>().ok()
        } else {
            parse_weather_number(field)
        };
        let placeholder = field.bytes().all(|byte| matches!(byte, b'.' | b' '));
        if let Some(value) = value {
            match identifier {
                b'c' if weather.wind_direction_deg.is_none() => {
                    weather.wind_direction_deg = Some(f64::from(value));
                }
                b's' if seen_numeric_field[usize::from(b'c')] => {
                    if weather.wind_speed_ms.is_none() {
                        weather.wind_speed_ms = Some(f64::from(value) * 0.44704);
                    }
                }
                b's' if weather.snow_24h_mm.is_none() => {
                    weather.snow_24h_mm = Some(f64::from(value) * 0.254);
                }
                b'g' if weather.wind_gust_ms.is_none() => {
                    weather.wind_gust_ms = Some(f64::from(value) * 0.44704);
                }
                b't' if weather.temperature_c.is_none() => {
                    weather.temperature_c = Some((f64::from(value) - 32.0) * 5.0 / 9.0);
                }
                b'r' if weather.rain_1h_mm.is_none() => {
                    weather.rain_1h_mm = Some(f64::from(value) * 0.254);
                }
                b'p' if weather.rain_24h_mm.is_none() => {
                    weather.rain_24h_mm = Some(f64::from(value) * 0.254);
                }
                b'P' if weather.rain_since_midnight_mm.is_none() => {
                    weather.rain_since_midnight_mm = Some(f64::from(value) * 0.254);
                }
                b'h' if weather.humidity_percent.is_none() => {
                    let humidity = if value == 0 { 100 } else { value };
                    weather.humidity_percent =
                        (1..=100).contains(&humidity).then_some(humidity as u8);
                }
                b'b' if weather.pressure_mbar.is_none() => {
                    weather.pressure_mbar = Some(f64::from(value) / 10.0);
                }
                b'L' if weather.luminosity_wm2.is_none() => {
                    weather.luminosity_wm2 = Some(value as u16);
                }
                b'l' if weather.luminosity_wm2.is_none() => {
                    weather.luminosity_wm2 = Some((value + 1000) as u16);
                }
                b'F' if weather.water_level_m.is_none() => {
                    weather.water_level_m = Some(f64::from(value) / 10.0 * 0.3048);
                }
                b'X' if weather.radiation_nsvh.is_none() => {
                    weather.radiation_nsvh = Some(f64::from(value / 10) * 10_f64.powi(value % 10))
                }
                b'V' if weather.battery_voltage.is_none() => {
                    weather.battery_voltage = Some(f64::from(value) / 10.0);
                }
                _ => {}
            }
            seen_numeric_field[usize::from(identifier)] = true;
            if matches!(identifier, b'L' | b'l') {
                seen_numeric_field[usize::from(b'L')] = true;
                seen_numeric_field[usize::from(b'l')] = true;
            }
        } else if !placeholder {
            cursor += 1;
            continue;
        }
        if placeholder && placeholder_in_comment {
            preserved_comment_placeholders
                .push((cursor, remaining[cursor..cursor + width + 1].to_owned()));
        }
        if placeholder
            && !placeholder_in_comment
            && cursor == 0
            && matches!(
                identifier,
                b'r' | b'P' | b'p' | b'h' | b'b' | b'l' | b'L' | b's'
            )
        {
            leading_placeholder_separator_capacity = 5_usize.saturating_sub(width);
        }
        field_sequence_cursor = Some(cursor);
        remaining.replace_range(cursor..cursor + width + 1, "");
    }
    for (position, text) in preserved_comment_placeholders.into_iter().rev() {
        remaining.insert_str(position, &text);
    }
    let separator_width = remaining
        .bytes()
        .take(leading_placeholder_separator_capacity)
        .take_while(|byte| matches!(byte, b'.' | b' '))
        .count();
    remaining.replace_range(..separator_width, "");
    let mut remaining = remaining.trim().to_owned();
    if let Some(start) = remaining
        .bytes()
        .position(|byte| byte.is_ascii_whitespace())
    {
        let run_length = remaining[start..]
            .bytes()
            .take_while(u8::is_ascii_whitespace)
            .count();
        remaining.replace_range(start..start + run_length, " ");
    }
    if (3..=5).contains(&remaining.len())
        && remaining
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        weather.software = Some(remaining);
        (weather, String::new())
    } else {
        (weather, remaining)
    }
}

fn inline_telemetry_end(data: &str, start: usize) -> Option<usize> {
    data[start + 1..]
        .match_indices('|')
        .map(|(offset, _)| start + 1 + offset)
        .find(|end| {
            let payload = &data[start + 1..*end];
            (4..=14).contains(&payload.len())
                && payload.len().is_multiple_of(2)
                && payload.bytes().all(|byte| (b'!'..=b'{').contains(&byte))
        })
        .map(|end| end + 1)
}

fn parse_weather_number(field: &str) -> Option<i32> {
    if field.bytes().all(|byte| matches!(byte, b'.' | b' ')) {
        None
    } else {
        let field = field.trim();
        field
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| field.parse().ok())
            .flatten()
    }
}

fn base91(bytes: &[u8]) -> Result<u32, ParseError> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        if !(33..=123).contains(byte) {
            return Err(ParseError::new(
                ErrorCode::CompressedPositionInvalid,
                "invalid base-91 value",
            ));
        }
        Ok(value * 91 + u32::from(*byte - 33))
    })
}
