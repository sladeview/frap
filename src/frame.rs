use crate::check_ax25_call;

const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
const TFEND: u8 = 0xdc;
const TFESC: u8 = 0xdd;

/// Convert a single-port KISS data frame to a TNC2 UI frame.
///
/// As in FAP, `frame` must not include the leading or trailing FEND bytes.
/// Non-data, non-UI, and non-PID-F0 frames return `None`.
pub fn kiss_to_tnc2(frame: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let raw = frame.as_ref();
    let mut unstuffed = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == FESC && index + 1 < raw.len() {
            match raw[index + 1] {
                TFEND => {
                    unstuffed.push(FEND);
                    index += 2;
                    continue;
                }
                TFESC => {
                    unstuffed.push(FESC);
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }
        unstuffed.push(raw[index]);
        index += 1;
    }
    if unstuffed.len() < 16 || unstuffed[0] != 0 {
        return None;
    }

    let mut offset = 1;
    let mut addresses = Vec::new();
    loop {
        if offset + 7 > unstuffed.len() || addresses.len() >= 10 {
            return None;
        }
        let address = &unstuffed[offset..offset + 7];
        let mut base = String::with_capacity(6);
        for byte in &address[..6] {
            let decoded = byte >> 1;
            if !decoded.is_ascii_uppercase() && !decoded.is_ascii_digit() && decoded != b' ' {
                return None;
            }
            base.push(decoded as char);
        }
        let base = base.trim_end();
        if base.is_empty() || base.len() > 6 || !base.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        let ssid = (address[6] >> 1) & 0x0f;
        let call = if ssid == 0 {
            base.to_owned()
        } else {
            format!("{base}-{ssid}")
        };
        let last = address[6] & 1 != 0;
        let repeated = address[6] & 0x80 != 0;
        addresses.push((call, repeated));
        offset += 7;
        if last {
            break;
        }
    }
    if addresses.len() < 2 || addresses.len() > 10 || offset + 2 > unstuffed.len() {
        return None;
    }
    if unstuffed[offset] != 0x03 || unstuffed[offset + 1] != 0xf0 {
        return None;
    }

    let mut result = Vec::new();
    result.extend_from_slice(addresses[1].0.as_bytes());
    result.push(b'>');
    result.extend_from_slice(addresses[0].0.as_bytes());
    for (call, repeated) in &addresses[2..] {
        result.push(b',');
        result.extend_from_slice(call.as_bytes());
        if *repeated {
            result.push(b'*');
        }
    }
    result.push(b':');
    result.extend_from_slice(&unstuffed[offset + 2..]);
    Some(result)
}

/// Convert a TNC2 UI frame to a complete single-port KISS data frame.
///
/// The returned bytes include leading and trailing FEND bytes and have KISS
/// byte stuffing applied.
pub fn tnc2_to_kiss(frame: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let (header, body) = split_once(frame.as_ref(), b':')?;
    if header.is_empty() || body.is_empty() || !header.is_ascii() {
        return None;
    }
    let header = std::str::from_utf8(header).ok()?;
    if header.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return None;
    }
    let (source, route) = header.split_once('>')?;
    let mut route = route.split(',');
    let destination = route.next()?;
    let digipeaters: Vec<_> = route.collect();
    if digipeaters.len() > 8 {
        return None;
    }
    let (source, source_ssid) = ax25_parts(source)?;
    let (destination, destination_ssid) = ax25_parts(destination)?;

    let mut ax25 = vec![0];
    // Match FAP's AX.25 UI convention: set the destination command bit.
    encode_address(&mut ax25, destination, destination_ssid, true, false);
    encode_address(
        &mut ax25,
        source,
        source_ssid,
        false,
        digipeaters.is_empty(),
    );
    for (index, raw) in digipeaters.iter().enumerate() {
        let (raw, repeated) = raw
            .strip_suffix('*')
            .map_or((*raw, false), |call| (call, true));
        let (call, ssid) = ax25_parts(raw)?;
        encode_address(
            &mut ax25,
            call,
            ssid,
            repeated,
            index + 1 == digipeaters.len(),
        );
    }
    ax25.extend_from_slice(&[0x03, 0xf0]);
    ax25.extend_from_slice(body);

    let mut result = Vec::with_capacity(ax25.len() + 2);
    result.push(FEND);
    for byte in ax25 {
        match byte {
            FEND => result.extend_from_slice(&[FESC, TFEND]),
            FESC => result.extend_from_slice(&[FESC, TFESC]),
            _ => result.push(byte),
        }
    }
    result.push(FEND);
    Some(result)
}

/// Extract the innermost source, destination base call, and payload used for
/// APRS duplicate detection.
pub fn aprs_duplicate_parts(packet: impl AsRef<[u8]>) -> Option<(String, String, Vec<u8>)> {
    let mut packet = packet.as_ref();
    loop {
        let (header, body) = split_once(packet, b':')?;
        if body.first() == Some(&b'}') && !header.is_empty() {
            packet = &body[1..];
        } else {
            break;
        }
    }
    let (header, body) = split_once(packet, b':')?;
    let header = std::str::from_utf8(header).ok()?;
    let (source, route) = header.split_once('>')?;
    let destination = route.split(',').next()?;
    if route.contains(',') && route.ends_with(',') {
        return None;
    }
    let source = duplicate_source(source)?;
    let destination = duplicate_destination(destination)?;
    let source = if source.contains('-') {
        source.to_ascii_uppercase()
    } else {
        format!("{}-0", source.to_ascii_uppercase())
    };
    let destination = destination.split('-').next()?.to_ascii_uppercase();
    let mut end = body.len();
    while end > 0 && body[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    Some((source, destination, body[..end].to_vec()))
}

/// Estimate the number of digipeated hops represented by a TNC2 header.
pub fn count_digihops(header: &str) -> Option<usize> {
    let header: String = header
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n'))
        .collect::<String>()
        .to_ascii_uppercase();
    let header = header
        .split_once(':')
        .map_or(header.as_str(), |(head, _)| head);
    let (source, route) = header.split_once('>')?;
    check_ax25_call(source)?;
    let mut route = route.split(',');
    check_ax25_call(route.next()?)?;
    let mut hops = 0;
    for raw in route {
        let (raw, repeated) = raw
            .strip_suffix('*')
            .map_or((raw, false), |call| (call, true));
        let call = check_ax25_call(raw)?;
        if let Some((wide, remaining)) = n_n_alias(&call, "WIDE") {
            if wide >= remaining {
                hops += usize::from(wide - remaining);
            }
        } else if n_n_alias(&call, "TRACE").is_some() {
            continue;
        } else if repeated {
            hops += 1;
        }
    }
    Some(hops)
}

fn split_once(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == separator)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn ax25_parts(call: &str) -> Option<(&str, u8)> {
    let (base, suffix) = call
        .split_once('-')
        .map_or((call, None), |(base, suffix)| (base, Some(suffix)));
    if base.is_empty()
        || base.len() > 6
        || !base
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    let ssid = match suffix {
        Some(suffix) if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) => {
            suffix.parse::<u8>().ok()?
        }
        Some(_) => return None,
        None => 0,
    };
    (ssid <= 15).then_some((base, ssid))
}

fn encode_address(output: &mut Vec<u8>, call: &str, ssid: u8, repeated: bool, last: bool) {
    for index in 0..6 {
        output.push(call.as_bytes().get(index).copied().unwrap_or(b' ') << 1);
    }
    output.push(0x60 | (ssid << 1) | u8::from(last) | if repeated { 0x80 } else { 0 });
}

fn n_n_alias(call: &str, prefix: &str) -> Option<(u8, u8)> {
    let rest = call.strip_prefix(prefix)?;
    let (initial, remaining) = rest.split_once('-')?;
    let initial = initial.parse::<u8>().ok()?;
    let remaining = remaining.parse::<u8>().ok()?;
    ((1..=7).contains(&initial) && remaining <= 7).then_some((initial, remaining))
}

fn duplicate_source(call: &str) -> Option<&str> {
    let (base, suffix) = call
        .split_once('-')
        .map_or((call, None), |(base, suffix)| (base, Some(suffix)));
    if base.is_empty()
        || base.len() > 6
        || !base.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || suffix.is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.len() > 2
                || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return None;
    }
    Some(call)
}

fn duplicate_destination(call: &str) -> Option<&str> {
    let (base, suffix) = call
        .split_once('-')
        .map_or((call, None), |(base, suffix)| (base, Some(suffix)));
    if base.is_empty()
        || base.len() > 6
        || !base.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || suffix.is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.len() > 2
                || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some(call)
}
