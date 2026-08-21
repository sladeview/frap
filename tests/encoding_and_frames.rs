use frap::{
    EncodeObjectOptions, EncodePositionOptions, Format, TimestampFormat, aprs_duplicate_parts,
    count_digihops, encode_object, encode_position, encode_timestamp, kiss_to_tnc2, parse,
    tnc2_to_kiss,
};

#[test]
fn round_trips_kiss_and_tnc2_with_binary_payload() {
    let tnc2 = b"2W0FWJ-2>APRS,WIDE1-1*,WIDE2-2:binary \xdb \xc0 payload";
    let kiss = tnc2_to_kiss(tnc2).unwrap();
    assert_eq!(kiss.first(), Some(&0xc0));
    assert_eq!(kiss.last(), Some(&0xc0));
    assert!(kiss.windows(2).any(|bytes| bytes == [0xdb, 0xdd]));
    assert!(kiss.windows(2).any(|bytes| bytes == [0xdb, 0xdc]));
    assert_eq!(kiss[8], 0xe0);
    assert_eq!(kiss_to_tnc2(&kiss[1..kiss.len() - 1]).unwrap(), tnc2);
}

#[test]
fn rejects_non_ui_kiss_frames_and_invalid_tnc2_paths() {
    let mut kiss = tnc2_to_kiss("2W0FWJ>APRS:hello").unwrap();
    let control = 1 + 1 + 14;
    kiss[control] = 0x13;
    assert!(kiss_to_tnc2(&kiss[1..kiss.len() - 1]).is_none());
    assert!(tnc2_to_kiss("2W0FWJ>APRS,WIDE1-16:hello").is_none());
    assert!(tnc2_to_kiss("2w0fwj>APRS:hello").is_none());
    assert!(tnc2_to_kiss("2W0FWJ-0002>APRS:hello").is_some());
}

#[test]
fn extracts_innermost_duplicate_parts() {
    let packet = b"IGATE>APRS:}N0CALL>APRS:}2W0FWJ-2>BEACON,WIDE1-1:payload  \r\n";
    assert_eq!(
        aprs_duplicate_parts(packet),
        Some((
            "2W0FWJ-2".to_owned(),
            "BEACON".to_owned(),
            b"payload".to_vec()
        ))
    );
    assert_eq!(
        aprs_duplicate_parts("2W0FWJ>APRS:test"),
        Some(("2W0FWJ-0".to_owned(), "APRS".to_owned(), b"test".to_vec()))
    );
}

#[test]
fn estimates_digipeater_hops_like_fap() {
    assert_eq!(count_digihops("2W0FWJ>APRS"), Some(0));
    assert_eq!(
        count_digihops("2W0FWJ>APRS,FIRST*,WIDE2-1,TRACE3-1,LAST*:body"),
        Some(3)
    );
    assert_eq!(count_digihops("2W0FWJ>APRS,WIDE1-2"), Some(0));
    assert_eq!(count_digihops("not a header"), None);
}

#[test]
fn creates_known_utc_timestamps() {
    let unix = Some(1_704_072_245); // 2024-01-01 01:24:05 UTC
    assert_eq!(
        encode_timestamp(unix, TimestampFormat::DayHourMinute).unwrap(),
        "010124z"
    );
    assert_eq!(
        encode_timestamp(unix, TimestampFormat::HourMinuteSecond).unwrap(),
        "012405h"
    );
}

#[test]
fn encodes_and_parses_compressed_positions() {
    let options = EncodePositionOptions {
        compressed: true,
        comment: "Testing".to_owned(),
        ..EncodePositionOptions::default()
    };
    let body = encode_position(
        51.5,
        -3.0,
        Some(92.6),
        Some(360.0),
        Some(123.0),
        "1-",
        &options,
    )
    .unwrap();
    let packet = parse(format!("2W0FWJ>APRS:{body}")).unwrap();
    assert_eq!(packet.format(), Some(Format::Compressed));
    assert_eq!(packet.symbol_table(), Some('1'));
    assert_eq!(packet.symbol_code(), Some('-'));
    assert!((packet.latitude().unwrap() - 51.5).abs() < 0.00001);
    assert!((packet.longitude().unwrap() + 3.0).abs() < 0.00001);
    assert!((packet.altitude_m().unwrap() - 123.0).abs() < 0.2);
    assert_eq!(packet.comment(), Some("Testing"));
}

#[test]
fn encodes_and_parses_objects() {
    let options = EncodeObjectOptions {
        timestamp: Some(1_704_072_245),
        symbol: "/-".to_owned(),
        position: EncodePositionOptions {
            comment: "Test object".to_owned(),
            ..EncodePositionOptions::default()
        },
        ..EncodeObjectOptions::default()
    };
    let body = encode_object("FRAP", 51.5, -3.0, &options).unwrap();
    let packet = parse(format!("2W0FWJ>APRS:{body}")).unwrap();
    assert_eq!(packet.object_name(), Some("FRAP"));
    assert_eq!(packet.alive(), Some(true));
    assert_eq!(packet.raw_timestamp(), Some("010124z"));
    assert_eq!(packet.comment(), Some("Test object"));
}

#[test]
fn compressed_positions_reject_incompatible_precision_options() {
    let options = EncodePositionOptions {
        compressed: true,
        ambiguity: 1,
        ..EncodePositionOptions::default()
    };
    assert!(encode_position(51.5, -3.0, None, None, None, "//", &options).is_err());
}

#[test]
fn an_empty_symbol_uses_the_fap_default() {
    let body = encode_position(
        51.5,
        -3.0,
        None,
        None,
        None,
        "",
        &EncodePositionOptions::default(),
    )
    .unwrap();
    let packet = parse(format!("2W0FWJ>APRS:{body}")).unwrap();
    assert_eq!(
        (packet.symbol_table(), packet.symbol_code()),
        (Some('/'), Some('/'))
    );
}
