use std::borrow::Cow;

use frap::{
    EncodePositionOptions, ErrorCode, Format, Message, PacketBody, PacketType, ParseOptions,
    aprs_passcode, check_ax25_call, direction, distance, encode_message, encode_position, parse,
    parse_ref, parse_with_options,
};

#[test]
fn borrowed_parser_reuses_ascii_input_and_converts_to_owned() {
    let raw = b"2W0FWJ-2>APRS,WIDE1-1,WIDE2-1:!6128.23N/02353.52E-Testing";
    let packet = parse_ref(raw).unwrap();

    assert!(matches!(packet.original, Cow::Borrowed(_)));
    assert!(matches!(packet.header, Cow::Borrowed(_)));
    assert!(matches!(packet.information, Cow::Borrowed(_)));
    assert!(matches!(packet.source, Cow::Borrowed("2W0FWJ-2")));
    assert!(matches!(packet.destination, Cow::Borrowed("APRS")));
    assert!(
        packet
            .digipeaters
            .iter()
            .all(|digipeater| matches!(digipeater.call, Cow::Borrowed(_)))
    );
    assert_eq!(packet.into_owned(), parse(raw).unwrap());
}

#[test]
fn borrowed_parser_owns_only_fields_that_require_normalization() {
    let packet = parse_ref(b"2w0fwj>aprs:>status").unwrap();

    assert!(matches!(packet.source, Cow::Borrowed("2w0fwj")));
    assert!(matches!(packet.destination, Cow::Owned(ref value) if value == "APRS"));
}

#[test]
fn stores_type_safe_packet_bodies() {
    let packet = parse("2W0FWJ>APRS:;TEST     *120102h5120.00N/00300.00W>object").unwrap();
    match packet.packet_body() {
        PacketBody::Object {
            name,
            alive,
            position,
            ..
        } => {
            assert_eq!(name, "TEST");
            assert!(alive);
            assert_eq!(position.latitude, 51.0 + 20.0 / 60.0);
            assert_eq!(position.comment.as_deref(), Some("object"));
        }
        body => panic!("unexpected body: {body:?}"),
    }

    let packet = parse_ref(b"2W0FWJ>APRS::N0CALL   :hello{42").unwrap();
    match packet.packet_body() {
        PacketBody::Message(message) => {
            assert_eq!(message.destination, "N0CALL");
            assert_eq!(message.id.as_deref(), Some("42"));
        }
        body => panic!("unexpected body: {body:?}"),
    }
}

#[test]
fn parses_uncompressed_position_and_path() {
    let packet =
        parse("2W0FWJ-2>APRS,WIDE1-1,WIDE2-1,qAo,2W0FWJ:!6128.23N/02353.52E-PHG2360/Testing")
            .unwrap();
    assert_eq!(packet.source, "2W0FWJ-2");
    assert_eq!(packet.destination, "APRS");
    assert_eq!(packet.packet_type(), Some(PacketType::Location));
    assert_eq!(packet.format(), Some(Format::Uncompressed));
    assert!((packet.latitude().unwrap() - 61.4705).abs() < 1e-8);
    assert!((packet.longitude().unwrap() - 23.892).abs() < 1e-8);
    assert_eq!(packet.symbol_code(), Some('-'));
    assert_eq!(packet.digipeaters.len(), 4);
}

#[test]
fn parses_compressed_position() {
    let packet = parse("N0CALL>APRS:!/5L!!<*e7>7P[Test").unwrap();
    assert_eq!(packet.format(), Some(Format::Compressed));
    assert!(packet.latitude().unwrap().is_finite());
    assert!(packet.longitude().unwrap().is_finite());
}

#[test]
fn normalizes_compressed_numeric_symbol_overlays() {
    let packet = parse("N0CALL>APRS:!b8^@*:t(l#  !").unwrap();
    assert_eq!(packet.symbol_table(), Some('1'));
}

#[test]
fn parses_altitude_from_a_compressed_position_comment() {
    let packet = parse("N0CALL>APRS:!/8Z_H2u_I>kVH/A=005896Test").unwrap();
    assert!((packet.altitude_m().unwrap() - 1_797.100_8).abs() < 0.0001);
    assert_eq!(packet.comment(), Some("Test"));
}

#[test]
fn parses_altitude_after_phg_data() {
    let packet = parse("N0CALL>APRS:!4731.09NI00744.05E&PHG2040/A=001181Test").unwrap();
    assert_eq!(packet.phg(), Some("2040"));
    assert!((packet.altitude_m().unwrap() - 359.968_8).abs() < 0.0001);
    assert_eq!(packet.comment(), Some("Test"));
}

#[test]
fn parses_messages_and_reply_ack() {
    let packet = parse("N0CALL>APRS::2W0FWJ-2 :Hello world{42}7").unwrap();
    let message = packet.message().unwrap();
    assert_eq!(message.destination, "2W0FWJ-2");
    assert_eq!(message.text, "Hello world");
    assert_eq!(message.id.as_deref(), Some("42"));
    assert_eq!(message.acknowledgement_id.as_deref(), Some("7"));
}

#[test]
fn distinguishes_control_responses_from_messages_starting_with_ack() {
    let packet = parse("2W0FWJ>APRS::N0CALL   :ack 3{07").unwrap();
    let message = packet.message().unwrap();
    assert_eq!(message.text, "ack 3");
    assert_eq!(message.id.as_deref(), Some("07"));
    assert_eq!(message.acknowledgement_id, None);

    let packet = parse("2W0FWJ>APRS::N0CALL   :ack12   ").unwrap();
    let message = packet.message().unwrap();
    assert_eq!(message.acknowledgement_id.as_deref(), Some("12"));
    assert_eq!(message.text, "");

    let packet = parse("2W0FWJ>APRS::N0CALL   :ack").unwrap();
    assert_eq!(packet.message().unwrap().text, "ack");
}

#[test]
fn ordinary_message_ids_do_not_create_empty_reply_acks() {
    let packet = parse("2W0FWJ>APRS::N0CALL   :hello{42}").unwrap();
    let message = packet.message().unwrap();

    assert_eq!(message.text, "hello");
    assert_eq!(message.id.as_deref(), Some("42"));
    assert_eq!(message.acknowledgement_id, None);
}

#[test]
fn validates_ax25_calls_and_paths() {
    assert_eq!(check_ax25_call("2w0fwj-2").as_deref(), Some("2W0FWJ-2"));
    assert!(check_ax25_call("N0CALL-16").is_none());
    assert!(
        parse_with_options(
            "N0CALL>APRS,A,B,C,D,E,F,G,H,I:>status",
            ParseOptions {
                strict_ax25: true,
                ..ParseOptions::default()
            },
        )
        .is_err()
    );
}

#[test]
fn parses_capabilities() {
    let packet = parse("N0CALL>APRS:<IGATE,MSG_CNT=12,LOC").unwrap();
    assert_eq!(packet.packet_type(), Some(PacketType::Capabilities));
    assert_eq!(packet.capabilities().unwrap()["MSG_CNT"], "12");
    assert_eq!(packet.capabilities().unwrap()["IGATE"], "");
}

#[test]
fn parses_mice_position_and_altitude() {
    let packet = parse("2W0FWJ-2>TQ4W2V,WIDE2-1,qAo,2W0FWJ:`c51!f?>/]\"3x}=").unwrap();
    assert_eq!(packet.format(), Some(Format::MicE));
    assert!((packet.latitude().unwrap() - 41.7877).abs() < 0.0001);
    assert!((packet.longitude().unwrap() + 71.4202).abs() < 0.0001);
    assert_eq!(packet.course_deg(), Some(35));
    assert_eq!(packet.altitude_m(), Some(6.0));
    assert_eq!(packet.mice_message_bits(), Some("110"));
}

#[test]
fn legacy_mice_telemetry_has_no_sequence() {
    let packet = parse("2W0FWJ-2>TQ4W2V,WIDE2-1,qAo,2W0FWJ:`c51!f?>/'A1B2").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.sequence, None);
    assert_eq!(telemetry.values[0], Some(161.0));
    assert_eq!(telemetry.values[1], Some(0.0));
    assert_eq!(telemetry.values[2], Some(178.0));
}

#[test]
fn repairs_the_known_mice_space_collapse() {
    let packet = parse_with_options(
        "KD0KZE>TUPX9R,RS0ISS*,qAR,K0GDI-6:'yaIl -/]Greetings via ISS=",
        ParseOptions {
            accept_broken_mice: true,
            ..ParseOptions::default()
        },
    )
    .unwrap();
    assert!(packet.mice_mangled());
    assert_eq!(packet.speed_kmh(), None);
    assert_eq!(packet.course_deg(), None);
    assert_eq!(packet.comment(), Some("]Greetings via ISS="));
    assert!((packet.latitude().unwrap() - 45.1487).abs() < 0.0001);
}

#[test]
fn decodes_aprs_timestamp() {
    let packet = parse("N0CALL>APRS:/120102h6128.23N/02353.52E-Test").unwrap();
    let timestamp = packet.timestamp().unwrap();
    assert_eq!(
        (timestamp.hour, timestamp.minute, timestamp.second),
        (12, 1, 2)
    );
}

#[test]
fn parses_nmea_and_checksum() {
    let packet =
        parse("N0CALL>GPS:$GPRMC,092204.999,A,4250.5589,N,14718.5084,E,0.02,31.66,280511,,,A*55")
            .unwrap();
    assert_eq!(packet.format(), Some(Format::Nmea));
    assert_eq!(packet.nmea_checksum_ok(), Some(true));
    assert!((packet.latitude().unwrap() - 42.842648).abs() < 0.00001);
}

#[test]
fn accepts_fap_compatible_variable_width_nmea_degrees() {
    let packet =
        parse("N0CALL>GPS:$GPGGA,200124.00,5341.150,N,1001.850,E,1,3,0.0,10.0,M,,M,,*4f").unwrap();
    assert!((packet.latitude().unwrap() - (53.0 + 41.150 / 60.0)).abs() < 1e-8);
    assert!((packet.longitude().unwrap() - (10.0 + 1.850 / 60.0)).abs() < 1e-8);
}

#[test]
fn derives_nmea_symbols_from_the_destination() {
    let encoded = parse("N0CALL>GPSMV:$GPGLL,5341.150,N,01001.850,E").unwrap();
    assert_eq!(
        (encoded.symbol_table(), encoded.symbol_code()),
        (Some('/'), Some('>'))
    );

    let fallback = parse("N0CALL>APRS:$GPGLL,5341.150,N,01001.850,E").unwrap();
    assert_eq!(
        (fallback.symbol_table(), fallback.symbol_code()),
        (Some('/'), Some('/'))
    );
}

#[test]
fn centers_mice_position_ambiguity_like_fap() {
    let packet = parse("N0CALL>SU12LZ:`qX\x1cmA!>/").unwrap();
    assert_eq!(packet.position_ambiguity(), Some(2));
    assert_eq!(packet.position_resolution_m(), Some(1_852.0));
}

#[test]
fn parses_telemetry_and_weather() {
    let telemetry = parse("N0CALL>APRS:T#005,1.0,,3,-4.5,5,10101010").unwrap();
    assert_eq!(telemetry.packet_type(), Some(PacketType::Telemetry));
    assert_eq!(telemetry.telemetry().unwrap().values[3], Some(-4.5));

    let weather = parse("N0CALL>APRS:_07251234c180s010g020t068h50b10132").unwrap();
    assert_eq!(weather.packet_type(), Some(PacketType::Weather));
    assert_eq!(weather.weather().unwrap().humidity_percent, Some(50));
}

#[test]
fn defaults_empty_telemetry_channels_and_pads_bits_like_fap() {
    let packet = parse("2W0FWJ>APRS:T#176,250,053,000,048,,1111,station").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.values[4], Some(0.0));
    assert_eq!(telemetry.bits.as_deref(), Some("11110000"));

    let packet = parse("2W0FWJ>APRS:T#001,52,287,2947,370,0,00000009").unwrap();
    assert_eq!(
        packet.telemetry().unwrap().bits.as_deref(),
        Some("00000000")
    );
}

#[test]
fn warns_when_preserving_partial_telemetry() {
    let packet = parse("2W0FWJ>APRS:T#558,151,000,246,000,164").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.values[4], Some(164.0));
    assert!(
        packet
            .warnings
            .iter()
            .any(|warning| warning.code == ErrorCode::TelemetryInvalid)
    );

    let packet = parse("2W0FWJ>APRS:T#480,240,13.18}},18.5,72.8,42.2,00000000").unwrap();
    assert_eq!(packet.telemetry().unwrap().values[0], Some(240.0));
    assert!(
        packet
            .warnings
            .iter()
            .any(|warning| warning.code == ErrorCode::TelemetryInvalid)
    );
}

#[test]
fn warns_when_preserving_large_telemetry_values() {
    let packet = parse("2W0FWJ>APRS:T#893,2975022.00,0.01,0,1,0.0,00000000,TetraLogic").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.values[0], Some(2_975_022.0));
    assert!(
        packet
            .warnings
            .iter()
            .any(|warning| warning.code == ErrorCode::TelemetryTooLarge)
    );
    assert_eq!(ErrorCode::TelemetryTooLarge.as_str(), "tlm_large");
}

#[test]
fn parses_inline_base91_telemetry_from_position_comments() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W>station|'U!!!!|").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.sequence, Some(598));
    assert_eq!(telemetry.values[0], Some(0.0));
    assert_eq!(packet.comment(), Some("station"));
}

#[test]
fn finds_telemetry_before_a_later_pipe_delimited_extension() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W>station|!$&='5|!wQK!|").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.sequence, Some(3));
    assert_eq!(packet.comment(), Some("station|"));
}

#[test]
fn treats_pipe_delimited_base91_text_as_telemetry() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W>APRS|Digi|IGate").unwrap();
    let telemetry = packet.telemetry().unwrap();

    assert_eq!(telemetry.sequence, Some(3257));
    assert_eq!(telemetry.values[0], Some(6442.0));
    assert_eq!(packet.comment(), Some("APRSIGate"));
}

#[test]
fn parses_three_digit_weather_humidity_and_signed_temperature() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_t-999h100b10140").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.humidity_percent, Some(100));
    assert_eq!(weather.temperature_c, Some((-999.0 - 32.0) * 5.0 / 9.0));
    assert_eq!(weather.pressure_mbar, Some(1014.0));
}

#[test]
fn accepts_fap_compatible_four_digit_weather_temperature() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_.../...g...t0071r...p...P...h49b.....").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.temperature_c, Some((71.0 - 32.0) * 5.0 / 9.0));
    assert_eq!(weather.humidity_percent, Some(49));
}

#[test]
fn accepts_fap_compatible_short_weather_fields() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_000/000g000t83h39b9970").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.temperature_c, Some((83.0 - 32.0) * 5.0 / 9.0));
    assert_eq!(weather.humidity_percent, Some(39));
    assert_eq!(weather.pressure_mbar, Some(997.0));
}

#[test]
fn finds_weather_fields_after_malformed_tokens_like_fap() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_000/000g000t081r-3439p000P000h44b10092L000 station")
            .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.pressure_mbar, Some(1009.2));
    assert_eq!(weather.humidity_percent, Some(44));
    assert_eq!(weather.luminosity_wm2, Some(0));
    assert_eq!(packet.comment(), Some("r-3439 station"));
}

#[test]
fn rounds_ultimeter_direction_and_humidity_like_fap() {
    let packet = parse(concat!(
        "2W0FWJ>APRS:$ULTW",
        "0000",
        "00D9",
        "0000",
        "0000",
        "0000",
        "0000",
        "0000",
        "0000",
        "01C7",
        "0000",
        "0000",
        "0000",
        "0000",
    ))
    .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_direction_deg, Some(306.0));
    assert_eq!(weather.humidity_percent, Some(46));
}

#[test]
fn keeps_weather_wind_speed_separate_from_snowfall() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_206/001g003t085r000p000P000h73b10117s012").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_direction_deg, Some(206.0));
    assert_eq!(weather.wind_speed_ms, Some(0.44704));
    assert_eq!(weather.snow_24h_mm, Some(3.048));

    let alternate = parse("2W0FWJ>APRS:!5120.00N/00300.00W_c206s001g003t085").unwrap();
    let weather = alternate.weather().unwrap();
    assert_eq!(weather.wind_direction_deg, Some(206.0));
    assert_eq!(weather.wind_speed_ms, Some(0.44704));
}

#[test]
fn accepts_a_repeated_weather_symbol_before_wind_data() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W__360/002g...t057b10130").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_direction_deg, Some(360.0));
    assert_eq!(weather.wind_speed_ms, Some(2.0 * 0.44704));
    assert_eq!(weather.temperature_c, Some((57.0 - 32.0) * 5.0 / 9.0));

    let alternate = parse("2W0FWJ>APRS:!5120.00N/00300.00W__c000s000g000t077").unwrap();
    let weather = alternate.weather().unwrap();
    assert_eq!(weather.wind_direction_deg, Some(0.0));
    assert_eq!(weather.wind_speed_ms, Some(0.0));
}

#[test]
fn preserves_partial_weather_wind_readings() {
    let direction_only = parse("2W0FWJ>APRS:!5120.00N/00300.00W_247/...g...t...").unwrap();
    let weather = direction_only.weather().unwrap();
    assert_eq!(weather.wind_direction_deg, Some(247.0));
    assert_eq!(weather.wind_speed_ms, None);

    let speed_only = parse("2W0FWJ>APRS:!5120.00N/00300.00W_.../002g...t...").unwrap();
    let weather = speed_only.weather().unwrap();
    assert_eq!(weather.wind_direction_deg, None);
    assert_eq!(weather.wind_speed_ms, Some(2.0 * 0.44704));
}

#[test]
fn keeps_weather_field_lookalikes_in_software_identifiers() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_188/001g003t064r000p000P000h74b10150L152eTMP1")
            .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.rain_since_midnight_mm, Some(0.0));
    assert_eq!(weather.software.as_deref(), Some("eTMP1"));
    assert_eq!(packet.comment(), None);
}

#[test]
fn does_not_parse_short_pressure_lookalikes_in_weather_comments() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_073/...g003t079h67station b9 test").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.pressure_mbar, None);
    assert_eq!(packet.comment(), Some("station b9 test"));

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_000/000g000t083b9970").unwrap();
    assert_eq!(packet.weather().unwrap().pressure_mbar, Some(997.0));
}

#[test]
fn does_not_parse_humidity_from_callsigns_or_hostnames() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_ www.dh5dy.de").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.humidity_percent, None);
    assert_eq!(packet.comment(), Some("www.dh5dy.de"));
}

#[test]
fn does_not_parse_gusts_from_callsigns_or_hostnames() {
    let packet = parse(
        "2W0FWJ>APRS:!5120.00N/00300.00W_.../...g...t072h99b10051 http://mtg3.eu /g8wvw /g1gmy",
    )
    .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_gust_ms, None);
    assert_eq!(packet.comment(), Some("http://mtg3.eu /g8wvw /g1gmy"));

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_g4t084").unwrap();
    assert_eq!(packet.weather().unwrap().wind_gust_ms, Some(4.0 * 0.44704));
}

#[test]
fn does_not_parse_wind_direction_from_dates_in_comments() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_.../...g...t083h66b10129 28Dec2025").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_direction_deg, None);
    assert_eq!(packet.comment(), Some("28Dec2025"));
}

#[test]
fn does_not_parse_snowfall_from_names_or_alternate_wind_speed() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_WX3in1Plus2.0 ks5s").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.snow_24h_mm, None);
    assert_eq!(packet.comment(), Some("WX3in1Plus2.0 ks5s"));

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_215/003 c215s004g...t069").unwrap();
    let weather = packet.weather().unwrap();
    assert_eq!(weather.wind_speed_ms, Some(3.0 * 0.44704));
    assert_eq!(weather.snow_24h_mm, None);

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_s012").unwrap();
    assert_eq!(packet.weather().unwrap().snow_24h_mm, Some(12.0 * 0.254));
}

#[test]
fn does_not_parse_luminosity_from_short_or_embedded_fields() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_PL100 DL6MM !L7").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.luminosity_wm2, None);
    assert_eq!(packet.comment(), Some("PL100 DL6MM !L7"));

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_L152").unwrap();
    assert_eq!(packet.weather().unwrap().luminosity_wm2, Some(152));
}

#[test]
fn stops_weather_fields_before_free_form_comments() {
    let packet = parse(
        "2W0FWJ>APRS:!5120.00N/00300.00W_057/005g006t070r000p000h69b10110Python APRS WX10 / Temp 22.0V",
    )
    .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.radiation_nsvh, None);
    assert_eq!(weather.battery_voltage, None);
    assert_eq!(packet.comment(), Some("Python APRS WX10 / Temp 22.0V"));

    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_300/005t059h72b10110 METAR 270V330 9999").unwrap();
    assert_eq!(packet.weather().unwrap().battery_voltage, None);
    assert_eq!(packet.comment(), Some("METAR 270V330 9999"));

    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991LRE.js V50000 C6/8")
            .unwrap();
    assert_eq!(packet.weather().unwrap().battery_voltage, None);
    assert_eq!(packet.comment(), Some("LRE.js V50000 C6/8"));

    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058V135").unwrap();
    assert_eq!(packet.weather().unwrap().battery_voltage, Some(13.5));
}

#[test]
fn does_not_consume_short_rain_placeholder_in_words() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_ APRMAP V8.08.0").unwrap();

    assert_eq!(packet.comment(), Some("APRMAP V8.08.0"));
}

#[test]
fn preserves_weather_field_letters_at_the_end_of_comment_words() {
    for comment in [
        "LoRa Igate with Wx BME280 sensor ",
        "LoRa UHF Forbordfjell ",
        "Netatmo Leipzig 124m ASL ",
        "APRS WX ARGENTINA LINK / Clima en Buenos Aires: nubes",
        "WX3in1+ Davis Vantage Vue",
        "LoRa APRS- SARIMESH- Lupus Hirpinus",
        "It's always sunny",
        "Up:5d2h27m26s Alt:1212m",
        "Gas: 86.02Kohms     144.975",
    ] {
        let raw = format!("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991{comment}");
        let packet = parse(&raw).unwrap();
        assert_eq!(packet.comment(), Some(comment.trim_end()));
    }
}

#[test]
fn applies_fap_legacy_weather_comment_cleanup() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991v1230  WX station #456")
            .unwrap();

    assert_eq!(packet.comment(), Some("WX station"));
}

#[test]
fn weather_cleanup_does_not_consume_inline_telemetry() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991|v12!|station").unwrap();

    assert!(packet.telemetry().is_some());
    assert_eq!(packet.comment(), Some("station"));
}

#[test]
fn weather_scanning_preserves_nonleading_placeholders_in_comments() {
    for comment in [
        "1297 m.s.l.m.",
        "F4FEB/P WX",
        "U...L...PiArdWx",
        "tnanr...p...P...b.....station",
    ] {
        let raw = format!("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991{comment}");
        let packet = parse(&raw).unwrap();
        assert_eq!(packet.comment(), Some(comment));
    }
}

#[test]
fn weather_placeholder_cleanup_absorbs_its_separator_slack() {
    let packet = parse(
        "2W0FWJ>APRS:!5120.00N/00300.00W_000/000g000t072r000p...P000h55b10033L000.Ecowitt WS69",
    )
    .unwrap();

    assert_eq!(packet.comment(), Some("Ecowitt WS69"));
}

#[test]
fn initial_gust_placeholder_does_not_absorb_a_comment_separator() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_000/000g...t077r000p000P000b10065h44.weewx")
            .unwrap();

    assert_eq!(packet.comment(), Some(".weewx"));
}

#[test]
fn initial_weather_temperature_consumes_fap_compatible_mixed_fragments() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_.../...g...t075.7h73b10074WXNET-ESP").unwrap();

    assert_eq!(packet.weather().as_ref().unwrap().temperature_c, None);
    assert_eq!(packet.comment(), Some("WXNET-ESP"));
}

#[test]
fn weather_cleanup_consumes_a_leading_raw_counter_placeholder() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991# t = 24.7").unwrap();

    assert_eq!(packet.comment(), Some("t = 24.7"));
}

#[test]
fn consumes_complete_weather_placeholders() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_.../...g...t...r...p...P...h..b..... station")
            .unwrap();

    assert_eq!(packet.comment(), Some("station"));
}

#[test]
fn recognizes_dot_delimited_weather_software_identifiers() {
    let packet =
        parse("2W0FWJ>APRS:!5120.00N/00300.00W_188/001g003t064r000p000P000h74b10150L....DsIP")
            .unwrap();
    assert_eq!(packet.weather().unwrap().software.as_deref(), Some("DsIP"));
}

#[test]
fn accepts_variable_width_weather_gusts_like_fap() {
    let packet = parse("2W0FWJ>APRS:!5120.00N/00300.00W_000/000g1403t069h57").unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.wind_gust_ms, Some(1403.0 * 0.44704));
    assert_eq!(weather.temperature_c, Some((69.0 - 32.0) * 5.0 / 9.0));
}

#[test]
fn ultimeter_humidity_uses_ties_to_even_rounding() {
    let packet = parse(concat!(
        "2W0FWJ>APRS:!!",
        "0000",
        "0000",
        "0000",
        "0000",
        "0000",
        "0000",
        "00E1",
        "01F9",
        "0000",
        "0000",
        "0000",
        "0000",
        "0000",
    ))
    .unwrap();
    let weather = packet.weather().unwrap();

    assert_eq!(weather.humidity_percent, Some(22));
    assert_eq!(weather.indoor_humidity_percent, Some(50));
}

#[test]
fn parses_partial_course_speed_extensions_like_fap() {
    let packet = parse("N0CALL>APRS:!0234.19S/14041.46E(.../012Test").unwrap();
    assert_eq!(packet.course_deg(), Some(0));
    assert_eq!(packet.speed_kmh(), Some(12.0 * 1.852));
}

#[test]
fn parses_position_extensions() {
    let packet = parse("N0CALL>APRS:!6128.23N/02353.52E>180/024/A=000394Test!wAA!").unwrap();
    assert_eq!(packet.course_deg(), Some(180));
    assert!((packet.speed_kmh().unwrap() - 44.448).abs() < 1e-6);
    assert!((packet.altitude_m().unwrap() - 120.0912).abs() < 1e-4);
    assert_eq!(packet.dao_datum(), Some('W'));
    assert_eq!(packet.comment(), Some("Test"));
}

#[test]
fn uses_the_last_valid_dao_candidate_like_fap() {
    let packet = parse("N0CALL>APRS:!3754.96N/08107.46W$aprs.fi for iOS !SN!!wkj!").unwrap();
    assert_eq!(packet.dao_datum(), Some('W'));
    assert_eq!(packet.comment(), Some("aprs.fi for iOS !SN!"));
}

#[test]
fn does_not_parse_dao_patterns_inside_inline_telemetry() {
    let packet = parse("N0CALL>APRS:!4101.43NI07408.26W#Solar digi |!d\"s!g!+#j!`!\"|").unwrap();
    assert_eq!(packet.dao_datum(), None);
    assert!((packet.latitude().unwrap() - (41.0 + 1.43 / 60.0)).abs() < 1e-8);
    assert!((packet.longitude().unwrap() - (-74.0 - 8.26 / 60.0)).abs() < 1e-8);
}

#[test]
fn positioned_weather_keeps_its_enclosing_object_or_item_type() {
    let object = parse("N0CALL>APRS:;WEATHER  *251200z6128.23N/02353.52E_180/010g020t050").unwrap();
    assert_eq!(object.packet_type(), Some(PacketType::Object));
    assert!(object.weather().is_some());

    let item = parse("N0CALL>APRS:)WEATHER!6128.23N/02353.52E_180/010g020t050").unwrap();
    assert_eq!(item.packet_type(), Some(PacketType::Item));
    assert!(item.weather().is_some());
}

#[test]
fn accepts_fap_compatible_lowercase_hemispheres() {
    let packet = parse("N0CALL>APRS:!2952.51n/09653.75w#").unwrap();
    assert!(packet.latitude().unwrap() > 0.0);
    assert!(packet.longitude().unwrap() < 0.0);
}

#[test]
fn applies_latitude_ambiguity_to_longitude_precision() {
    let packet = parse("N0CALL>APRS:!4424.4 N/10017.85W#").unwrap();
    assert_eq!(packet.position_ambiguity(), Some(1));
    assert!((packet.latitude().unwrap() - (44.0 + 24.45 / 60.0)).abs() < 1e-8);
    assert!((packet.longitude().unwrap() - (-100.0 - 17.85 / 60.0)).abs() < 1e-8);

    let packet = parse("N0CALL>APRS:!4156.  N/08617.22W#").unwrap();
    assert_eq!(packet.position_ambiguity(), Some(2));
    assert!((packet.longitude().unwrap() - (-86.0 - 17.5 / 60.0)).abs() < 1e-8);
}

#[test]
fn accepts_minimum_length_compressed_object() {
    let packet = parse("N0CALL>APRS:;SHNC     *000000z/8><_1Z7W>!!E").unwrap();
    assert_eq!(packet.packet_type(), Some(PacketType::Object));
    assert_eq!(packet.object_name(), Some("SHNC"));
}

#[test]
fn encodes_messages_and_positions() {
    let message = Message {
        destination: "N0CALL".into(),
        text: "Hello".into(),
        id: Some("42".into()),
        ..Message::default()
    };
    assert_eq!(encode_message(&message).unwrap(), ":N0CALL   :Hello{42");
    let encoded = encode_position(
        60.4525,
        24.9842,
        Some(45.0),
        Some(180.0),
        Some(120.0),
        "/>",
        &EncodePositionOptions::default(),
    )
    .unwrap();
    assert!(encoded.starts_with("!6027.15N/02459.05E>180/024/A=000394"));
    assert!(parse(format!("N0CALL>APRS:{encoded}")).is_ok());
}

#[test]
fn utility_functions_and_passcode_match_fap() {
    assert_eq!(aprs_passcode("N0CALL"), 13023);
    assert!((distance(60.0, 24.0, 61.0, 25.0) - 123.9).abs() < 1.0);
    assert!((0.0..360.0).contains(&direction(60.0, 24.0, 61.0, 25.0)));
}

#[test]
fn accepts_utf8_and_preserves_exact_packet_bytes() {
    let raw = "N0CALL>APRS:>晴れ ☀";
    let packet = parse(raw).unwrap();

    assert_eq!(packet.original_bytes, raw.as_bytes());
    assert_eq!(packet.original, raw);
    assert_eq!(packet.packet_type(), Some(PacketType::Status));
    assert_eq!(packet.status(), Some("?????? ???"));
}

#[test]
fn accepts_non_utf8_payload_and_preserves_exact_packet_bytes() {
    let raw = b"N0CALL>APRS:>binary \x81 status";
    let packet = parse(raw).unwrap();

    assert_eq!(packet.original_bytes, raw);
    assert_eq!(packet.original, "N0CALL>APRS:>binary \u{fffd} status");
    assert_eq!(packet.status(), Some("binary ? status"));
}

#[test]
fn removes_ascii_control_bytes_from_position_comments() {
    let raw = b"2W0FWJ>APRS:!5120.00N/00300.00W-Test\0comment\x03";
    let packet = parse(raw).unwrap();

    assert_eq!(packet.original_bytes, raw);
    assert_eq!(packet.comment(), Some("Testcomment"));
}

#[test]
fn removes_ff_bytes_from_comments_but_preserves_the_ascii_parser_view() {
    let raw = b"2W0FWJ>APRS:!5120.00N/00300.00W-Test\xff\xffcomment";
    let packet = parse(raw).unwrap();

    assert_eq!(packet.original_bytes, raw);
    assert!(packet.information.ends_with("Test??comment"));
    assert_eq!(packet.comment(), Some("Testcomment"));
}

#[test]
fn normalizes_weather_comment_tabs_without_changing_the_ascii_view() {
    let raw = b"2W0FWJ>APRS:!5120.00N/00300.00W_175/005g009t058h82b09991Test\x7fcomment\ttext";
    let packet = parse(raw).unwrap();

    assert_eq!(packet.original_bytes, raw);
    assert_eq!(packet.comment(), Some("Test?comment text"));
}

#[test]
fn non_ascii_replacements_do_not_change_position_extensions() {
    let compressed =
        b"EA3IK-5>APLRFD,ED3YAB-7*,qAR,EA3IK-3:!L9NI0Ny%T#  GLoRa APRS Digi|&6!o\"n!\xa2E!;|?";
    let packet = parse(compressed).unwrap();
    assert!((packet.latitude().unwrap() - 41.533_885_052_914_9).abs() < 1e-12);
    assert!((packet.longitude().unwrap() - 1.871_885_143_921_22).abs() < 1e-12);

    let mice =
        b"KN6PHW>S4QVU9,K6ERN,KF6ILA-10,WIDE2*,qAR,W6ZU-10:`/azl `>/'\"4R}|)\\%@'\xde}!wU\xa3!|3";
    let packet = parse(mice).unwrap();
    assert!((packet.latitude().unwrap() - 34.2765).abs() < 1e-12);
    assert!((packet.longitude().unwrap() - 119.165_666_666_667).abs() < 1e-12);
}

#[test]
fn rejects_non_ascii_bytes_in_structural_header_fields() {
    let error = parse(b"N0\xffCALL>APRS:>status").unwrap_err();
    assert_eq!(error.code.as_str(), "srccall_badchars");
}
