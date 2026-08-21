use frap::{PacketType, distance, parse};
use std::{
    collections::BTreeMap,
    env,
    fmt::Write as _,
    fs::{self, File, create_dir_all},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Default)]
struct Comparison {
    total: u64,
    both_pass: u64,
    both_fail: u64,
    frap_only: u64,
    fap_only: u64,
    non_utf8: u64,
    type_mismatches: u64,
    position_presence_mismatches: u64,
    position_value_mismatches: u64,
    position_distances_m: Vec<f64>,
    frap_only_fields: BTreeMap<String, u64>,
    fap_only_fields: BTreeMap<String, u64>,
    field_value_mismatches: BTreeMap<String, u64>,
    intentional_field_differences: BTreeMap<String, u64>,
    comment_deltas: BTreeMap<(String, String), u64>,
    type_mismatch_pairs: BTreeMap<String, u64>,
    frap_errors: BTreeMap<String, u64>,
    fap_errors: BTreeMap<String, u64>,
    frap_only_by_fap_error: BTreeMap<String, u64>,
    fap_only_by_frap_error: BTreeMap<String, u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut arguments = env::args_os().skip(1).peekable();
    let libfap = arguments
        .next_if(|argument| argument == "--libfap")
        .is_some();
    let corpus_path = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("test-data/real-world-1m.tnc2"));
    let (reference_name, output_dir, mut child) = if libfap {
        let runner = root.join("target/libfap/libfap-outcomes");
        if !runner.is_file() {
            return Err("run scripts/bootstrap-libfap first".into());
        }
        (
            "libfap",
            root.join("target/libfap-diff"),
            Command::new(runner)
                .arg(&corpus_path)
                .stdout(Stdio::piped())
                .spawn()?,
        )
    } else {
        let perl_root = root.join("target/perl-fap");
        if !perl_root.join("Ham/APRS/FAP.pm").is_file() {
            return Err("run scripts/bootstrap-perl-fap first".into());
        }
        (
            "Perl FAP",
            root.join("target/fap-diff"),
            Command::new("perl")
                .arg(format!("-I{}", perl_root.display()))
                .arg(root.join("tools/perl-fap-outcomes.pl"))
                .arg(&corpus_path)
                .stdout(Stdio::piped())
                .spawn()?,
        )
    };

    let corpus = BufReader::new(File::open(&corpus_path)?);
    let reference_stdout = child.stdout.take().expect("piped reference stdout");
    let reference = BufReader::new(reference_stdout);

    create_dir_all(&output_dir)?;
    let mut mismatches = BufWriter::new(File::create(output_dir.join("outcome-mismatches.tsv"))?);
    let mut position_mismatches =
        BufWriter::new(File::create(output_dir.join("position-mismatches.tsv"))?);
    let mut field_mismatches =
        BufWriter::new(File::create(output_dir.join("field-mismatches.tsv"))?);
    let mut intentional_differences = BufWriter::new(File::create(
        output_dir.join("intentional-differences.tsv"),
    )?);
    writeln!(
        mismatches,
        "line\tfrap_outcome\tfap_outcome\tfrap_error\tfap_error\tpacket_hex"
    )?;
    writeln!(
        position_mismatches,
        "line\tdistance_m\tfrap_latitude\tfrap_longitude\tfap_latitude\tfap_longitude\tpacket_hex"
    )?;
    writeln!(
        field_mismatches,
        "line\tfield\tmismatch_kind\tfrap_value\tfap_value\tpacket_hex"
    )?;
    writeln!(
        intentional_differences,
        "line\tfield\treason\tfrap_value\tfap_value\tpacket_hex"
    )?;

    let mut comparison = Comparison::default();
    let corpus_lines = corpus.split(b'\n');
    let mut reference_lines = reference.lines();
    for raw in corpus_lines {
        let raw = raw?;
        let fap_line = reference_lines
            .next()
            .ok_or_else(|| format!("{reference_name} produced fewer outcomes than the corpus"))??;
        comparison.total += 1;

        let fap = FapOutcome::parse(&fap_line)?;
        let frap = FrapOutcome::parse(&raw);
        if frap.non_utf8 {
            comparison.non_utf8 += 1;
        }
        if let Some(error) = frap.error.as_deref() {
            *comparison.frap_errors.entry(error.to_string()).or_default() += 1;
        }
        if let Some(error) = fap.error.as_deref() {
            *comparison.fap_errors.entry(error.to_string()).or_default() += 1;
        }

        match (frap.ok, fap.ok) {
            (true, true) => {
                comparison.both_pass += 1;
                if frap.packet_type != fap.packet_type {
                    comparison.type_mismatches += 1;
                    let pair = format!(
                        "{} -> {}",
                        frap.packet_type.as_deref().unwrap_or("(none)"),
                        fap.packet_type.as_deref().unwrap_or("(none)")
                    );
                    *comparison.type_mismatch_pairs.entry(pair).or_default() += 1;
                }
                match compare_positions(frap.position, fap.position) {
                    PositionComparison::Same => {}
                    PositionComparison::Presence => comparison.position_presence_mismatches += 1,
                    PositionComparison::Value => {
                        comparison.position_value_mismatches += 1;
                        if let (Some(frap_position), Some(fap_position)) =
                            (frap.position, fap.position)
                        {
                            let distance_m = distance(
                                frap_position.0,
                                frap_position.1,
                                fap_position.0,
                                fap_position.1,
                            ) * 1_000.0;
                            comparison.position_distances_m.push(distance_m);
                            writeln!(
                                position_mismatches,
                                "{}\t{distance_m}\t{}\t{}\t{}\t{}\t{}",
                                comparison.total,
                                frap_position.0,
                                frap_position.1,
                                fap_position.0,
                                fap_position.1,
                                encode_hex(&raw),
                            )?;
                        }
                    }
                }
                compare_integer_field(
                    "symbol_table",
                    frap.symbol_table,
                    fap.symbol_table,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_integer_field(
                    "symbol_code",
                    frap.symbol_code,
                    fap.symbol_code,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_float_field(
                    "course",
                    frap.course,
                    fap.course,
                    0.001,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_float_field(
                    "speed",
                    frap.speed,
                    fap.speed,
                    0.001,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_float_field(
                    "altitude",
                    frap.altitude,
                    fap.altitude,
                    0.01,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_integer_field(
                    "position_ambiguity",
                    frap.position_ambiguity,
                    fap.position_ambiguity,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_integer_field(
                    "messaging",
                    frap.messaging,
                    fap.messaging,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_string_field(
                    "message_destination",
                    frap.message_destination.as_deref(),
                    fap.message_destination.as_deref(),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                let reply_ack_difference = frap.message_ack.is_some()
                    || fap
                        .message_id
                        .as_deref()
                        .is_some_and(|message_id| message_id.contains('}'));
                compare_or_record_intentional_string_field(
                    "message_text",
                    frap.message_text.as_deref(),
                    fap.message_text.as_deref(),
                    reply_ack_difference.then_some("aprs_1_1_reply_ack"),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                    &mut intentional_differences,
                )?;
                compare_or_record_intentional_string_field(
                    "message_id",
                    frap.message_id.as_deref(),
                    fap.message_id.as_deref(),
                    reply_ack_difference.then_some("aprs_1_1_reply_ack"),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                    &mut intentional_differences,
                )?;
                compare_string_field(
                    "message_ack",
                    frap.message_ack.as_deref(),
                    fap.message_ack.as_deref(),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_string_field(
                    "message_reject",
                    frap.message_reject.as_deref(),
                    fap.message_reject.as_deref(),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                compare_integer_field(
                    "telemetry_sequence",
                    frap.telemetry_sequence,
                    fap.telemetry_sequence,
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                for index in 0..5 {
                    compare_float_field(
                        &format!("telemetry_value_{}", index + 1),
                        frap.telemetry_values[index],
                        fap.telemetry_values[index],
                        0.01,
                        comparison.total,
                        &raw,
                        &mut comparison,
                        &mut field_mismatches,
                    )?;
                }
                compare_string_field(
                    "telemetry_bits",
                    frap.telemetry_bits.as_deref(),
                    fap.telemetry_bits.as_deref(),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                const WEATHER_NAMES: [&str; 13] = [
                    "weather_wind_direction",
                    "weather_wind_speed",
                    "weather_wind_gust",
                    "weather_temperature",
                    "weather_indoor_temperature",
                    "weather_humidity",
                    "weather_indoor_humidity",
                    "weather_pressure",
                    "weather_rain_1h",
                    "weather_rain_24h",
                    "weather_rain_midnight",
                    "weather_snow_24h",
                    "weather_luminosity",
                ];
                for (index, name) in WEATHER_NAMES.iter().enumerate() {
                    compare_float_field(
                        name,
                        frap.weather_values[index],
                        fap.weather_values[index],
                        0.11,
                        comparison.total,
                        &raw,
                        &mut comparison,
                        &mut field_mismatches,
                    )?;
                }
                compare_string_field(
                    "weather_software",
                    frap.weather_software.as_deref(),
                    fap.weather_software.as_deref(),
                    comparison.total,
                    &raw,
                    &mut comparison,
                    &mut field_mismatches,
                )?;
                const WEATHER_EXTENSION_NAMES: [&str; 3] = [
                    "weather_water_level",
                    "weather_radiation",
                    "weather_battery_voltage",
                ];
                for (index, name) in WEATHER_EXTENSION_NAMES.iter().enumerate() {
                    compare_float_field(
                        name,
                        frap.weather_extension_values[index],
                        None,
                        0.11,
                        comparison.total,
                        &raw,
                        &mut comparison,
                        &mut field_mismatches,
                    )?;
                }
                if frap.weather_present && fap.weather_present {
                    let intentional_reason =
                        if (frap.weather_extension_values.iter().any(Option::is_some)
                            || comments_differ_only_by_extension_placeholder(
                                frap.comment.as_deref(),
                                fap.comment.as_deref(),
                            ))
                            && frap.comment != fap.comment
                        {
                            Some("frap_weather_extension")
                        } else if comments_differ_only_by_inline_telemetry(
                            frap.comment.as_deref(),
                            fap.comment.as_deref(),
                        ) {
                            Some("positioned_weather_inline_telemetry")
                        } else if raw.contains(&0x7f) && frap.comment != fap.comment {
                            Some("ascii_parser_view_del")
                        } else if frap
                            .weather_values
                            .iter()
                            .zip(fap.weather_values.iter())
                            .any(|(frap, fap)| frap.is_some() && fap.is_none())
                            && frap.comment != fap.comment
                        {
                            Some("preserved_partial_weather_field")
                        } else {
                            None
                        };
                    compare_or_record_intentional_string_field(
                        "weather_comment",
                        frap.comment.as_deref(),
                        fap.comment.as_deref(),
                        intentional_reason,
                        comparison.total,
                        &raw,
                        &mut comparison,
                        &mut field_mismatches,
                        &mut intentional_differences,
                    )?;
                }
            }
            (false, false) => comparison.both_fail += 1,
            (true, false) => {
                comparison.frap_only += 1;
                *comparison
                    .frap_only_by_fap_error
                    .entry(fap.error.clone().unwrap_or_else(|| "(none)".to_string()))
                    .or_default() += 1;
            }
            (false, true) => {
                comparison.fap_only += 1;
                *comparison
                    .fap_only_by_frap_error
                    .entry(frap.error.clone().unwrap_or_else(|| "(none)".to_string()))
                    .or_default() += 1;
            }
        }

        if frap.ok != fap.ok {
            writeln!(
                mismatches,
                "{}\t{}\t{}\t{}\t{}\t{}",
                comparison.total,
                outcome_name(frap.ok),
                outcome_name(fap.ok),
                frap.error.as_deref().unwrap_or(""),
                fap.error.as_deref().unwrap_or(""),
                encode_hex(&raw),
            )?;
        }
    }
    if reference_lines.next().is_some() {
        return Err(format!("{reference_name} produced more outcomes than the corpus").into());
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("{reference_name} runner exited with {status}").into());
    }
    mismatches.flush()?;
    position_mismatches.flush()?;
    field_mismatches.flush()?;
    intentional_differences.flush()?;
    write_comment_delta_report(&output_dir, &comparison.comment_deltas)?;

    let summary = build_summary(&comparison, &output_dir, reference_name);
    print!("{summary}");
    let summary_path = output_dir.join("summary.txt");
    let temporary_summary_path = output_dir.join("summary.txt.tmp");
    fs::write(&temporary_summary_path, &summary)?;
    fs::rename(temporary_summary_path, summary_path)?;
    Ok(())
}

struct FrapOutcome {
    ok: bool,
    error: Option<String>,
    packet_type: Option<String>,
    position: Option<(f64, f64)>,
    symbol_table: Option<i64>,
    symbol_code: Option<i64>,
    course: Option<f64>,
    speed: Option<f64>,
    altitude: Option<f64>,
    position_ambiguity: Option<i64>,
    messaging: Option<i64>,
    message_destination: Option<String>,
    message_text: Option<String>,
    message_id: Option<String>,
    message_ack: Option<String>,
    message_reject: Option<String>,
    telemetry_sequence: Option<i64>,
    telemetry_values: [Option<f64>; 5],
    telemetry_bits: Option<String>,
    weather_values: [Option<f64>; 13],
    weather_extension_values: [Option<f64>; 3],
    weather_software: Option<String>,
    weather_present: bool,
    comment: Option<String>,
    non_utf8: bool,
}

impl FrapOutcome {
    fn parse(raw: &[u8]) -> Self {
        match parse(raw) {
            Ok(packet) => {
                let position = packet.latitude().zip(packet.longitude());
                let message = packet.message();
                let telemetry = packet.telemetry();
                let weather = packet.weather();
                Self {
                    ok: true,
                    error: None,
                    packet_type: packet
                        .packet_type()
                        .map(|packet_type| frap_packet_type(packet_type, position.is_some())),
                    position,
                    symbol_table: packet.symbol_table().map(|value| value as i64),
                    symbol_code: packet.symbol_code().map(|value| value as i64),
                    course: packet.course_deg().map(f64::from),
                    speed: packet.speed_kmh(),
                    altitude: packet.altitude_m(),
                    position_ambiguity: packet.position_ambiguity().map(i64::from),
                    messaging: packet.messaging().map(i64::from),
                    message_destination: message
                        .filter(|value| !value.destination.is_empty())
                        .map(|value| value.destination.clone()),
                    message_text: message
                        .filter(|value| !value.text.is_empty())
                        .map(|value| value.text.clone()),
                    message_id: message.and_then(|value| value.id.clone()),
                    message_ack: message.and_then(|value| value.acknowledgement_id.clone()),
                    message_reject: message.and_then(|value| value.rejection_id.clone()),
                    telemetry_sequence: telemetry.and_then(|value| value.sequence.map(i64::from)),
                    telemetry_values: telemetry.map_or([None; 5], |value| value.values),
                    telemetry_bits: telemetry.and_then(|value| value.bits.clone()),
                    weather_values: weather.map_or([None; 13], |value| {
                        [
                            value.wind_direction_deg,
                            value.wind_speed_ms,
                            value.wind_gust_ms,
                            value.temperature_c,
                            value.indoor_temperature_c,
                            value.humidity_percent.map(f64::from),
                            value.indoor_humidity_percent.map(f64::from),
                            value.pressure_mbar,
                            value.rain_1h_mm,
                            value.rain_24h_mm,
                            value.rain_since_midnight_mm,
                            value.snow_24h_mm,
                            value.luminosity_wm2.map(f64::from),
                        ]
                    }),
                    weather_extension_values: weather.map_or([None; 3], |value| {
                        [
                            value.water_level_m,
                            value.radiation_nsvh,
                            value.battery_voltage,
                        ]
                    }),
                    weather_software: weather.and_then(|value| value.software.clone()),
                    weather_present: weather.is_some(),
                    comment: packet.comment().map(str::to_owned),
                    non_utf8: std::str::from_utf8(raw).is_err(),
                }
            }
            Err(error) => Self {
                ok: false,
                error: Some(error.code.as_str().to_string()),
                packet_type: None,
                position: None,
                symbol_table: None,
                symbol_code: None,
                course: None,
                speed: None,
                altitude: None,
                position_ambiguity: None,
                messaging: None,
                message_destination: None,
                message_text: None,
                message_id: None,
                message_ack: None,
                message_reject: None,
                telemetry_sequence: None,
                telemetry_values: [None; 5],
                telemetry_bits: None,
                weather_values: [None; 13],
                weather_extension_values: [None; 3],
                weather_software: None,
                weather_present: false,
                comment: None,
                non_utf8: std::str::from_utf8(raw).is_err(),
            },
        }
    }
}

struct FapOutcome {
    ok: bool,
    error: Option<String>,
    packet_type: Option<String>,
    position: Option<(f64, f64)>,
    symbol_table: Option<i64>,
    symbol_code: Option<i64>,
    course: Option<f64>,
    speed: Option<f64>,
    altitude: Option<f64>,
    position_ambiguity: Option<i64>,
    messaging: Option<i64>,
    message_destination: Option<String>,
    message_text: Option<String>,
    message_id: Option<String>,
    message_ack: Option<String>,
    message_reject: Option<String>,
    telemetry_sequence: Option<i64>,
    telemetry_values: [Option<f64>; 5],
    telemetry_bits: Option<String>,
    weather_values: [Option<f64>; 13],
    weather_software: Option<String>,
    weather_present: bool,
    comment: Option<String>,
}

impl FapOutcome {
    fn parse(line: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 40 {
            return Err(format!("invalid reference-parser outcome: {line:?}").into());
        }
        Ok(Self {
            ok: fields[0] == "1",
            error: (!fields[1].is_empty()).then(|| fields[1].to_string()),
            packet_type: (!fields[2].is_empty()).then(|| fields[2].to_string()),
            position: match (fields[3].parse::<f64>(), fields[4].parse::<f64>()) {
                (Ok(latitude), Ok(longitude)) => Some((latitude, longitude)),
                _ => None,
            },
            symbol_table: fields[5].parse().ok(),
            symbol_code: fields[6].parse().ok(),
            course: fields[7].parse().ok(),
            speed: fields[8].parse().ok(),
            altitude: fields[9].parse().ok(),
            position_ambiguity: fields[10].parse().ok(),
            messaging: fields[11].parse().ok(),
            message_destination: decode_optional_hex(fields[12])?,
            message_text: decode_optional_hex(fields[13])?,
            message_id: decode_optional_hex(fields[14])?,
            message_ack: decode_optional_hex(fields[15])?,
            message_reject: decode_optional_hex(fields[16])?,
            telemetry_sequence: fields[17].parse().ok(),
            telemetry_values: [
                fields[18].parse().ok(),
                fields[19].parse().ok(),
                fields[20].parse().ok(),
                fields[21].parse().ok(),
                fields[22].parse().ok(),
            ],
            telemetry_bits: decode_optional_hex(fields[23])?,
            weather_values: std::array::from_fn(|index| fields[24 + index].parse().ok()),
            weather_software: decode_optional_hex(fields[37])?,
            comment: decode_optional_hex(fields[38])?,
            weather_present: fields[39] == "1",
        })
    }
}

fn decode_optional_hex(value: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if value.is_empty() {
        return Ok(None);
    }
    if !value.len().is_multiple_of(2) {
        return Err(format!("odd-length hex value: {value:?}").into());
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("invalid hex value: {value:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // FRAP exposes parsed string fields through an ASCII parser view while
    // retaining the exact packet separately in `Packet::original_bytes`.
    // Compare Perl's byte strings through that same view so encoding alone is
    // not reported as a parser-semantic mismatch.
    Ok(Some(
        bytes
            .into_iter()
            .map(|byte| {
                if byte.is_ascii() {
                    char::from(byte)
                } else {
                    '?'
                }
            })
            .collect(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn compare_integer_field(
    name: &str,
    frap: Option<i64>,
    fap: Option<i64>,
    line: u64,
    raw: &[u8],
    comparison: &mut Comparison,
    report: &mut impl Write,
) -> std::io::Result<()> {
    compare_field(name, frap, fap, line, raw, comparison, report, |a, b| {
        a == b
    })
}

#[allow(clippy::too_many_arguments)]
fn compare_float_field(
    name: &str,
    frap: Option<f64>,
    fap: Option<f64>,
    tolerance: f64,
    line: u64,
    raw: &[u8],
    comparison: &mut Comparison,
    report: &mut impl Write,
) -> std::io::Result<()> {
    compare_field(name, frap, fap, line, raw, comparison, report, |a, b| {
        (a - b).abs() <= tolerance
    })
}

#[allow(clippy::too_many_arguments)]
fn compare_string_field(
    name: &str,
    frap: Option<&str>,
    fap: Option<&str>,
    line: u64,
    raw: &[u8],
    comparison: &mut Comparison,
    report: &mut impl Write,
) -> std::io::Result<()> {
    if frap == fap {
        return Ok(());
    }
    if name == "weather_comment"
        && let (Some(frap), Some(fap)) = (frap, fap)
    {
        let delta = comment_delta(frap, fap);
        *comparison.comment_deltas.entry(delta).or_default() += 1;
    }
    let (mismatch, kind) = match (frap, fap) {
        (Some(_), Some(_)) => (&mut comparison.field_value_mismatches, "value"),
        (Some(_), None) => (&mut comparison.frap_only_fields, "frap_only"),
        (None, Some(_)) => (&mut comparison.fap_only_fields, "fap_only"),
        (None, None) => unreachable!("equal absent fields returned above"),
    };
    *mismatch.entry(name.to_string()).or_default() += 1;
    writeln!(
        report,
        "{line}\t{name}\t{kind}\t{}\t{}\t{}",
        frap.unwrap_or_default().escape_default(),
        fap.unwrap_or_default().escape_default(),
        encode_hex(raw)
    )
}

#[allow(clippy::too_many_arguments)]
fn compare_or_record_intentional_string_field(
    name: &str,
    frap: Option<&str>,
    fap: Option<&str>,
    intentional_reason: Option<&str>,
    line: u64,
    raw: &[u8],
    comparison: &mut Comparison,
    mismatch_report: &mut impl Write,
    intentional_report: &mut impl Write,
) -> std::io::Result<()> {
    if frap == fap {
        return Ok(());
    }
    if let Some(reason) = intentional_reason {
        *comparison
            .intentional_field_differences
            .entry(format!("{name} ({reason})"))
            .or_default() += 1;
        return writeln!(
            intentional_report,
            "{line}\t{name}\t{reason}\t{}\t{}\t{}",
            frap.unwrap_or_default().escape_default(),
            fap.unwrap_or_default().escape_default(),
            encode_hex(raw)
        );
    }
    compare_string_field(name, frap, fap, line, raw, comparison, mismatch_report)
}

fn comments_differ_only_by_inline_telemetry(frap: Option<&str>, fap: Option<&str>) -> bool {
    let Some(fap) = fap else {
        return false;
    };
    let Some(stripped) = strip_inline_telemetry(fap) else {
        return false;
    };
    let stripped = stripped.trim();
    frap.unwrap_or_default() == stripped
}

fn comments_differ_only_by_extension_placeholder(frap: Option<&str>, fap: Option<&str>) -> bool {
    let (Some(frap), Some(fap)) = (frap, fap) else {
        return false;
    };
    ["X ", "X."]
        .into_iter()
        .any(|placeholder| fap.strip_prefix(placeholder) == Some(frap))
}

fn strip_inline_telemetry(comment: &str) -> Option<String> {
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
        })?;
    Some(format!(
        "{}{}",
        &comment[..selected.0],
        &comment[selected.1 + 1..]
    ))
}

#[allow(clippy::too_many_arguments)]
fn compare_field<T: Copy + std::fmt::Display>(
    name: &str,
    frap: Option<T>,
    fap: Option<T>,
    line: u64,
    raw: &[u8],
    comparison: &mut Comparison,
    report: &mut impl Write,
    equal: impl FnOnce(T, T) -> bool,
) -> std::io::Result<()> {
    let (mismatch, kind) = match (frap, fap) {
        (None, None) => return Ok(()),
        (Some(a), Some(b)) if equal(a, b) => return Ok(()),
        (Some(_), Some(_)) => (&mut comparison.field_value_mismatches, "value"),
        (Some(_), None) => (&mut comparison.frap_only_fields, "frap_only"),
        (None, Some(_)) => (&mut comparison.fap_only_fields, "fap_only"),
    };
    *mismatch.entry(name.to_string()).or_default() += 1;
    writeln!(
        report,
        "{line}\t{name}\t{kind}\t{}\t{}\t{}",
        frap.map(|value| value.to_string()).unwrap_or_default(),
        fap.map(|value| value.to_string()).unwrap_or_default(),
        encode_hex(raw)
    )
}

fn frap_packet_type(packet_type: PacketType, has_position: bool) -> String {
    match packet_type {
        PacketType::Location => "location",
        PacketType::Object => "object",
        PacketType::Item => "item",
        PacketType::Message => "message",
        PacketType::TelemetryMessage => "telemetry-message",
        PacketType::Status => "status",
        PacketType::Capabilities => "capabilities",
        PacketType::Beacon => "beacon",
        PacketType::Weather if has_position => "location",
        PacketType::Weather => "wx",
        PacketType::Telemetry => "telemetry",
        _ => "unknown",
    }
    .to_string()
}

enum PositionComparison {
    Same,
    Presence,
    Value,
}

fn compare_positions(left: Option<(f64, f64)>, right: Option<(f64, f64)>) -> PositionComparison {
    match (left, right) {
        (None, None) => PositionComparison::Same,
        (Some(left), Some(right)) => {
            if (left.0 - right.0).abs() > 0.000_01 || (left.1 - right.1).abs() > 0.000_01 {
                PositionComparison::Value
            } else {
                PositionComparison::Same
            }
        }
        _ => PositionComparison::Presence,
    }
}

fn outcome_name(ok: bool) -> &'static str {
    if ok { "pass" } else { "fail" }
}

fn encode_hex(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(raw.len() * 2);
    for byte in raw {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn comment_delta(frap: &str, fap: &str) -> (String, String) {
    let frap = frap.chars().collect::<Vec<_>>();
    let fap = fap.chars().collect::<Vec<_>>();
    let prefix = frap
        .iter()
        .zip(&fap)
        .take_while(|(left, right)| left == right)
        .count();
    let mut suffix = 0;
    while suffix < frap.len() - prefix
        && suffix < fap.len() - prefix
        && frap[frap.len() - suffix - 1] == fap[fap.len() - suffix - 1]
    {
        suffix += 1;
    }
    let frap_end = frap.len() - suffix;
    let fap_end = fap.len() - suffix;
    (
        normalize_comment_fragment(&frap[prefix..frap_end]),
        normalize_comment_fragment(&fap[prefix..fap_end]),
    )
}

fn normalize_comment_fragment(fragment: &[char]) -> String {
    let mut normalized = String::new();
    let mut in_digits = false;
    let mut in_whitespace = false;
    for &character in fragment {
        if character.is_ascii_digit() {
            if !in_digits {
                normalized.push('#');
            }
            in_digits = true;
            in_whitespace = false;
        } else if character.is_whitespace() {
            if !in_whitespace {
                normalized.push(' ');
            }
            in_digits = false;
            in_whitespace = true;
        } else {
            normalized.push(character);
            in_digits = false;
            in_whitespace = false;
        }
        if normalized.chars().count() == 48 {
            normalized.push('…');
            break;
        }
    }
    normalized
}

fn write_comment_delta_report(
    output_dir: &Path,
    deltas: &BTreeMap<(String, String), u64>,
) -> std::io::Result<()> {
    let mut report = BufWriter::new(File::create(output_dir.join("comment-deltas.tsv"))?);
    writeln!(report, "count\tfrap_fragment\tfap_fragment")?;
    let mut deltas = deltas.iter().collect::<Vec<_>>();
    deltas.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for ((frap, fap), count) in deltas {
        writeln!(
            report,
            "{count}\t{}\t{}",
            frap.escape_default(),
            fap.escape_default()
        )?;
    }
    report.flush()
}

fn build_summary(comparison: &Comparison, output_dir: &Path, reference_name: &str) -> String {
    let mut output = String::new();
    writeln!(output, "packets: {}", comparison.total).unwrap();
    writeln!(
        output,
        "FRAP passes: {}",
        comparison.both_pass + comparison.frap_only
    )
    .unwrap();
    writeln!(
        output,
        "{reference_name} passes: {}",
        comparison.both_pass + comparison.fap_only
    )
    .unwrap();
    writeln!(output, "both pass: {}", comparison.both_pass).unwrap();
    writeln!(output, "both fail: {}", comparison.both_fail).unwrap();
    writeln!(output, "FRAP only passes: {}", comparison.frap_only).unwrap();
    writeln!(
        output,
        "{reference_name} only passes: {}",
        comparison.fap_only
    )
    .unwrap();
    writeln!(
        output,
        "non-UTF-8 inputs parsed by FRAP: {}",
        comparison.non_utf8
    )
    .unwrap();
    writeln!(
        output,
        "packet-type mismatches among mutual successes: {}",
        comparison.type_mismatches
    )
    .unwrap();
    writeln!(
        output,
        "position-presence mismatches among mutual successes: {}",
        comparison.position_presence_mismatches
    )
    .unwrap();
    writeln!(
        output,
        "position-value mismatches among mutual successes: {}",
        comparison.position_value_mismatches
    )
    .unwrap();
    write_position_distances(&mut output, &comparison.position_distances_m);
    writeln!(output, "FRAP-only field presence:").unwrap();
    write_counts(&mut output, &comparison.frap_only_fields);
    writeln!(output, "{reference_name}-only field presence:").unwrap();
    write_counts(&mut output, &comparison.fap_only_fields);
    writeln!(output, "field-value mismatches:").unwrap();
    write_counts(&mut output, &comparison.field_value_mismatches);
    writeln!(output, "known intentional field differences:").unwrap();
    write_counts(&mut output, &comparison.intentional_field_differences);
    writeln!(output, "most common normalized weather-comment deltas:").unwrap();
    write_comment_delta_counts(&mut output, &comparison.comment_deltas, 20);
    writeln!(output, "packet-type mismatch pairs:").unwrap();
    write_counts(&mut output, &comparison.type_mismatch_pairs);
    writeln!(output, "FRAP failures by code:").unwrap();
    write_counts(&mut output, &comparison.frap_errors);
    writeln!(output, "{reference_name} failures by code:").unwrap();
    write_counts(&mut output, &comparison.fap_errors);
    writeln!(output, "FRAP-only successes by {reference_name} error:").unwrap();
    write_counts(&mut output, &comparison.frap_only_by_fap_error);
    writeln!(output, "{reference_name}-only successes by FRAP error:").unwrap();
    write_counts(&mut output, &comparison.fap_only_by_frap_error);
    writeln!(
        output,
        "outcome mismatches: {}",
        output_dir.join("outcome-mismatches.tsv").display()
    )
    .unwrap();
    writeln!(
        output,
        "position mismatches: {}",
        output_dir.join("position-mismatches.tsv").display()
    )
    .unwrap();
    writeln!(
        output,
        "field mismatches: {}",
        output_dir.join("field-mismatches.tsv").display()
    )
    .unwrap();
    writeln!(
        output,
        "intentional differences: {}",
        output_dir.join("intentional-differences.tsv").display()
    )
    .unwrap();
    writeln!(
        output,
        "weather comment deltas: {}",
        output_dir.join("comment-deltas.tsv").display()
    )
    .unwrap();
    output
}

fn write_position_distances(output: &mut String, distances: &[f64]) {
    if distances.is_empty() {
        return;
    }
    let mut sorted = distances.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |percent: usize| {
        let index = (sorted.len() - 1) * percent / 100;
        sorted[index]
    };
    writeln!(output, "position mismatch separation:").unwrap();
    writeln!(output, "  median: {:.1} m", percentile(50)).unwrap();
    writeln!(output, "  p90: {:.1} m", percentile(90)).unwrap();
    writeln!(output, "  p99: {:.1} m", percentile(99)).unwrap();
    writeln!(output, "  maximum: {:.1} m", sorted[sorted.len() - 1]).unwrap();
    for limit in [10.0, 100.0, 1_000.0, 10_000.0] {
        let count = sorted.iter().filter(|distance| **distance <= limit).count();
        writeln!(output, "  <= {limit:.0} m: {count}").unwrap();
    }
    writeln!(
        output,
        "  > 10 km: {}",
        sorted
            .iter()
            .filter(|distance| **distance > 10_000.0)
            .count()
    )
    .unwrap();
}

fn write_counts(output: &mut String, counts: &BTreeMap<String, u64>) {
    let mut counts = counts.iter().collect::<Vec<_>>();
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (code, count) in counts {
        writeln!(output, "  {code}: {count}").unwrap();
    }
}

fn write_comment_delta_counts(
    output: &mut String,
    deltas: &BTreeMap<(String, String), u64>,
    limit: usize,
) {
    let mut deltas = deltas.iter().collect::<Vec<_>>();
    deltas.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for ((frap, fap), count) in deltas.into_iter().take(limit) {
        writeln!(
            output,
            "  {} -> {}: {count}",
            frap.escape_default(),
            fap.escape_default()
        )
        .unwrap();
    }
}
