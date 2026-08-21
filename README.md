# frap

`frap` is a pure Rust port of the Finnish/Fabulous APRS Parser
([Ham::APRS::FAP](https://metacpan.org/pod/Ham::APRS::FAP)). It parses APRS
packets in TNC2/APRS-IS text format without C bindings or runtime
dependencies.

The parser accepts either UTF-8 text or raw bytes. `Packet::original_bytes`
always contains the exact input. Valid UTF-8 is restored in unambiguous
free-text fields after structural parsing; invalid or ambiguous non-ASCII
payload bytes are represented by `?`.

```rust
use frap::{PacketBody, parse};

let packet = parse(
    "2W0FWJ-2>APRS,WIDE1-1,WIDE2-1:!6128.23N/02353.52E-Testing"
)?;

assert_eq!(packet.source, "2W0FWJ-2");
let PacketBody::Location { position, .. } = &packet.body else {
    unreachable!();
};
assert_eq!(position.latitude, 61.4705);
# Ok::<(), frap::ParseError>(())
```

```rust
let raw = b"N0CALL>APRS:>binary \x81 status";
let packet = frap::parse(raw)?;
assert_eq!(packet.original_bytes, raw);
# Ok::<(), frap::ParseError>(())
```

For hot paths, `parse_ref` borrows the input buffer for the original packet,
header, body, callsigns, and path components whenever normalization is not
needed. Convert to the original owned representation only when required:

```rust
let raw = b"2W0FWJ>APRS:!5120.00N/00300.00W>Testing";
let borrowed = frap::parse_ref(raw)?;
assert_eq!(borrowed.source, "2W0FWJ");

let owned = borrowed.into_owned();
assert_eq!(owned.comment.as_deref(), Some("Testing"));
# Ok::<(), frap::ParseError>(())
```

Both packet representations store decoded payload data directly in a
`PacketBody` variant. Position, object, item, message, weather, telemetry,
status, capability, and beacon fields therefore cannot be confused with one
another or appear in an impossible combination.

## Status

The parser supports:

- TNC2/APRS-IS headers and digipeater paths
- optional strict AX.25 callsign/path validation
- uncompressed and compressed positions
- Mic-E positions, altitude, telemetry, and opt-in damaged-packet recovery
- NMEA GPRMC, GPGGA, and GPGLL positions with checksum validation
- timestamped positions, objects, and status reports with decoded timestamps
- objects and items
- messages, acknowledgements, rejects, and reply-acks
- status and station capabilities
- classic and Mic-E telemetry
- positionless, positioned, compressed, and ULTW weather reports
- DAO, PHG/PHGRA, radio range, altitude, course, and speed extensions
- generic beacon recognition
- stable, machine-readable parse errors
- message, object, timestamp, and compressed/uncompressed-position encoding
- KISS/TNC2 conversion and duplicate-detection helpers
- distance, direction, digihop, callsign, and APRS-IS passcode utilities
- an optional asynchronous APRS-IS client

The public functionality exported by FAP has a Rust equivalent. Idiomatic
names such as `parse`, `encode_position`, and `mice_message` are primary;
`make_position`, `make_object`, `make_timestamp`, and
`mice_mbits_to_message` are also available as compatibility names.

## Encoding and frame conversion

`EncodePositionOptions::compressed` selects APRS base-91 position encoding;
compressed positions cannot also use ambiguity or DAO. `EncodeObjectOptions`
uses the same position options and creates the required UTC object timestamp.
An empty symbol selects FAP's default `//` symbol.

`tnc2_to_kiss` returns a complete, byte-stuffed KISS frame including its FEND
bytes. `kiss_to_tnc2` follows FAP and accepts the content between those FEND
bytes. Both APIs use byte vectors so binary APRS information fields round-trip
without UTF-8 conversion.

## Async APRS-IS client

The parser has no runtime dependencies. Enable the separate Tokio-based client
only when it is needed:

```toml
[dependencies]
frap = { version = "0.1", features = ["aprs-is"] }
```

```rust,no_run
use std::time::Duration;
use frap::AprsIsConnection;

# async fn example() -> std::io::Result<()> {
let mut connection = AprsIsConnection::connect(
    "rotate.aprs2.net:14580",
    "N0CALL",
    "-1",
    "my-app",
    "0.1",
    Some("r/60.18/24.94/100"),
).await?;

let raw = connection.read_packet(Duration::from_secs(30)).await?;
let packet = frap::parse(&raw)?;
# Ok(())
# }
```

## Development

Run the complete black-box parser suite with:

```console
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo bench --bench parser
```

The tests live in `tests/parser.rs`, so `cargo test --lib` is not the test
command for this crate. To run only the parser integration test target, use:

```console
cargo test --test parser
```

## Real-world corpus

Large real-world packet corpora belong in the git-ignored `test-data`
directory. The corpus audit test defaults to
`test-data/real-world-1m.tnc2`, or accepts another path through
`FRAP_CORPUS`:

```console
cargo test --test corpus -- --ignored --nocapture
FRAP_CORPUS=/path/to/corpus.tnc2 cargo test --test corpus -- --ignored --nocapture
```

The audit reports parser errors by stable error code and fails if any packet
causes a panic. Parse errors do not currently fail the audit, so the corpus can
drive incremental compatibility work.

### Comparing with Perl FAP

Bootstrap the pinned original `Ham::APRS::FAP` 1.21 module into `target/`, then
run the line-for-line differential comparison:

```console
scripts/bootstrap-perl-fap
cargo run --release --example fap-diff -- test-data/real-world-1m.tnc2
```

For a parser-only throughput comparison, load the same corpus into memory in
both runtimes and run repeated timed passes:

```console
cargo run --release --example corpus-bench -- test-data/real-world-1m.tnc2 3
perl -Itarget/perl-fap tools/perl-fap-bench.pl test-data/real-world-1m.tnc2 3
```

These benchmarks exclude database export, differential-report I/O, and corpus
loading. The Rust runner reports both borrowed and owned FRAP parsing; both
runners report every pass and the median packet rate.

The comparator reports pass/fail agreement, error distributions, packet-type,
position, message, telemetry, and weather differences among mutual successes.
Weather comments are compared when both parsers attach a weather record.
Perl byte-string fields are normalized to FRAP's documented ASCII parser view;
exact input bytes remain available through `Packet::original_bytes`.
FRAP-only water-level, radiation, and battery-voltage extensions are also
inventoried even though FAP 1.21 has no corresponding output fields.
Exact packets with differing outcomes are written as hex to
`target/fap-diff/outcome-mismatches.tsv`. Field-presence differences are reported
directionally, and every run atomically refreshes `target/fap-diff/summary.txt`.
Known differences caused by FRAP's documented extensions, UTF-8 free text,
positioned-weather inline telemetry, and APRS 1.1 reply-acks are written separately to
`target/fap-diff/intentional-differences.tsv`.
Normalized weather-comment edit fragments are grouped by frequency in
`target/fap-diff/comment-deltas.tsv` so common scanner effects can be audited
without inspecting every packet individually.

### Comparing with libfap

The same comparator can run against the released C port, libfap 1.5. The
bootstrap script downloads the source from the
[official libfap site](https://www.pakettiradio.net/libfap/), verifies its
published SHA-256, and builds it locally under `target/`; it does not install a
system library.

```console
scripts/bootstrap-libfap
cargo run --release --example fap-diff -- --libfap test-data/real-world-1m.tnc2
```

Its reports are written separately under `target/libfap-diff/`. Libfap is not
treated as a newer specification: version 1.5 predates FAP 1.21 and contains
known port-specific differences, so the report preserves raw mismatch totals
for diagnosis instead of making FRAP emulate them.

FRAP deliberately preserves valid partial weather readings. For example, a
direction paired with an unavailable speed (`247/...`) remains available as a
direction-only reading. FAP 1.21 omits both fields unless the initial wind pair
is complete, so these appear as FRAP-only field-presence differences. The same
policy preserves valid four- or five-digit pressure fields in otherwise partial
weather reports. Shorter `b` fragments are left in the comment rather than being
misidentified as pressure. Explicit gust fields are likewise retained in
partial reports, while field-like fragments inside words, callsigns, hostnames,
and dates (such as `mtg3.eu`, `g8wvw`, and `Dec2025`) remain comment text.
The `s` in an embedded `cDDDsSSS` pair is treated as wind speed rather than
snowfall. Standalone snow and luminosity markers are kept when they form weather
fields, but fragments in otherwise free-form names such as `WX3in1Plus2.0`,
`ks5s`, `PL100`, and `DL6MM` remain comments.

Temperature and humidity fields receive the same partial-report treatment.
FRAP keeps explicit `t` and `h` measurements even when malformed or unavailable
fields prevent FAP 1.21 from attaching a weather record. A one-digit `h` embedded
inside a word or hostname (such as `dh5dy`) is left as comment text rather than
being mistaken for humidity.

FRAP's `F` water-level, `X` radiation, and `V` battery-voltage extensions are
recognized at the start of weather data or directly after another parsed weather
field. This keeps explicit forms such as `X111`, `V135`, and `F....V041` while
preventing values in METARs, software names, and free-form sensor text from being
reinterpreted as extensions.

Like FAP, FRAP recognizes the variable-width rain markers `r`, `p`, and `P`
wherever they occur in the remaining weather text. A marker followed by digits
in free-form text is therefore inherently ambiguous. FRAP retains this behavior
for compatibility; applications can consult the preserved comment and original
packet bytes when provenance matters.

FAP derives weather software identifiers after a sequence of destructive regular
expression substitutions. On malformed or unusually ordered reports this can
turn a delimiter fragment, numeric residue, or unconsumed weather field into a
three-to-five-character software string. FRAP reports software only when its
decoded remainder is itself a clean identifier, leaving ambiguous residue in the
comment instead.

Inline base-91 telemetry is decoded on every positioned packet type, including
positioned weather. APRS identifies it only by a pipe-delimited 4–14 character
base-91 payload, so ordinary text such as `|Digi|` is syntactically
indistinguishable from a two-pair telemetry report. FRAP follows the wire
format and decodes it; applications that use free-form pipe-delimited comments
should account for that ambiguity.

Classic `T#` reports are decoded permissively when truncated or when a later
analog field is malformed. Valid leading channels remain available and a
`tlm_inv` entry is added to `Packet::warnings`. FAP 1.21 rejects these reports
entirely, so they account for most FRAP-only telemetry successes.

Analog values at or beyond FAP's numeric limit of ±999999 are also preserved,
with a `tlm_large` warning. This retains real-world frequency-like readings used
by RXTLM, TetraLogic, and RepeaterLogic packets while making the FAP compatibility
difference explicit.

Message response keywords are recognized only when followed by a valid one-to-five
character response ID; ordinary text such as `ack`, `ack 3`, or `ack?=` remains a
message. FRAP also implements APRS 1.1 reply-ack (`{message-id}ack-id`) parsing,
which FAP 1.21 lists as a TODO. The differential report therefore shows intentional
message-ID and acknowledgement differences for reply-ack packets. Other message-text
value differences are the public ASCII parser view's `?` substitutions for
non-ASCII bytes; exact input remains available through `Packet::original_bytes`.
