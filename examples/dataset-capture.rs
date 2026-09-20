use std::{
    env,
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
    time::Duration,
};

use frap::AprsIsConnection;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| invalid_input("usage: dataset-capture OUTPUT PACKETS FILTER"))?;
    let packet_limit = arguments
        .next()
        .ok_or_else(|| invalid_input("usage: dataset-capture OUTPUT PACKETS FILTER"))?
        .to_string_lossy()
        .parse::<usize>()?;
    if packet_limit == 0 {
        return Err(invalid_input("PACKETS must be greater than zero").into());
    }
    let filter = arguments
        .next()
        .ok_or_else(|| invalid_input("usage: dataset-capture OUTPUT PACKETS FILTER"))?
        .to_string_lossy()
        .into_owned();
    if arguments.next().is_some() {
        return Err(invalid_input("usage: dataset-capture OUTPUT PACKETS FILTER").into());
    }

    let callsign =
        env::var("APRS_CALLSIGN").map_err(|_| invalid_input("APRS_CALLSIGN must be set"))?;
    let passcode =
        env::var("APRS_PASSCODE").map_err(|_| invalid_input("APRS_PASSCODE must be set"))?;
    let server = env::var("APRS_SERVER").unwrap_or_else(|_| "rotate.aprs2.net:14580".to_owned());

    let mut connection = AprsIsConnection::connect(
        server.as_str(),
        &callsign,
        &passcode,
        "frap-dataset-capture",
        env!("CARGO_PKG_VERSION"),
        Some(&filter),
    )
    .await?;
    let mut writer = BufWriter::new(File::create(&output)?);
    let mut captured = 0;

    while captured < packet_limit {
        match connection.read_packet(Duration::from_secs(60)).await {
            Ok(packet) => {
                writer.write_all(packet.as_bytes())?;
                writer.write_all(b"\n")?;
                captured += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error.into()),
        }
    }

    writer.flush()?;
    eprintln!("captured {captured} packets in {}", output.display());
    Ok(())
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
