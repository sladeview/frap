use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;

/// APRS packets are limited to 512 bytes on the wire. Allow additional room
/// for APRS-IS server messages without permitting an unbounded allocation.
const MAX_APRS_IS_LINE_BYTES: usize = 2_048;

/// An asynchronous APRS-IS connection.
///
/// This client is available with the `aprs-is` Cargo feature. Keeping it
/// optional means applications that only parse APRS packets do not pull in an
/// async runtime.
pub struct AprsIsConnection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    line_buffer: Vec<u8>,
    discarding_oversized_line: bool,
}

impl AprsIsConnection {
    /// Connect to APRS-IS and asynchronously send the login line.
    pub async fn connect(
        address: impl ToSocketAddrs,
        callsign: &str,
        passcode: &str,
        application: &str,
        version: &str,
        filter: Option<&str>,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        let (reader, writer) = stream.into_split();
        let mut connection = Self {
            reader: BufReader::new(reader),
            writer,
            line_buffer: Vec::with_capacity(256),
            discarding_oversized_line: false,
        };
        let mut login = format!("user {callsign} pass {passcode} vers {application} {version}");
        if let Some(filter) = filter {
            login.push_str(" filter ");
            login.push_str(filter);
        }
        connection.send_line(&login).await?;
        Ok(connection)
    }

    /// Read one line, removing its CR/LF terminator.
    ///
    /// Returns `TimedOut` if no complete line arrives before `read_timeout`,
    /// and `UnexpectedEof` if the connection closes before a complete line is
    /// received. Lines longer than 2048 bytes are drained and return
    /// `InvalidData`.
    pub async fn read_line(&mut self, read_timeout: Duration) -> io::Result<String> {
        let line = timeout(read_timeout, async {
            loop {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    if self.discarding_oversized_line {
                        break;
                    }
                    let message = if self.line_buffer.is_empty() {
                        "APRS-IS connection closed"
                    } else {
                        "APRS-IS connection closed before line terminator"
                    };
                    self.line_buffer.clear();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, message));
                }
                let consumed = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |index| index + 1);
                if !self.discarding_oversized_line {
                    if self.line_buffer.len() + consumed <= MAX_APRS_IS_LINE_BYTES {
                        self.line_buffer.extend_from_slice(&available[..consumed]);
                    } else {
                        self.line_buffer.clear();
                        self.discarding_oversized_line = true;
                    }
                }
                let complete = available[consumed - 1] == b'\n';
                self.reader.consume(consumed);
                if complete {
                    break;
                }
            }
            if self.discarding_oversized_line {
                self.discarding_oversized_line = false;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "APRS-IS line exceeds 2048 bytes",
                ));
            }
            let mut line = std::mem::take(&mut self.line_buffer);
            while matches!(line.last(), Some(b'\r' | b'\n')) {
                line.pop();
            }
            let result = String::from_utf8(line).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "APRS-IS line is not UTF-8")
            });
            self.line_buffer = Vec::with_capacity(256);
            result
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "APRS-IS read timed out"))??;
        Ok(line)
    }

    /// Read the next packet line, skipping APRS-IS `#` server comments.
    pub async fn read_packet(&mut self, read_timeout: Duration) -> io::Result<String> {
        loop {
            let line = self.read_line(read_timeout).await?;
            if !line.starts_with('#') {
                return Ok(line);
            }
        }
    }

    /// Write one line with the APRS-IS CR/LF terminator.
    pub async fn send_line(&mut self, line: &str) -> io::Result<()> {
        if line.contains(['\r', '\n']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "line contains CR/LF",
            ));
        }
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.writer.flush().await
    }

    /// Gracefully close the write side of the connection.
    pub async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}
