#![cfg(feature = "aprs-is")]

use std::time::Duration;

use frap::AprsIsConnection;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[tokio::test]
async fn async_client_logs_in_and_skips_server_comments() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut login = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut login)
            .await
            .unwrap();
        assert_eq!(
            login,
            "user N0CALL pass -1 vers frap-test 0.1 filter m/10\r\n"
        );
        stream.write_all(b"# keepalive\r\n").await.unwrap();
        stream
            .write_all(b"N0CALL>APRS:>async packet\r\n")
            .await
            .unwrap();
    });

    let mut client =
        AprsIsConnection::connect(address, "N0CALL", "-1", "frap-test", "0.1", Some("m/10"))
            .await
            .unwrap();
    let packet = client.read_packet(Duration::from_secs(1)).await.unwrap();
    assert_eq!(packet, "N0CALL>APRS:>async packet");
    client.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn async_client_rejects_embedded_newlines() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let mut client = AprsIsConnection::connect(address, "N0CALL", "-1", "frap-test", "0.1", None)
        .await
        .unwrap();
    let error = client.send_line("one\ntwo").await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    accept.abort();
}

#[tokio::test]
async fn async_client_bounds_and_drains_oversized_lines() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut login = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut login)
            .await
            .unwrap();
        stream.write_all(&vec![b'x'; 2_049]).await.unwrap();
        stream
            .write_all(b"\r\nN0CALL>APRS:>next packet\r\n")
            .await
            .unwrap();
    });

    let mut client = AprsIsConnection::connect(address, "N0CALL", "-1", "frap-test", "0.1", None)
        .await
        .unwrap();
    let error = client.read_line(Duration::from_secs(1)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        client.read_packet(Duration::from_secs(1)).await.unwrap(),
        "N0CALL>APRS:>next packet"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn async_client_preserves_partial_lines_across_timeouts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut login = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut login)
            .await
            .unwrap();
        stream.write_all(b"N0CALL>APRS:>partial").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.write_all(b" packet\r\n").await.unwrap();
    });

    let mut client = AprsIsConnection::connect(address, "N0CALL", "-1", "frap-test", "0.1", None)
        .await
        .unwrap();
    let error = client
        .read_line(Duration::from_millis(10))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        client.read_packet(Duration::from_secs(1)).await.unwrap(),
        "N0CALL>APRS:>partial packet"
    );
    server.await.unwrap();
}
