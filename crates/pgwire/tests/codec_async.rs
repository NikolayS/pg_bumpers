//! Async framing tests: write encoded frames into a tokio duplex pipe and read
//! them back as `RawFrame`s, then decode (SPEC §3 layer 2 — the byte-level seam).

use bytes::Bytes;
use pgb_pgwire::backend::BackendMessage;
use pgb_pgwire::codec::{read_startup_body, read_tagged_frame, write_frame};
use pgb_pgwire::frontend::{FrontendMessage, StartupMessage};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn frames_round_trip_over_async_stream() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);

    let parse = FrontendMessage::Parse {
        statement: String::new(),
        sql: "SELECT * FROM t WHERE id = $1".into(),
        param_types: vec![23],
    };
    let execute = FrontendMessage::Execute {
        portal: String::new(),
        max_rows: 0,
    };
    let sync = FrontendMessage::Sync;

    // Writer side.
    let p = parse.clone();
    let e = execute.clone();
    let s = sync.clone();
    let writer = tokio::spawn(async move {
        write_frame(&mut client, &p.encode()).await.unwrap();
        write_frame(&mut client, &e.encode()).await.unwrap();
        write_frame(&mut client, &s.encode()).await.unwrap();
        client.shutdown().await.unwrap();
    });

    // Reader side decodes each raw frame back into a typed message.
    let f1 = read_tagged_frame(&mut server).await.unwrap().unwrap();
    assert_eq!(FrontendMessage::decode(f1.tag, f1.body).unwrap(), parse);
    let f2 = read_tagged_frame(&mut server).await.unwrap().unwrap();
    assert_eq!(FrontendMessage::decode(f2.tag, f2.body).unwrap(), execute);
    let f3 = read_tagged_frame(&mut server).await.unwrap().unwrap();
    assert_eq!(FrontendMessage::decode(f3.tag, f3.body).unwrap(), sync);

    // Clean EOF after the last frame yields None (peer closed between messages).
    assert!(read_tagged_frame(&mut server).await.unwrap().is_none());

    writer.await.unwrap();
}

#[tokio::test]
async fn startup_then_tagged_backend_round_trip() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);

    let startup = StartupMessage {
        protocol_version: pgb_pgwire::frontend::PROTOCOL_VERSION_3,
        parameters: vec![("user".into(), "agent".into())],
    };
    let ready = BackendMessage::ReadyForQuery {
        status: pgb_pgwire::backend::TransactionStatus::Idle,
    };

    let st = startup.clone();
    let rdy = ready.clone();
    let writer = tokio::spawn(async move {
        // Untagged startup first.
        write_frame(&mut client, &st.encode()).await.unwrap();
        // Then a tagged backend message on the same stream.
        write_frame(&mut client, &rdy.encode()).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let body = read_startup_body(&mut server).await.unwrap();
    assert_eq!(StartupMessage::decode_body(body).unwrap(), startup);

    let frame = read_tagged_frame(&mut server).await.unwrap().unwrap();
    assert_eq!(
        BackendMessage::decode(frame.tag, frame.body).unwrap(),
        ready
    );

    writer.await.unwrap();
}

#[tokio::test]
async fn truncated_frame_is_an_error_not_a_panic() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    // A tagged frame claiming a 100-byte body but we send only the header +
    // a few bytes, then close → read_exact must surface an error (fail-closed).
    let writer = tokio::spawn(async move {
        client.write_u8(b'Q').await.unwrap();
        client.write_i32(104).await.unwrap(); // declares 100 body bytes
        client.write_all(b"SELECT").await.unwrap();
        client.shutdown().await.unwrap();
    });
    let res = read_tagged_frame(&mut server).await;
    assert!(res.is_err(), "truncated body must be an error");
    writer.await.unwrap();
    let _ = Bytes::new();
}
