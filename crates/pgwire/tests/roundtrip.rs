//! FE/BE message encode→decode round-trip identity tests (SPEC §7 S1).
//!
//! Each test encodes a typed message to bytes, peels the framing (tag + 4-byte
//! length), and decodes the body back, asserting the value is byte-for-byte
//! identical. This is the acceptance criterion: the covered messages — incl.
//! the SCRAM/SASL set — round-trip.

use bytes::{Buf, Bytes, BytesMut};
use pgb_pgwire::backend::{BackendMessage, FieldDescription, TransactionStatus};
use pgb_pgwire::frontend::{FrontendMessage, StartupMessage, TargetKind};
use pgb_pgwire::scram::{
    AuthenticationSasl, AuthenticationSaslContinue, AuthenticationSaslFinal, SaslInitialResponse,
    SaslResponse,
};

/// Split an encoded **tagged** frame into `(tag, body)`, validating that the
/// declared length matches the actual bytes (catches off-by-one framing bugs).
fn split_tagged(frame: BytesMut) -> (u8, Bytes) {
    let mut b = frame.freeze();
    let tag = b.get_u8();
    let len = b.get_i32();
    assert_eq!(
        len as usize,
        4 + b.remaining(),
        "declared length must equal 4 + body bytes"
    );
    (tag, b)
}

/// Round-trip a frontend message through encode → split → decode.
fn rt_frontend(msg: FrontendMessage) {
    let (tag, body) = split_tagged(msg.encode());
    assert_eq!(tag, msg.tag(), "tag stability");
    let decoded = FrontendMessage::decode(tag, body).expect("decode frontend");
    assert_eq!(decoded, msg, "frontend round-trip identity");
}

/// Round-trip a backend message through encode → split → decode.
fn rt_backend(msg: BackendMessage) {
    let (tag, body) = split_tagged(msg.encode());
    assert_eq!(tag, msg.tag(), "tag stability");
    let decoded = BackendMessage::decode(tag, body).expect("decode backend");
    assert_eq!(decoded, msg, "backend round-trip identity");
}

#[test]
fn startup_message_round_trips() {
    let msg = StartupMessage {
        protocol_version: pgb_pgwire::frontend::PROTOCOL_VERSION_3,
        parameters: vec![
            ("user".into(), "agent".into()),
            ("database".into(), "appdb".into()),
            ("application_name".into(), "pg_bumpers".into()),
        ],
    };
    let frame = msg.encode();
    // Untagged: just length + body.
    let mut b = frame.freeze();
    let len = b.get_i32();
    assert_eq!(len as usize, 4 + b.remaining());
    let decoded = StartupMessage::decode_body(b).expect("decode startup");
    assert_eq!(decoded, msg);
}

#[test]
fn extended_protocol_messages_round_trip() {
    rt_frontend(FrontendMessage::Parse {
        statement: "stmt1".into(),
        sql: "SELECT * FROM accounts WHERE id = $1".into(),
        param_types: vec![23],
    });
    rt_frontend(FrontendMessage::Bind {
        portal: "p1".into(),
        statement: "stmt1".into(),
        rest: Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 2, b'4', b'2', 0, 0]),
    });
    rt_frontend(FrontendMessage::Describe {
        kind: TargetKind::Portal,
        name: "p1".into(),
    });
    rt_frontend(FrontendMessage::Execute {
        portal: "p1".into(),
        max_rows: 100,
    });
    rt_frontend(FrontendMessage::Sync);
    rt_frontend(FrontendMessage::Flush);
    rt_frontend(FrontendMessage::Close {
        kind: TargetKind::Statement,
        name: "stmt1".into(),
    });
    rt_frontend(FrontendMessage::Terminate);
}

#[test]
fn simple_query_and_copy_frontend_round_trip() {
    rt_frontend(FrontendMessage::Query {
        sql: "SELECT 1".into(),
    });
    rt_frontend(FrontendMessage::CopyData {
        data: Bytes::from_static(b"1\t2\n"),
    });
    rt_frontend(FrontendMessage::CopyDone);
    rt_frontend(FrontendMessage::CopyFail {
        message: "aborted".into(),
    });
}

#[test]
fn backend_core_messages_round_trip() {
    rt_backend(BackendMessage::AuthenticationOk);
    rt_backend(BackendMessage::AuthenticationCleartextPassword);
    rt_backend(BackendMessage::AuthenticationMd5Password {
        salt: [0xde, 0xad, 0xbe, 0xef],
    });
    rt_backend(BackendMessage::ParameterStatus {
        name: "server_version".into(),
        value: "18.0".into(),
    });
    rt_backend(BackendMessage::BackendKeyData {
        process_id: 4242,
        secret_key: 0x1122_3344,
    });
    rt_backend(BackendMessage::ReadyForQuery {
        status: TransactionStatus::Idle,
    });
    rt_backend(BackendMessage::ReadyForQuery {
        status: TransactionStatus::InTransaction,
    });
    rt_backend(BackendMessage::ReadyForQuery {
        status: TransactionStatus::Failed,
    });
    rt_backend(BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "ERROR".into()),
            (b'C', "42501".into()),
            (b'M', "read-only: write rejected".into()),
        ],
    });
    rt_backend(BackendMessage::CommandComplete {
        tag: "SELECT 3".into(),
    });
    rt_backend(BackendMessage::PortalSuspended);
    rt_backend(BackendMessage::ParseComplete);
    rt_backend(BackendMessage::BindComplete);
    rt_backend(BackendMessage::CloseComplete);
    rt_backend(BackendMessage::NoData);
    rt_backend(BackendMessage::EmptyQueryResponse);
}

#[test]
fn row_description_and_data_row_round_trip() {
    rt_backend(BackendMessage::RowDescription {
        fields: vec![
            FieldDescription {
                name: "id".into(),
                table_oid: 16384,
                column_attr: 1,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: 0,
            },
            FieldDescription {
                name: "name".into(),
                table_oid: 16384,
                column_attr: 2,
                type_oid: 25,
                type_size: -1,
                type_modifier: -1,
                format: 0,
            },
        ],
    });
    rt_backend(BackendMessage::DataRow {
        columns: vec![
            Some(Bytes::from_static(b"42")),
            None, // SQL NULL
            Some(Bytes::from_static(b"alice")),
        ],
    });
}

#[test]
fn copy_backend_messages_round_trip() {
    rt_backend(BackendMessage::CopyInResponse {
        format: 0,
        column_formats: vec![0, 0, 1],
    });
    rt_backend(BackendMessage::CopyOutResponse {
        format: 1,
        column_formats: vec![1, 1],
    });
    rt_backend(BackendMessage::CopyData {
        data: Bytes::from_static(b"row-bytes"),
    });
    rt_backend(BackendMessage::CopyDone);
}

#[test]
fn scram_backend_messages_round_trip() {
    rt_backend(BackendMessage::AuthenticationSasl(AuthenticationSasl {
        mechanisms: vec!["SCRAM-SHA-256".into(), "SCRAM-SHA-256-PLUS".into()],
    }));
    rt_backend(BackendMessage::AuthenticationSaslContinue(
        AuthenticationSaslContinue {
            data: Bytes::from_static(b"r=abc123,s=salt,i=4096"),
        },
    ));
    rt_backend(BackendMessage::AuthenticationSaslFinal(
        AuthenticationSaslFinal {
            data: Bytes::from_static(b"v=serversignature"),
        },
    ));
}

#[test]
fn scram_frontend_message_bodies_round_trip() {
    // SASLInitialResponse with an initial client response.
    let init = SaslInitialResponse {
        mechanism: "SCRAM-SHA-256".into(),
        initial_response: Some(Bytes::from_static(b"n,,n=agent,r=clientnonce")),
    };
    let frame = FrontendMessage::SaslInitialResponse(init.clone()).encode();
    let (tag, mut body) = split_tagged(frame);
    assert_eq!(tag, b'p');
    let decoded = SaslInitialResponse::decode_body_from(&mut body).expect("decode sasl-init");
    assert_eq!(decoded, init);

    // SASLInitialResponse with no initial response (length -1).
    let init_none = SaslInitialResponse {
        mechanism: "SCRAM-SHA-256".into(),
        initial_response: None,
    };
    let frame = FrontendMessage::SaslInitialResponse(init_none.clone()).encode();
    let (_, mut body) = split_tagged(frame);
    let decoded = SaslInitialResponse::decode_body_from(&mut body).expect("decode sasl-init none");
    assert_eq!(decoded, init_none);

    // SASLResponse (client-final-message).
    let resp = SaslResponse {
        data: Bytes::from_static(b"c=biws,r=clientservernonce,p=proof"),
    };
    let frame = FrontendMessage::SaslResponse(resp.clone()).encode();
    let (tag, mut body) = split_tagged(frame);
    assert_eq!(tag, b'p');
    let decoded = SaslResponse::decode_body_from(&mut body).expect("decode sasl-resp");
    assert_eq!(decoded, resp);
}

#[test]
fn password_message_round_trips() {
    rt_frontend(FrontendMessage::PasswordMessage {
        password: "md5deadbeef".into(),
    });
}
