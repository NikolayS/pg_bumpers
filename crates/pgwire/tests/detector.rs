//! Rejection-detector tests (SPEC §3 layer 2, §7 S1).
//!
//! The proxy must detect simple `Query` ('Q') and `Copy*` frames so it can
//! reject them and force the extended protocol.

use bytes::Bytes;
use pgb_pgwire::codec::RawFrame;
use pgb_pgwire::detector::{
    RejectReason, backend_starts_copy, classify_frontend_frame, classify_frontend_tag,
};
use pgb_pgwire::frontend::{FrontendMessage, TargetKind};

fn frame_of(msg: FrontendMessage) -> RawFrame {
    use bytes::Buf;
    let mut b = msg.encode().freeze();
    let tag = b.get_u8();
    let _len = b.get_i32();
    RawFrame { tag, body: b }
}

#[test]
fn simple_query_is_rejected() {
    let frame = frame_of(FrontendMessage::Query {
        sql: "SELECT 1; DROP SCHEMA public".into(),
    });
    assert_eq!(
        classify_frontend_frame(&frame),
        Err(RejectReason::SimpleQuery)
    );
}

#[test]
fn copy_frontend_frames_are_rejected() {
    let copy_data = frame_of(FrontendMessage::CopyData {
        data: Bytes::from_static(b"1\t2\n"),
    });
    let copy_done = frame_of(FrontendMessage::CopyDone);
    let copy_fail = frame_of(FrontendMessage::CopyFail {
        message: "x".into(),
    });
    assert_eq!(classify_frontend_frame(&copy_data), Err(RejectReason::Copy));
    assert_eq!(classify_frontend_frame(&copy_done), Err(RejectReason::Copy));
    assert_eq!(classify_frontend_frame(&copy_fail), Err(RejectReason::Copy));
}

#[test]
fn extended_protocol_frames_are_allowed() {
    let allowed = [
        frame_of(FrontendMessage::Parse {
            statement: "s".into(),
            sql: "SELECT 1".into(),
            param_types: vec![],
        }),
        frame_of(FrontendMessage::Bind {
            portal: "p".into(),
            statement: "s".into(),
            rest: Bytes::from_static(&[0, 0, 0, 0, 0, 0]),
        }),
        frame_of(FrontendMessage::Describe {
            kind: TargetKind::Portal,
            name: "p".into(),
        }),
        frame_of(FrontendMessage::Execute {
            portal: "p".into(),
            max_rows: 0,
        }),
        frame_of(FrontendMessage::Sync),
        frame_of(FrontendMessage::Close {
            kind: TargetKind::Statement,
            name: "s".into(),
        }),
        frame_of(FrontendMessage::Terminate),
    ];
    for f in &allowed {
        assert_eq!(
            classify_frontend_frame(f),
            Ok(()),
            "tag {:?} should be allowed",
            f.tag as char
        );
    }
}

#[test]
fn tag_only_classifier_matches_frame_classifier() {
    assert_eq!(classify_frontend_tag(b'Q'), Err(RejectReason::SimpleQuery));
    assert_eq!(classify_frontend_tag(b'd'), Err(RejectReason::Copy));
    assert_eq!(classify_frontend_tag(b'P'), Ok(()));
}

#[test]
fn backend_copy_start_is_detected() {
    for tag in [b'G', b'H', b'W'] {
        let frame = RawFrame {
            tag,
            body: Bytes::new(),
        };
        assert!(backend_starts_copy(&frame), "tag {:?}", tag as char);
    }
    let not_copy = RawFrame {
        tag: b'T',
        body: Bytes::new(),
    };
    assert!(!backend_starts_copy(&not_copy));
}
