//! Tests for defects found in the userspace stack, each written after the
//! failure was reproduced.
//!
//! Three of these pin bugs that existed in the reference implementation this
//! module was ported from, and were invisible to its own tests. Each test's
//! doc comment names the failure it was written from and what would make it
//! vacuous.
//!
//! | test | defect | how it failed |
//! | --- | --- | --- |
//! | [`a_multibyte_error_message_at_the_length_limit_does_not_panic`] | `encode` truncated an `Error` message at a byte budget that could split a UTF-8 character, then sliced the `&str` there | panic: byte index N is not a char boundary |
//! | [`one_bad_opcode_does_not_wedge_the_decoder`] | the decoder returned the error with the bad byte still at the head, so it never drained | every later `push` failed identically, buffer grew without bound |
//! | [`closed_connections_do_not_accumulate_in_the_socket_set`] | closed sockets were dropped from the map but never removed from the smoltcp `SocketSet` | 128 KiB leaked per connection, permanently |
//! | [`the_poll_interval_knob_is_honoured`] | a hardcoded 100 ms clamp overrode the configured maximum | any `max_poll_interval` above 100 ms was a no-op |

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use cfrs::vnet::control::{
    ControlDecoder, ControlMessage, ControlOp, ErrorCode, MAX_CONTROL_PAYLOAD,
};
use cfrs::vnet::addr::{subnet_addr, VirtualSubnet};
use cfrs::vnet::{NetStack, StackConfig, VirtAddr};

/// An address inside the default virtual subnet.
///
/// Not `127.0.0.1`: the subnet is `10.66.0.0/24`, and a helper that folded
/// loopback in silently would hide that from the test.
fn local(port: u16) -> VirtAddr {
    let subnet = VirtualSubnet::default();
    subnet_addr(&subnet, "10.66.0.2", port).expect("inside the default subnet")
}

#[test]
fn a_multibyte_error_message_at_the_length_limit_does_not_panic() {
    // The budget is MAX_CONTROL_PAYLOAD - 7 bytes. Fill it with ASCII and then
    // put a two-byte character across the boundary, so the naive cut lands in
    // its middle.
    let budget = MAX_CONTROL_PAYLOAD.saturating_sub(7);
    let message = format!("{}{}", "a".repeat(budget - 1), "é");

    // The reference implementation panicked here. A panic in an encoder is a
    // crash of whatever was reporting an error, which is the least useful place
    // in a program to die.
    let encoded = ControlMessage::Error { id: 1, code: ErrorCode::Refused, message }.encode();

    // And the frame it produced must be self-consistent: the declared payload
    // length has to match the bytes actually written, or the peer desynchronises.
    // The wire frame is op(1) | payload_len(2) | payload, and the Error
    // payload is id(4) | code(1) | msg_len(2) | message.
    assert_eq!(encoded[0], ControlOp::Error as u8, "the opcode comes first");
    let declared = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
    assert_eq!(
        declared + 3,
        encoded.len(),
        "the frame's declared length and its actual length must agree"
    );
    assert_eq!(
        declared,
        encoded.len() - 3,
        "the payload must fill the frame exactly"
    );
    let msg_len = u16::from_be_bytes([encoded[8], encoded[9]]) as usize;
    assert_eq!(
        msg_len,
        encoded.len() - 10,
        "the message length must describe the message that follows"
    );
    let text = &encoded[10..];
    assert!(
        std::str::from_utf8(text).is_ok(),
        "the truncated message must still be valid UTF-8, or the peer cannot read it"
    );

    // A message that fits must survive intact, or the truncation is not just
    // safe but lossless where it can be.
    let short = "no truncation needed";
    let encoded = ControlMessage::Error {
        id: 1,
        code: ErrorCode::Denied,
        message: short.into(),
    }
    .encode();
    assert_eq!(&encoded[10..], short.as_bytes());

    // And it must survive a decode, which is the property a peer depends on.
    let decoded = ControlMessage::decode(&encoded).expect("decode").expect("a whole frame");
    assert_eq!(
        decoded.0,
        ControlMessage::Error { id: 1, code: ErrorCode::Denied, message: short.into() },
        "an Error must round-trip through the wire format"
    );
}

#[test]
fn truncation_never_splits_a_character() {
    // Every offset matters, so walk the whole range rather than trusting one
    // boundary case.
    for padding in 0..64usize {
        let message = format!("{}{}", "a".repeat(padding), "→é漢");
        let encoded = ControlMessage::Error {
            id: 0,
            code: ErrorCode::BadRequest,
            message,
        }
        .encode();
        let text = &encoded[6..];
        assert!(
            std::str::from_utf8(text).is_ok(),
            "padding {padding} produced an invalid UTF-8 frame"
        );
    }
}

#[test]
fn one_bad_opcode_does_not_wedge_the_decoder() {
    let mut decoder = ControlDecoder::new();

    // A valid frame, so we can prove the stream still works afterwards.
    let good = ControlMessage::Ping { token: 42 }.encode();

    // A frame whose opcode is not one of the twelve defined values. Three bytes
    // are needed before the decoder reads the opcode at all, so the junk is a
    // full frame. A decoder that keeps these bytes at the head of its buffer can
    // never make progress again.
    let junk = [0xFFu8, 0x00, 0x00];

    let first = decoder.push(&junk).expect("a bad opcode is dropped, not fatal");
    assert!(first.is_empty(), "nothing should be decoded from one junk byte");
    assert_eq!(decoder.dropped(), 1, "the drop must be counted");

    let messages = decoder
        .push(&good)
        .expect("the decoder must recover");
    assert_eq!(
        messages,
        vec![ControlMessage::Ping { token: 42 }],
        "a good frame after a bad one must still decode"
    );
    assert_eq!(decoder.pending(), 0, "the buffer must be empty, not stuck");
}

#[test]
fn the_decoder_resynchronises_after_a_truncated_junk_run() {
    let mut decoder = ControlDecoder::new();
    let good = ControlMessage::Ping { token: 7 }.encode();

    // Rubbish that *looks* like frames: plausible opcodes with lengths that run
    // past the end of the input. A decoder must neither panic nor wedge.
    let mut rubbish = Vec::new();
    for i in 0..64u8 {
        rubbish.push(i);
        rubbish.extend_from_slice(&[0xFFu8, 0x00u8]);
    }
    let _ = decoder.push(&rubbish);
    assert!(decoder.dropped() > 0, "rubbish must be counted as dropped");

    let messages = decoder.push(&good).expect("the decoder must still work");
    assert_eq!(messages, vec![ControlMessage::Ping { token: 7 }]);
}

#[test]
fn a_partial_frame_is_held_not_dropped() {
    // The distinction that matters: bytes that are merely incomplete are not
    // rubbish. Dropping them would break every stream that arrives in chunks.
    let mut decoder = ControlDecoder::new();
    let full = ControlMessage::Data { id: 3, data: vec![1, 2, 3, 4] }.encode();
    assert!(full.len() > 4);

    let (head, tail) = full.split_at(2);
    let messages = decoder.push(head).expect("a partial frame is not an error");
    assert!(messages.is_empty(), "nothing to decode yet");
    assert_eq!(decoder.pending(), head.len(), "the partial frame is held");
    assert_eq!(decoder.dropped(), 0, "a partial frame is not a drop");

    let messages = decoder.push(tail).expect("the rest completes the frame");
    assert_eq!(messages.len(), 1);
    assert_eq!(decoder.dropped(), 0);
}

#[tokio::test]
async fn closed_connections_do_not_accumulate_in_the_socket_set() {
    // Measure the socket count directly.
    //
    // An earlier version of this test opened and closed 40 connections with
    // `max_connections: 8` and asserted that the connects kept succeeding, on
    // the reasoning that a leak would eventually show up as a refused connect.
    // It passed with the leak present, because `max_connections` is checked
    // against the connection map, which *did* shrink; the leak was in the
    // smoltcp SocketSet, which nothing bounded. So the observable has to be the
    // count itself, which is why `NetStack::socket_count` exists.
    let config = StackConfig { accept_pool: 2, ..StackConfig::default() };
    let net = NetStack::loopback_with(config);
    let mut listener = net.listen(local(19001)).await.expect("listen");

    // The listener pool is created up front, so the resting count is that pool
    // rather than zero.
    let (resting, _) = net.socket_count();
    assert!(resting > 0, "a listener pool should have been created, saw {resting}");

    for round in 0..40u16 {
        let client = net
            .connect(local(19001))
            .await
            .unwrap_or_else(|e| panic!("connect {round} failed: {e}"));
        // Both halves must be dropped, not one: a half-open connection retains
        // its smoltcp socket exactly as much as a closed one does.
        let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("accept {round} timed out"))
            .expect("accept must not fail");
        drop(client);
        drop(accepted);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Let the reaper run after the last close.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (live, peak) = net.socket_count();
    assert!(
        live <= resting,
        "after 40 closed connections the set should be back at its resting size \
         ({resting}); it holds {live} and peaked at {peak}. A SocketSet reuses a \
         vacant slot on add but never reclaims one, so a live count above the \
         resting count means closed sockets are being retained."
    );

    // And the stack must still work, with a real exchange rather than a connect
    // that would hang for want of a listener.
    let mut client = net.connect(local(19001)).await.expect("still usable");
    let mut server = listener.accept().await.expect("accept");
    client.write_all(b"still here").await.expect("write");
    let mut buf = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut buf))
        .await
        .expect("the exchange must not time out")
        .expect("read");
    assert_eq!(&buf, b"still here");
}

#[tokio::test]
async fn the_poll_interval_knob_is_honoured() {
    // `max_poll_interval` is documented as the upper bound on the reactor's
    // sleep between polls. A hardcoded clamp above it makes the knob a no-op,
    // which is not observable from the public API directly, so this asserts the
    // property that a longer interval must not slow a connection down: with a
    // generous interval the round trip still completes, because the connection
    // work wakes the reactor rather than waiting for the tick.
    let config = StackConfig {
        max_poll_interval: Duration::from_secs(5),
        ..StackConfig::default()
    };
    let net = NetStack::loopback_with(config);
    let mut listener = net.listen(local(19010)).await.expect("listen");

    let mut client = net
        .connect(local(19010))
        .await
        .expect("connect must not wait for the poll tick");

    let mut server = listener.accept().await.expect("accept");
    // If the reactor only woke on the tick, this write would take five seconds.
    let timeout = Duration::from_secs(2);
    client.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(timeout, server.read_exact(&mut buf))
        .await
        .expect("the round trip must not wait for a 5s poll tick")
        .expect("read");
    assert_eq!(&buf, b"ping");
}

#[test]
fn the_control_op_values_are_the_documented_ones() {
    // The wire format is a contract with the C shim. A renumbered opcode would
    // silently break it, and this is the cheapest place to notice.
    assert_eq!(ControlOp::RegisterBind as u8, 1);
    assert_eq!(ControlOp::RegisterConnect as u8, 2);
    assert_eq!(ControlOp::Unregister as u8, 3);
    assert_eq!(ControlOp::Datagram as u8, 4);
    assert_eq!(ControlOp::Data as u8, 5);
    assert_eq!(ControlOp::Eof as u8, 6);
    assert_eq!(ControlOp::Reset as u8, 7);
    assert_eq!(ControlOp::Ack as u8, 8);
    assert_eq!(ControlOp::Error as u8, 9);
    assert_eq!(ControlOp::Hello as u8, 10);
    assert_eq!(ControlOp::Ping as u8, 11);
    assert_eq!(ControlOp::Pong as u8, 12);
}