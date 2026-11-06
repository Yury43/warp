use super::*;

#[test]
fn fragmented_binary_frames_are_reassembled() {
    let mut decoder = Decoder::default();
    let message = frame(b'O', b"\0\xff\x1b[31m");
    assert!(decoder.feed(&message[..3]).unwrap().is_empty());
    assert!(decoder.feed(&message[3..7]).unwrap().is_empty());
    assert_eq!(
        decoder.feed(&message[7..]).unwrap(),
        vec![(b'O', b"\0\xff\x1b[31m".to_vec())]
    );
}

#[test]
fn multiple_frames_keep_their_order() {
    let mut decoder = Decoder::default();
    let mut data = frame(b'D', b"one");
    data.extend(frame(b'X', b"two"));
    assert_eq!(
        decoder.feed(&data).unwrap(),
        vec![(b'D', b"one".to_vec()), (b'X', b"two".to_vec())]
    );
}

#[test]
fn oversized_frame_is_rejected_before_receiving_payload() {
    assert!(Decoder::default().feed(b"O\x00\x10\x00\x01").is_err());
}

#[test]
fn handshake_rejects_invalid_terminal_dimensions() {
    let data = json_frame(
        b'H',
        &serde_json::json!({
            "name": "work", "action": "attach", "client": "abc",
            "size": [24, 65536], "term": "xterm"
        }),
    );
    assert!(read_request(&mut data.as_slice()).is_err());
}

#[test]
fn handshake_rejects_negative_output_cursor() {
    let data = json_frame(
        b'H',
        &serde_json::json!({
            "name": "work", "action": "attach", "client": "abc",
            "size": [24, 80], "term": "xterm", "offset": -1
        }),
    );
    assert!(read_request(&mut data.as_slice()).is_err());
}
