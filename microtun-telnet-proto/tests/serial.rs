use heapless::Vec;
use microtun_telnet_proto::{IAC, OPT_COM_PORT, SB, SE, serial};
use serial::{Message, Origin};

#[test]
fn baud_rate_request_round_trips() {
    let message = Message::SetBaudRate {
        origin: Origin::Client,
        value: 115_200,
    };
    let mut wire = Vec::<u8, 32>::new();
    assert!(serial::encode(message, &mut wire));
    assert_eq!(
        wire.as_slice(),
        &[
            IAC,
            SB,
            OPT_COM_PORT,
            serial::SET_BAUDRATE,
            0,
            1,
            0xc2,
            0,
            IAC,
            SE
        ]
    );
    assert_eq!(serial::decode(&wire.as_slice()[3..8]), Ok(message));
}

#[test]
fn server_confirmation_uses_100_offset() {
    let message = Message::SetDataSize {
        origin: Origin::Server,
        value: serial::data_size::EIGHT,
    };
    let mut wire = Vec::<u8, 16>::new();
    assert!(serial::encode(message, &mut wire));
    assert_eq!(wire[3], 102);
    assert_eq!(serial::decode(&wire.as_slice()[3..5]), Ok(message));
}

#[test]
fn signature_escapes_iac_and_decodes_after_telnet_unescaping() {
    let text = [b'M', IAC, b'T'];
    let message = Message::Signature {
        origin: Origin::Server,
        text: &text,
    };
    let mut wire = Vec::<u8, 16>::new();
    assert!(serial::encode(message, &mut wire));
    assert_eq!(
        wire.as_slice(),
        &[
            IAC,
            SB,
            OPT_COM_PORT,
            serial::SIGNATURE + 100,
            b'M',
            IAC,
            IAC,
            b'T',
            IAC,
            SE
        ]
    );

    // The Telnet core removes the doubled IAC before serial decoding.
    let payload = [serial::SIGNATURE + 100, b'M', IAC, b'T'];
    assert_eq!(serial::decode_from(Origin::Server, &payload), Ok(message));

    // Also accept the legacy/ambiguous code 0 when the caller supplies server context.
    let legacy_payload = [serial::SIGNATURE, b'M', IAC, b'T'];
    assert_eq!(
        serial::decode_from(Origin::Server, &legacy_payload),
        Ok(message)
    );
}

#[test]
fn flow_control_commands_have_no_value_octet() {
    let message = Message::FlowControlSuspend {
        origin: Origin::Client,
    };
    let mut wire = Vec::<u8, 16>::new();
    assert!(serial::encode(message, &mut wire));
    assert_eq!(
        wire.as_slice(),
        &[IAC, SB, OPT_COM_PORT, serial::FLOWCONTROL_SUSPEND, IAC, SE]
    );
    assert_eq!(serial::decode(&[serial::FLOWCONTROL_SUSPEND]), Ok(message));
}
