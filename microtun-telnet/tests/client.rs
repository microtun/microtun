use heapless::Vec;
use microtun_telnet::{
    DO, DONT, IAC, OPT_BINARY, OPT_COM_PORT, OPT_SUPPRESS_GO_AHEAD, SB, SE,
    client::{ClientEvent, ClientSession, SerialEvent, SerialStatus},
    serial,
};

#[test]
fn serial_mode_negotiation_is_owned_by_client_session() {
    let mut client = ClientSession::<256, 12, 64>::new();
    let mut wire = Vec::<u8, 32>::new();

    assert_eq!(client.enter_serial_mode(&mut wire), Ok(true));
    assert_eq!(
        wire.as_slice(),
        &[
            IAC,
            microtun_telnet::WILL,
            OPT_BINARY,
            IAC,
            DO,
            OPT_BINARY,
            IAC,
            microtun_telnet::WILL,
            OPT_SUPPRESS_GO_AHEAD,
            IAC,
            DO,
            OPT_SUPPRESS_GO_AHEAD,
            IAC,
            microtun_telnet::WILL,
            OPT_COM_PORT,
        ]
    );
    assert!(client.serial_mode());
    assert_eq!(
        client.serial_state().map(|state| state.status),
        Some(SerialStatus::Negotiating)
    );
}

#[test]
fn com_port_refusal_is_reported_without_host_side_pending_checks() {
    let mut client = ClientSession::<256, 12, 64>::new();
    let mut wire = Vec::<u8, 32>::new();
    client.enter_serial_mode(&mut wire).unwrap();

    let mut event = None;
    for byte in [IAC, DONT, OPT_COM_PORT] {
        let mut reply = Vec::<u8, 32>::new();
        event = client.feed(byte, &mut reply).or(event);
    }

    assert!(matches!(event, Some(ClientEvent::SerialModeRefused)));
    assert_eq!(
        client.serial_state().map(|state| state.status),
        Some(SerialStatus::Refused)
    );
}

#[test]
fn initial_serial_query_and_state_tracking_are_shared() {
    let mut client = ClientSession::<256, 12, 64>::new();
    let mut wire = Vec::<u8, 32>::new();
    client.enter_serial_mode(&mut wire).unwrap();

    for byte in [IAC, DO, OPT_COM_PORT] {
        let mut reply = Vec::<u8, 32>::new();
        let _ = client.feed(byte, &mut reply);
    }
    assert!(client.serial_active());

    let mut query = Vec::<u8, 128>::new();
    assert_eq!(client.queue_initial_serial_query(&mut query), Ok(true));
    assert_eq!(query.len(), 88);
    assert_eq!(&query.as_slice()[..4], &[IAC, SB, OPT_COM_PORT, 0]);
    assert_eq!(&query.as_slice()[query.len() - 3..], &[IAC, IAC, SE]);
    assert_eq!(client.queue_initial_serial_query(&mut query), Ok(false));

    let mut response = Vec::<u8, 32>::new();
    assert!(serial::encode(
        serial::Message::SetBaudRate {
            origin: serial::Origin::Server,
            value: 115_200,
        },
        &mut response,
    ));

    let mut received = None;
    for &byte in response.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        if let Some(event) = client.feed(byte, &mut reply) {
            received = Some(event);
        }
    }
    assert_eq!(
        received,
        Some(ClientEvent::Serial(SerialEvent::BaudRate(115_200)))
    );
    assert_eq!(
        client.serial_state().and_then(|state| state.baud),
        Some(115_200)
    );
}

#[test]
fn ordinary_data_stays_data_while_serial_mode_is_active() {
    let mut client = ClientSession::<256, 12, 64>::new();
    let mut wire = Vec::<u8, 32>::new();
    client.enter_serial_mode(&mut wire).unwrap();

    let mut reply = Vec::<u8, 32>::new();
    assert_eq!(client.feed(b'x', &mut reply), Some(ClientEvent::Data(b'x')));
    assert!(reply.is_empty());

    // IAC IAC remains one application byte in BINARY mode as required by TELNET framing.
    assert_eq!(client.feed(IAC, &mut reply), None);
    assert_eq!(client.feed(IAC, &mut reply), Some(ClientEvent::Data(IAC)));
}
