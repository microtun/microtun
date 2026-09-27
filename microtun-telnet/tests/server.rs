use heapless::Vec;
use microtun_telnet::{
    IAC,
    client::{ClientEvent, ClientSession, SerialEvent},
    serial,
    server::{
        Parity, QueryOrSet, SerialRequest, SerialRequestError, ServerEvent, ServerSerialState,
        ServerSession,
    },
};

fn feed_client<const N: usize>(
    client: &mut ClientSession<256, 12, 64>,
    bytes: &[u8],
    reply: &mut Vec<u8, N>,
) -> std::vec::Vec<ClientEvent<64>> {
    let mut events = std::vec::Vec::new();
    for &byte in bytes {
        if let Some(event) = client.feed(byte, reply) {
            events.push(event);
        }
    }
    events
}

fn negotiate() -> (ClientSession<256, 12, 64>, ServerSession<256, 12>) {
    let mut client = ClientSession::<256, 12, 64>::new();
    let mut server = ServerSession::<256, 12>::new();
    let mut client_wire = Vec::<u8, 64>::new();
    let mut server_wire = Vec::<u8, 64>::new();

    client.enter_serial_mode(&mut client_wire).unwrap();
    server.start(&mut server_wire).unwrap();

    let client_bytes = client_wire.clone();
    client_wire.clear();
    let mut server_active = false;
    for &byte in client_bytes.as_slice() {
        if matches!(
            server.feed(byte, &mut server_wire),
            Some(ServerEvent::SerialModeActive)
        ) {
            server_active = true;
        }
    }

    let server_bytes = server_wire.clone();
    server_wire.clear();
    let mut client_active = false;
    for &byte in server_bytes.as_slice() {
        if matches!(
            client.feed(byte, &mut client_wire),
            Some(ClientEvent::SerialModeActive)
        ) {
            client_active = true;
        }
    }

    // Any Q-method acknowledgements generated above need one final pass.
    if !client_wire.is_empty() {
        let client_bytes = client_wire.clone();
        client_wire.clear();
        for &byte in client_bytes.as_slice() {
            if matches!(
                server.feed(byte, &mut server_wire),
                Some(ServerEvent::SerialModeActive)
            ) {
                server_active = true;
            }
        }
    }
    if !server_wire.is_empty() {
        let server_bytes = server_wire.clone();
        server_wire.clear();
        for &byte in server_bytes.as_slice() {
            if matches!(
                client.feed(byte, &mut client_wire),
                Some(ClientEvent::SerialModeActive)
            ) {
                client_active = true;
            }
        }
    }

    assert!(client_active || client.serial_active());
    assert!(server_active || server.serial_active());
    assert!(client.serial_active());
    assert!(server.serial_active());
    (client, server)
}

#[test]
fn client_and_server_negotiate_and_exchange_typed_settings() {
    let (mut client, mut server) = negotiate();

    let mut wire = Vec::<u8, 128>::new();
    client.queue_initial_serial_query(&mut wire).unwrap();

    let mut saw_parity_query = false;
    for &byte in wire.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        if let Some(ServerEvent::Serial(request)) = server.feed(byte, &mut reply)
            && request == SerialRequest::Parity(QueryOrSet::Query)
        {
            saw_parity_query = true;
        }
    }
    assert!(saw_parity_query);
    assert_eq!(server.serial_state().line_state_mask(), u8::MAX);
    assert_eq!(server.serial_state().modem_state_mask(), u8::MAX);

    wire.clear();
    client
        .queue_serial(
            serial::Message::FlowControlSuspend {
                origin: serial::Origin::Client,
            },
            &mut wire,
        )
        .unwrap();
    for &byte in wire.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        let _ = server.feed(byte, &mut reply);
    }
    assert!(server.serial_state().tx_suspended());

    wire.clear();
    client
        .queue_serial(
            serial::Message::FlowControlResume {
                origin: serial::Origin::Client,
            },
            &mut wire,
        )
        .unwrap();
    for &byte in wire.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        let _ = server.feed(byte, &mut reply);
    }
    assert!(!server.serial_state().tx_suspended());

    wire.clear();
    client.set_baud(115_200, &mut wire).unwrap();
    let mut saw_baud_request = false;
    for &byte in wire.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        if let Some(ServerEvent::Serial(request)) = server.feed(byte, &mut reply) {
            saw_baud_request |= request == SerialRequest::Baud(QueryOrSet::Set(115_200));
        }
    }
    assert!(saw_baud_request);

    let mut response = Vec::<u8, 32>::new();
    server.confirm_baud(115_200, &mut response).unwrap();
    let mut reply = Vec::<u8, 32>::new();
    let events = feed_client(&mut client, response.as_slice(), &mut reply);
    assert!(events.contains(&ClientEvent::Serial(SerialEvent::BaudRate(115_200))));

    wire.clear();
    client.set_rts(true, &mut wire).unwrap();
    let mut saw_rts_request = false;
    for &byte in wire.as_slice() {
        let mut reply = Vec::<u8, 32>::new();
        if let Some(ServerEvent::Serial(request)) = server.feed(byte, &mut reply) {
            saw_rts_request |= request == SerialRequest::Rts(QueryOrSet::Set(true));
        }
    }
    assert!(saw_rts_request);

    response.clear();
    server.confirm_rts(true, &mut response).unwrap();
    reply.clear();
    let events = feed_client(&mut client, response.as_slice(), &mut reply);
    assert!(events.contains(&ClientEvent::Serial(SerialEvent::Control(
        serial::control::RTS_ON
    ))));

    assert_eq!(
        server
            .serial_state_mut()
            .modem_state_changed(serial::modem_state::CTS),
        None
    );
    let modem = server.serial_state_mut().modem_state_changed(0).unwrap();
    response.clear();
    server.queue_serial(modem, &mut response).unwrap();
    reply.clear();
    let events = feed_client(&mut client, response.as_slice(), &mut reply);
    assert!(
        events.contains(&ClientEvent::Serial(SerialEvent::ModemState(
            serial::modem_state::DELTA_CTS
        )))
    );
}

#[test]
fn server_distinguishes_valid_unsupported_values_from_invalid_wire_values() {
    let mark = SerialRequest::from_message(serial::Message::SetParity {
        origin: serial::Origin::Client,
        value: serial::parity::MARK,
    });
    assert_eq!(
        mark,
        Ok(SerialRequest::Parity(QueryOrSet::Set(Parity::Mark)))
    );

    let invalid = SerialRequest::from_message(serial::Message::SetParity {
        origin: serial::Origin::Client,
        value: 99,
    });
    assert_eq!(
        invalid,
        Err(SerialRequestError::InvalidValue {
            command: serial::Command::SetParity,
            value: 99,
        })
    );
}

#[test]
fn protocol_only_server_state_tracks_masks_suspend_and_modem_deltas() {
    let mut state = ServerSerialState::new();
    assert_eq!(state.line_state_mask(), 0);
    assert_eq!(state.modem_state_mask(), u8::MAX);
    state.apply_request(&SerialRequest::LineStateMask(
        serial::line_state::OVERRUN_ERROR | serial::line_state::FRAMING_ERROR,
    ));
    state.apply_request(&SerialRequest::ModemStateMask(u8::MAX));
    state.apply_request(&SerialRequest::Suspend);

    assert!(state.tx_suspended());
    assert_eq!(
        state.line_state(serial::line_state::OVERRUN_ERROR),
        Some(serial::Message::NotifyLineState {
            origin: serial::Origin::Server,
            value: serial::line_state::OVERRUN_ERROR,
        })
    );

    assert_eq!(
        state.modem_state_changed(serial::modem_state::CTS | serial::modem_state::RING_INDICATOR),
        None
    );
    assert_eq!(
        state.modem_state_changed(0),
        Some(serial::Message::NotifyModemState {
            origin: serial::Origin::Server,
            value: serial::modem_state::DELTA_CTS | serial::modem_state::TRAILING_EDGE_RING,
        })
    );

    state.apply_request(&SerialRequest::Resume);
    assert!(!state.tx_suspended());
}

#[test]
fn server_unescapes_iac_application_data_in_serial_mode() {
    let (_client, mut server) = negotiate();
    let mut reply = Vec::<u8, 32>::new();

    assert_eq!(server.feed(IAC, &mut reply), None);
    assert_eq!(server.feed(IAC, &mut reply), Some(ServerEvent::Data(IAC)));
}
