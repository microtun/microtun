use heapless::Vec;
use microtun_telnet_proto::{
    DO, IAC, OPT_BINARY, OPT_ECHO, Policy, SB, SE, Side, Telnet, TelnetEvent, WILL,
};

#[derive(Clone, Copy)]
struct TerminalPolicy;

impl Policy for TerminalPolicy {
    fn support_us(&self, option: u8) -> bool {
        option != OPT_ECHO
    }

    fn support_him(&self, _option: u8) -> bool {
        true
    }
}

#[test]
fn q_method_does_not_ack_repeated_will() {
    let mut telnet = Telnet::<TerminalPolicy, 64, 8>::new(TerminalPolicy);
    let mut reply = Vec::<u8, 16>::new();

    assert_eq!(telnet.feed(IAC, &mut reply), None);
    assert_eq!(telnet.feed(WILL, &mut reply), None);
    assert_eq!(
        telnet.feed(OPT_ECHO, &mut reply),
        Some(TelnetEvent::OptionEnabled {
            side: Side::Him,
            option: OPT_ECHO,
        })
    );
    assert_eq!(reply.as_slice(), &[IAC, DO, OPT_ECHO]);

    reply.clear();
    for byte in [IAC, WILL, OPT_ECHO] {
        telnet.feed(byte, &mut reply);
    }
    assert!(reply.is_empty());
}

#[test]
fn option_policy_is_directional() {
    let mut telnet = Telnet::<TerminalPolicy, 64, 8>::new(TerminalPolicy);
    let mut reply = Vec::<u8, 16>::new();

    for byte in [IAC, DO, OPT_ECHO] {
        telnet.feed(byte, &mut reply);
    }
    assert_eq!(
        reply.as_slice(),
        &[IAC, microtun_telnet_proto::WONT, OPT_ECHO]
    );
    assert!(!telnet.us_enabled(OPT_ECHO));

    reply.clear();
    for byte in [IAC, WILL, OPT_ECHO] {
        telnet.feed(byte, &mut reply);
    }
    assert_eq!(reply.as_slice(), &[IAC, DO, OPT_ECHO]);
    assert!(telnet.him_enabled(OPT_ECHO));
}

#[test]
fn subnegotiation_unescapes_iac() {
    let mut telnet = Telnet::<TerminalPolicy, 64, 8>::new(TerminalPolicy);
    let mut reply = Vec::<u8, 16>::new();
    let option = 44;
    let mut event = None;
    for byte in [IAC, SB, option, 1, IAC, IAC, 2, IAC, SE] {
        event = telnet.feed(byte, &mut reply).or(event);
    }
    assert_eq!(event, Some(TelnetEvent::Subnegotiation(option)));
    assert_eq!(telnet.subnegotiation(), (option, &[1, IAC, 2][..]));
}

#[test]
fn binary_helpers_negotiate_both_directions() {
    let mut telnet = Telnet::<TerminalPolicy, 64, 8>::new(TerminalPolicy);
    let mut wire = Vec::<u8, 16>::new();

    telnet.request_binary_mode(&mut wire);
    assert_eq!(
        wire.as_slice(),
        &[
            IAC,
            microtun_telnet_proto::WILL,
            OPT_BINARY,
            IAC,
            DO,
            OPT_BINARY
        ]
    );
    assert!(!telnet.binary_mode_enabled());
    assert!(!telnet.binary_mode_refused());

    wire.clear();
    for byte in [IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY] {
        telnet.feed(byte, &mut wire);
    }
    assert!(telnet.binary_mode_enabled());

    wire.clear();
    telnet.disable_binary_mode(&mut wire);
    assert_eq!(
        wire.as_slice(),
        &[
            IAC,
            microtun_telnet_proto::WONT,
            OPT_BINARY,
            IAC,
            microtun_telnet_proto::DONT,
            OPT_BINARY,
        ]
    );
}

#[test]
fn q_method_reports_rejected_enable_request() {
    let mut telnet = Telnet::<TerminalPolicy, 64, 8>::new(TerminalPolicy);
    let mut wire = Vec::<u8, 16>::new();

    telnet.request_us(OPT_BINARY, &mut wire);
    wire.clear();
    let mut event = None;
    for byte in [IAC, microtun_telnet_proto::DONT, OPT_BINARY] {
        event = telnet.feed(byte, &mut wire).or(event);
    }
    assert_eq!(
        event,
        Some(TelnetEvent::OptionRefused {
            side: Side::Us,
            option: OPT_BINARY,
        })
    );
}
