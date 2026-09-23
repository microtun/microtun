use heapless::Vec;
use microtun_cli::{
    lexer::lex,
    telnet::{DO, IAC, OPT_ECHO, OPT_NAWS, SB, SE, Telnet, TelnetEvent, WILL},
};

#[test]
fn lexer_compacts_quotes_and_escapes_in_place() {
    let mut bytes = *b"echo \"hello world\" a\\ b                       ";
    let len = b"echo \"hello world\" a\\ b".len();
    let lexed = lex(&mut bytes, len).unwrap();
    assert_eq!(lexed.len(), 3);
    assert_eq!(lexed.arg(0).unwrap(), "echo");
    assert_eq!(lexed.arg(1).unwrap(), "hello world");
    assert_eq!(lexed.arg(2).unwrap(), "a b");
}

#[test]
fn telnet_unescapes_iac_data() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut reply = Vec::<u8, 32>::new();
    assert_eq!(telnet.feed(IAC, &mut reply), None);
    assert_eq!(telnet.feed(IAC, &mut reply), Some(TelnetEvent::Data(IAC)));
}

#[test]
fn telnet_tracks_naws() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut reply = Vec::<u8, 32>::new();

    // Client agrees to NAWS, then reports 120x40.
    assert_eq!(telnet.feed(IAC, &mut reply), None);
    assert_eq!(telnet.feed(WILL, &mut reply), None);
    assert_eq!(telnet.feed(OPT_NAWS, &mut reply), None);
    assert_eq!(telnet.feed(IAC, &mut reply), None);
    assert_eq!(telnet.feed(SB, &mut reply), None);
    assert_eq!(telnet.feed(OPT_NAWS, &mut reply), None);
    for b in [0, 120, 0, 40] {
        assert_eq!(telnet.feed(b, &mut reply), None);
    }
    assert_eq!(telnet.feed(IAC, &mut reply), None);
    assert_eq!(
        telnet.feed(SE, &mut reply),
        Some(TelnetEvent::WindowSizeChanged)
    );
    assert_eq!(telnet.window_size(), Some((120, 40)));
}

#[test]
fn initial_negotiation_requests_echo() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut out = Vec::<u8, 32>::new();
    telnet.initial_negotiation(&mut out);
    assert!(out.windows(3).any(|chunk| chunk == [IAC, WILL, OPT_ECHO]));
    assert!(
        out.windows(3)
            .any(|chunk| chunk[0] == IAC && chunk[1] == DO)
    );
}

// ---------------------------------------------------------------------------
// Regression tests for telnet fixes
// ---------------------------------------------------------------------------

use microtun_cli::telnet::{DONT, OPT_SUPPRESS_GO_AHEAD, OPT_TERMINAL_TYPE, SB as SB_, WONT};

#[test]
fn echo_state_is_observable_and_tracks_refusal() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut out = Vec::<u8, 32>::new();
    telnet.initial_negotiation(&mut out);

    // The offer is outstanding: not enabled, but not refused either.
    assert!(!telnet.us_enabled(OPT_ECHO));
    assert!(telnet.us_pending(OPT_ECHO));

    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, DO, OPT_ECHO] {
        telnet.feed(byte, &mut reply);
    }
    assert!(telnet.us_enabled(OPT_ECHO));
    assert!(!telnet.us_pending(OPT_ECHO));
}

#[test]
fn a_client_refusing_echo_leaves_it_disabled() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut out = Vec::<u8, 32>::new();
    telnet.initial_negotiation(&mut out);

    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, DONT, OPT_ECHO] {
        telnet.feed(byte, &mut reply);
    }
    assert!(!telnet.us_enabled(OPT_ECHO));
    assert!(!telnet.us_pending(OPT_ECHO));
}

#[test]
fn zero_naws_dimensions_mean_unknown() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, WILL, OPT_NAWS, IAC, SB_, OPT_NAWS, 0, 0, 0, 0, IAC, SE] {
        telnet.feed(byte, &mut reply);
    }
    assert_eq!(telnet.window_size(), None);
}

#[test]
fn negotiation_state_does_not_advance_when_the_reply_buffer_is_full() {
    let mut telnet = Telnet::<64, 32>::new();

    // A buffer with no room at all: the reply cannot be emitted.
    let mut full = Vec::<u8, 0>::new();
    for byte in [IAC, DO, OPT_SUPPRESS_GO_AHEAD] {
        telnet.feed(byte, &mut full);
    }
    // Nothing was sent, so nothing may be treated as agreed.
    assert!(!telnet.us_enabled(OPT_SUPPRESS_GO_AHEAD));

    // The peer repeats itself and this time there is room; the handshake completes.
    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, DO, OPT_SUPPRESS_GO_AHEAD] {
        telnet.feed(byte, &mut reply);
    }
    assert!(telnet.us_enabled(OPT_SUPPRESS_GO_AHEAD));
    assert_eq!(reply.as_slice(), &[IAC, WILL, OPT_SUPPRESS_GO_AHEAD]);
}

#[test]
fn a_terminal_type_request_that_did_not_fit_is_retried() {
    let mut telnet = Telnet::<64, 32>::new();

    // Room for the DO reply but not the six-byte SEND subnegotiation that follows it.
    let mut cramped = Vec::<u8, 3>::new();
    for byte in [IAC, WILL, OPT_TERMINAL_TYPE] {
        telnet.feed(byte, &mut cramped);
    }
    assert_eq!(cramped.as_slice(), &[IAC, DO, OPT_TERMINAL_TYPE]);

    // The next byte carries the deferred request rather than losing it.
    let mut reply = Vec::<u8, 32>::new();
    telnet.feed(NOP_BYTE, &mut reply);
    assert!(
        reply
            .windows(4)
            .any(|chunk| chunk == [IAC, SB_, OPT_TERMINAL_TYPE, 1])
    );
}

const NOP_BYTE: u8 = 0;

#[test]
fn wont_after_will_disables_the_option() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, WILL, OPT_NAWS] {
        telnet.feed(byte, &mut reply);
    }
    assert!(telnet.him_enabled(OPT_NAWS));
    for byte in [IAC, WONT, OPT_NAWS] {
        telnet.feed(byte, &mut reply);
    }
    assert!(!telnet.him_enabled(OPT_NAWS));
}
