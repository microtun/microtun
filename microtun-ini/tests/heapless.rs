#![cfg(feature = "heapless")]

mod common;

use common::{Interface, MIXED_CASE_SAMPLE, Peer, SAMPLE};
use microtun_ini::{from_str, heapless::Vec};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Config<'a> {
    #[serde(rename = "Interface", borrow)]
    interface: Interface<'a>,
    #[serde(rename = "Peer", borrow)]
    peers: Vec<Peer<'a, Vec<&'a str, 4>>, 4>,
}

#[test]
fn parses_into_fixed_capacity_collections() {
    let config: Config<'_> = from_str(SAMPLE).unwrap();
    assert_eq!(config.interface.address, "10.14.0.2/32");
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].allowed_ips.len(), 2);
}

#[test]
fn names_are_case_insensitive_without_alloc() {
    let config: Config<'_> = from_str(MIXED_CASE_SAMPLE).unwrap();
    assert_eq!(config.interface.listen_port, 51820);
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].allowed_ips.len(), 2);
}

#[test]
fn reports_capacity_overflow_as_a_serde_error() {
    #[derive(Debug, Deserialize)]
    struct OnePeer<'a> {
        #[serde(rename = "Peer", borrow)]
        _peers: Vec<Peer<'a, Vec<&'a str, 4>>, 1>,
    }

    let error = from_str::<OnePeer<'_>>(SAMPLE).unwrap_err();
    assert_eq!(error.kind(), microtun_ini::ErrorKind::Serde);
}
