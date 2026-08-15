#![cfg(feature = "alloc")]

mod common;

use std::vec::Vec;

use common::{Interface, MIXED_CASE_SAMPLE, Peer, SAMPLE};
use microtun_ini::{ErrorKind, from_str};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Config<'a> {
    #[serde(rename = "Interface", borrow)]
    interface: Interface<'a>,
    #[serde(rename = "Peer", borrow)]
    peers: Vec<Peer<'a, Vec<&'a str>>>,
}

#[test]
fn parses_wireguard_shape_without_copying_strings() {
    let config: Config<'_> = from_str(SAMPLE).unwrap();
    assert_eq!(config.interface.listen_port, 51820);
    assert!(config.interface.enabled);
    assert_eq!(config.peers.len(), 2);
    assert_eq!(
        config.peers[0].allowed_ips,
        ["10.0.0.0/8", "192.168.0.0/16"]
    );
    assert_eq!(config.peers[1].persistent_keepalive, None);

    let source_start = SAMPLE.as_ptr() as usize;
    let source_end = source_start + SAMPLE.len();
    let borrowed = config.peers[0].public_key.as_ptr() as usize;
    assert!((source_start..source_end).contains(&borrowed));
}

#[test]
fn section_and_property_names_are_ascii_case_insensitive() {
    let config: Config<'_> = from_str(MIXED_CASE_SAMPLE).unwrap();
    assert_eq!(config.interface.address, "10.14.0.2/32");
    assert_eq!(config.interface.listen_port, 51820);
    assert!(config.interface.enabled);
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].persistent_keepalive, Some(25));
    assert_eq!(config.peers[1].allowed_ips, ["0.0.0.0/0"]);
}

#[test]
fn reserved_root_section_is_case_insensitive() {
    let error = from_str::<Config<'_>>("[$ROOT]\nvalue = nope\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ReservedSectionName);
    assert_eq!(error.line(), Some(1));
}

#[derive(Debug, Deserialize, PartialEq)]
struct Root<'a> {
    #[serde(rename = "$root", borrow)]
    global: Global<'a>,
    #[serde(rename = "section", borrow)]
    section: Section<'a>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Global<'a> {
    name: &'a str,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Section<'a> {
    value: &'a str,
}

#[test]
fn parses_global_properties_and_crlf() {
    let parsed: Root<'_> = from_str("name = demo\r\n[section]\r\nvalue: ok\r\n").unwrap();
    assert_eq!(parsed.global.name, "demo");
    assert_eq!(parsed.section.value, "ok");
}

#[derive(Debug, Deserialize)]
struct ScalarPeers<'a> {
    #[serde(rename = "Peer", borrow)]
    _peer: Peer<'a, Vec<&'a str>>,
}

#[test]
fn repeated_section_requires_a_sequence() {
    let error = from_str::<ScalarPeers<'_>>(
        "[Peer]\nPublicKey = one\nAllowedIPs = 10.0.0.0/8\n[peer]\nPublicKey = two\nAllowedIPs = 0.0.0.0/0\n",
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DuplicateSection);
    assert_eq!(error.line(), Some(1));
}

#[derive(Debug, Deserialize)]
struct NumberConfig {
    #[serde(rename = "Numbers")]
    _numbers: Numbers,
}

#[derive(Debug, Deserialize)]
struct Numbers {
    #[serde(rename = "value")]
    _value: u16,
}

#[test]
fn conversion_errors_have_a_location() {
    let error = from_str::<NumberConfig>("[Numbers]\nvalue = nope\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidUnsignedInteger);
    assert_eq!(error.line(), Some(2));
    assert_eq!(error.column(), Some(9));
}

#[test]
fn malformed_input_is_rejected_even_if_the_field_is_unknown() {
    let error = from_str::<NumberConfig>("[Ignored]\nthis is not valid\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::MissingDelimiter);
    assert_eq!(error.line(), Some(2));
}

#[derive(Debug, Deserialize, PartialEq)]
struct Routes<'a> {
    #[serde(rename = "Routes", borrow)]
    routes: RouteList<'a>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct RouteList<'a> {
    #[serde(borrow)]
    route: Vec<&'a str>,
}

#[test]
fn repeated_and_comma_separated_properties_form_one_sequence() {
    let parsed: Routes<'_> =
        from_str("[Routes]\nroute = 10.0.0.0/8, 192.168.0.0/16\nROUTE = fd00::/8\n").unwrap();
    assert_eq!(
        parsed.routes.route,
        ["10.0.0.0/8", "192.168.0.0/16", "fd00::/8"]
    );
}

#[derive(Debug, Deserialize)]
struct ScalarRoute<'a> {
    #[serde(rename = "Routes", borrow)]
    _routes: OneRoute<'a>,
}

#[derive(Debug, Deserialize)]
struct OneRoute<'a> {
    #[serde(rename = "route")]
    _route: &'a str,
}

#[test]
fn repeated_property_requires_a_sequence() {
    let error = from_str::<ScalarRoute<'_>>("[Routes]\nroute = one\nROUTE = two\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DuplicateKey);
    assert_eq!(error.line(), Some(2));
    assert_eq!(error.column(), Some(1));
}

#[derive(Debug, Deserialize, PartialEq)]
struct OptionalSectionConfig<'a> {
    #[serde(rename = "Optional", default, borrow)]
    optional: Option<OptionalSection<'a>>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct OptionalSection<'a> {
    value: &'a str,
}

#[test]
fn optional_section_deserializes_when_present_and_defaults_when_absent() {
    let present: OptionalSectionConfig<'_> = from_str("[Optional]\nvalue = yes\n").unwrap();
    assert_eq!(present.optional.unwrap().value, "yes");

    let absent: OptionalSectionConfig<'_> = from_str("").unwrap();
    assert_eq!(absent.optional, None);
}
