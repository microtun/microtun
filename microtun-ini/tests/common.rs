#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Interface<'a> {
    #[serde(rename = "PrivateKey")]
    pub private_key: &'a str,
    #[serde(rename = "Address")]
    pub address: &'a str,
    #[serde(rename = "ListenPort")]
    pub listen_port: u16,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Peer<'a, T> {
    #[serde(rename = "PublicKey")]
    pub public_key: &'a str,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: T,
    #[serde(rename = "PersistentKeepalive")]
    pub persistent_keepalive: Option<u16>,
}

pub const SAMPLE: &str = r#"
# generated configuration
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.14.0.2/32
ListenPort: 51820
Enabled = yes

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
PersistentKeepalive = 25

[Peer]
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
AllowedIPs = 0.0.0.0/0
"#;

pub const MIXED_CASE_SAMPLE: &str = r#"
[interface]
privatekey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ADDRESS = 10.14.0.2/32
listenPORT: 51820
eNaBlEd = yes

[PEER]
publickey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
allowedips = 10.0.0.0/8, 192.168.0.0/16
persistentKEEPALIVE = 25

[peer]
PUBLICKEY = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
AllowedIPs = 0.0.0.0/0
"#;
