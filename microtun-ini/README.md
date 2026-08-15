# microtun-ini

`microtun-ini` is a small, borrowing Serde deserializer for WireGuard-style INI files. The parser is always `#![no_std]` and performs no heap allocation. You choose whether the destination uses `alloc` collections or fixed-capacity [`heapless`](https://docs.rs/heapless) collections.

## Data model

- The document is a map whose keys are section names.
- Each section is a map of properties.
- Section and property names are grouped ASCII case-insensitively; struct fields are matched the same way.
- Repeated sections deserialize into a sequence. This maps naturally to repeated `[Peer]` blocks.
- A sequence-valued property flattens repeated keys and comma-separated values.
- Properties before the first section live under the reserved `$root` section.
- Values are left untouched. Surrounding Unicode whitespace is trimmed.
- `#` and `;` start comments only when they are the first non-whitespace character on a line.
- Both `key = value` and `key: value` are accepted. Values remain borrowed slices of the input.

This deliberately avoids interpolation, escape processing, inline comments, and implicit lowercasing. Those features either require allocation or make networking values ambiguous.

## Default `alloc` use

```toml
[dependencies]
microtun-ini = "0.1"
serde = { version = "1", features = ["derive"] }
```

```rust
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WireGuard<'a> {
    #[serde(rename = "Interface", borrow)]
    interface: Interface<'a>,
    #[serde(rename = "Peer", borrow)]
    peers: Vec<Peer<'a>>,
}

#[derive(Debug, Deserialize)]
struct Interface<'a> {
    #[serde(rename = "PrivateKey")]
    private_key: &'a str,
    #[serde(rename = "Address")]
    address: &'a str,
    #[serde(rename = "ListenPort")]
    listen_port: u16,
}

#[derive(Debug, Deserialize)]
struct Peer<'a> {
    #[serde(rename = "PublicKey")]
    public_key: &'a str,
    #[serde(rename = "AllowedIPs", borrow)]
    allowed_ips: Vec<&'a str>,
    #[serde(rename = "PersistentKeepalive")]
    persistent_keepalive: Option<u16>,
}

let input = r#"
[Interface]
PrivateKey = secret=
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = peer-one=
AllowedIPs = 10.0.0.2/32, fd00::2/128

[Peer]
PublicKey = peer-two=
AllowedIPs = 10.0.0.3/32
PersistentKeepalive = 25
"#;

let config: WireGuard<'_> = microtun_ini::from_str(input)?;
# Ok::<(), microtun_ini::Error>(())
```

## Fully `no_alloc` with `heapless`

```toml
[dependencies]
microtun-ini = { version = "0.1", default-features = false, features = ["heapless"] }
serde = { version = "1", default-features = false, features = ["derive"] }
```

Only the destination capacities change:

```rust
use microtun_ini::heapless::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config<'a> {
    #[serde(rename = "Peer", borrow)]
    peers: Vec<Peer<'a>, 8>,
}

#[derive(Deserialize)]
struct Peer<'a> {
    #[serde(rename = "PublicKey")]
    public_key: &'a str,
    #[serde(rename = "AllowedIPs", borrow)]
    allowed_ips: Vec<&'a str, 16>,
}
# let _: Option<Config<'_>> = None;
```

Capacity overflow is reported as `ErrorKind::Serde`. Syntax and scalar conversion errors retain one-based line and column information.

## Duplicate rules

A repeated section must target a sequence. A repeated property must also target a sequence. A scalar destination returns `DuplicateSection` or `DuplicateKey` instead of silently discarding data.

The parser validates the whole document before deserializing, including unknown sections and properties. Its allocation-free grouping uses rescans, so worst-case parsing is quadratic in the number of distinct sections or keys. That is a deliberate size/memory tradeoff for small embedded configuration files.

## Feature flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | yes | Enables Serde implementations for `String`, `Vec`, and other allocation-backed targets. The parser still does not allocate. |
| `std` | no | Enables Serde's standard-library support and implies `alloc`. |
| `heapless` | no | Re-exports `heapless` with Serde support for a fully fixed-capacity destination. |
