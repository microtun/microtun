# microtun-provisioning

`microtun-provisioning` contains the portable device-side provisioning support shared
by the microtun embedded targets. It owns the persistent provisioning record format,
stable device identity helpers, fallback-link addressing, DHCP support, and the wire
constants used when the normal Telnet shell hands a connection to YMODEM. Shared mDNS
networking lives in `microtun-net-util`.

The host provisioning workflow CLI has been removed. Host interaction now lives in the
`microtun-telnet` crate, which is a normal interactive Telnet client with built-in
YMODEM uploads and an mDNS `discover` subcommand.

## Features

`std` remains enabled by default for compatibility but does not add networking dependencies.
Embedded users that need the provisioning DHCP server should disable default features and
enable `embassy-net` explicitly:

```toml
microtun-provisioning = { path = "../../microtun-provisioning", default-features = false, features = ["embassy-net"] }
```

Available features are:

- `std`: compatibility feature for host users; no extra dependencies.
- `embassy-net`: async Embassy-net DHCP support.
- `defmt`: `defmt::Format` support for embedded diagnostics.

There is no `cli` feature or binary target in this crate anymore.

## Provisioning shell protocol

Provisioning mode uses the same main `microtun> ` Telnet shell as an operational
device. The outer listener is present only while the board is unprovisioned; after
provisioning the shell is normally reachable on the inner microtun interface.

Bare `provision` prints:

```text
MICROTUN-PROVISION-YMODEM-1K READY
```

and hands the same Telnet connection to a YMODEM-1K/CRC receiver. Standard YMODEM block
0 carries the filename and exact decimal file size. The receiver checks the declared
size against `MAX_INI_LEN`, strips final-block padding, and hands exactly that many bytes
to the board's configuration store. A successful write is verified before the device
prints `configuration stored; rebooting` and resets.

The `fw update` shell command uses the same transport pattern for signed MCUboot images,
with the generic marker `MICROTUN-YMODEM-1K READY`. Firmware validation and slot
activation are implemented by each board target rather than this provisioning crate.

## Automatic provisioning network

An unprovisioned wireless device exposes a per-device `microtun-<device_id>` access
point at `192.168.7.1/24`; its DHCP server configures the host automatically. The wired
Nucleo first probes for an existing DHCP server and otherwise falls back to the same
`192.168.7.1/24` provisioning subnet.

Provisioning-mode devices advertise `_microtun._tcp.local` through mDNS/DNS-SD.
The response includes an SRV record for the Telnet port, an A record for the current
IPv4 address, and TXT keys containing `device_id` and `model`.

The `std` discovery API is provided by `microtun-net-util`:

```rust
let devices = microtun_net_util::mdns::discover(
    std::time::Duration::from_secs(2),
)?;
```

For the host client, discover the advertised address and then connect explicitly by IP:

```bash
cargo run -p microtun-telnet -- discover
cargo run -p microtun-telnet -- 192.168.7.1
```

## Configuration format

The provisioned payload is the same device INI schema owned by
`microtun-core::device_config`. A starting point is available at
`microtun-core/device.example.conf`.

## Security model

Provisioning mode is intentionally unauthenticated and should be exposed only on a
controlled provisioning link. Telnet and YMODEM provide no confidentiality on that
outer link: the INI is sent in plaintext and can contain private keys and Wi-Fi
credentials. Do not expose the provisioning-mode Telnet service to an untrusted or
routed network.
