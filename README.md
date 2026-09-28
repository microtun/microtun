# microtun

microtun is a VPN for microcontrollers. It implements a secure, Noise_IK-based tunnel protocol in Rust, using Curve25519 and ChaCha20-Poly1305, and runs on no_std targets with no heap allocator requirement. It is wire-compatible with existing, widely deployed [Linux VPN technologies](https://man7.org/linux/man-pages/man8/wg.8.html).

## Host tools

Host-side commands are provided by one `microtun` binary from the `microtun` crate:

```text
microtun tunnel /path/to/device.toml
microtun tracker /path/to/tracker.toml
microtun console device.example.net
microtun console --serial device.example.net
microtun console --serial --baudrate 115200 --data-bits 8 device.example.net
microtun serial device.example.net --name ttyMT0
microtun serial device.example.net --baudrate 115200 --data-bits 8 --name ttyMT0
```

## Contributing

Contributions are welcome. Before a contribution can be merged, the contributor
must complete the applicable Contributor License Agreement (CLA). Contributions
made on behalf of an employer or other organization may also require an entity
CLA or equivalent authorization. See [`CONTRIBUTING.md`](CONTRIBUTING.md), the
[`Individual CLA`](CLA-INDIVIDUAL.md), and the [`Entity CLA`](CLA-ENTITY.md)
for details.

## License

microtun is licensed under the Business Source License 1.1 (`BUSL-1.1`).
There is no Additional Use Grant, so the BUSL-1.1 non-production-use grant
applies until the change. Each version changes to the GNU General Public
License v3.0 or later (`GPL-3.0-or-later`) four years after that version is
published. See [`LICENSE`](LICENSE) for the complete terms.