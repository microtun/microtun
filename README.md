# microtun

microtun is a VPN for microcontrollers. It implements the WireGuard® protocol in
Rust, and runs on `no_std` targets with no heap allocator. The same code also
builds for normal hosts, so a Linux daemon and a small embedded device can join
the same network.

The workspace holds the protocol engine, two runtime integrations (Embassy for
firmware, Tokio for hosts), and two ready-to-run binaries.

## Why peers are loaded on demand

A normal WireGuard device keeps every peer in memory. A microcontroller cannot
do that: each peer costs RAM, and a device with a few kilobytes to spare can
hold maybe eight of them. Sizing the peer table for the whole network is not an
option.

So microtun loads peers only when it needs them. When a packet arrives from an
unknown key, or is sent to an address that is not in the route cache, the engine
asks for that one peer record and caches it. Records that are not used are
dropped again.

This needs a *Peers API server*: one node that knows the whole network and
answers lookups. Clients reach it **through the tunnel**, over a persistent
JSON-RPC 2.0 connection. The only thing a device must be configured with is its
own key and that one server. The server also pushes updates for records a client
still holds, so cached peers do not go stale.

This design is a workaround for the memory limit, not a feature in itself. On a
host you would simply configure all peers.

## Crates

| Crate | What it does | Environment |
| --- | --- | --- |
| `microtun-core` | The protocol engine: handshakes, sessions, routing, replay protection, rate limits, a small stateful firewall, and relay support. Sans-IO — it never touches a socket. | `no_std`, no alloc |
| `microtun-jsonrpc` | Bidirectional JSON-RPC 2.0 over a byte stream. Newline-framed, zero allocation, transport-agnostic. No microtun-specific content. | `no_std`, no alloc |
| `microtun-api` | The Peers API wire format: methods, parameters, and record decoding, plus an optional typed client. | `no_std`, no alloc |
| `microtun-embassy` | Runs the engine on [Embassy](https://embassy.dev). Exposes the tunnel as an `embassy-net` device, so firmware gets normal sockets over the VPN. Optional `alloc` forwards to the core for heap-backed state. | `no_std`, alloc optional |
| `microtun-std` | Runs the engine on Tokio, with a stateful Peers API resolver. Does not create an OS tunnel interface; the application supplies the device. | host |
| `microtun-linux` | Linux daemon (`microtun`). TUN setup, WireGuard-style INI config with `[Interface]` and `[ApiServer]` sections, logging. | host binary |
| `microtun-apiserver` | The Peers API server. Reads a `wg.conf`-style file listing the network's peers. | host binary |

`microtun-core` is deliberately free of I/O. You give it packets, timer ticks
and resolver answers; it writes its output straight into a sink you provide.
There is no output queue and nothing to allocate, so the whole engine can live
in a `static`.

"No alloc" in the table above is a claim about the whole dependency graph, not
just about this crate's own code. A `#![no_std]` dependency that links `alloc`
unconditionally still forces a `#[global_allocator]` into every binary that
uses it, and the failure only appears when someone links firmware for a target
that has no allocator. CIDR prefixes use `cidr`, which fits that constraint.
The bare-metal build in `examples/nucleo-h753zi` is what keeps this property
honest — see
"Testing the no-alloc build" below.

## How a node fits together

```text
    application / OS
           │  plaintext IP packets
           ▼
    ┌─────────────┐   encrypted UDP    ┌──────────────┐
    │ TunnelRunner│◄──────────────────►│ peers, relays│
    │  + Core     │                    └──────────────┘
    └─────┬───────┘
          │ resolver commands / answers (inside the tunnel)
          ▼
    ┌──────────────┐
    │ resolver task│◄──── JSON-RPC ────► Peers API server
    └──────────────┘
```

The runner is one task. It reacts to four things: encrypted datagrams from the
UDP socket, plaintext packets from the tunnel device, resolver answers, and the
engine's next timer deadline. Resolution runs in a second task, because its
replies arrive as ordinary tunnel packets and must not block the packet path.

Peers that cannot be reached directly (NAT, firewall) can be routed through a
single relay. Microtun private message type `0xF0` (240) carries a destination
static key, inner length, and one complete end-to-end WireGuard datagram over
the authenticated session with the relay. The relay can route the packet but
cannot read its tunneled IP plaintext.
The extension is intentionally single-hop and is specified in
`docs/microtun-relay-protocol.md`.

## Sizing

Peer, session, replay-window and route capacities are const generics, fixed at
compile time. The core orders them as `P, S, REPLAY_WORDS, RT`, keeping the
per-session replay storage next to the session capacity. On allocation-free
builds the route trie derives its fixed backing storage directly from `RT`, so
there is no separate trie-node capacity to tune. One replay word tracks 64
counters and one word is reserved for recycling, so `REPLAY_WORDS = 128` gives
the reference-compatible 8,128
counter trailing window. At that setting an established session slot is roughly
1.2 KiB. A reasonable starting point for an ESP32-C3 is
`P = 8, S = 8, REPLAY_WORDS = 128, RT = 16`.

With the `alloc` feature the same limits still apply, but storage moves to the
heap and a `Core` value becomes pointer-sized. Hosts use this by default.
Heap-capable firmware can opt into it as well when task-stack pressure matters;
allocator-free firmware keeps the inline backend.

## Building

Requires Rust 1.85 or newer (edition 2024).

```bash
cargo build --workspace
cargo test  --workspace
```

`microtun-embassy` is `no_std` and needs a cross target, for example:

```bash
cargo build -p microtun-embassy --target thumbv7em-none-eabihf
```

### Testing the no-alloc build

Building a library for a bare-metal target does **not** prove it is
allocator-free: the "no global memory allocator found" check runs when a final
binary is linked, not when a `rlib` is compiled. Only linking an actual
firmware image exercises it:

```bash
cd examples/nucleo-h753zi
cargo build
```

Worth having in CI. Without it, a dependency can quietly acquire an `alloc`
requirement and nothing notices until someone tries to flash a board.


### STM32H753ZI board example

`examples/nucleo-h753zi` is a standalone Embassy firmware example for the
NUCLEO-H753ZI onboard wired Ethernet, boot-time STM32 RTC synchronization via
SNTP, microtun/WireGuard, Peers API resolver, and an interactive shell on
TCP/23 over the tunnel. It is deliberately excluded from the Cargo workspace;
build it from that directory.

Device-specific configuration is provisioned separately from the firmware. The
last 128 KiB internal-flash erase sector is reserved for provisioning, with the
portable 4 KiB MTUN record stored at `0x081e0000`. `provision.x` asserts at link
time that the firmware image does not grow into the reserved sector. The sample
`examples/nucleo-h753zi/provision.example.json` contains the WireGuard key, API
endpoint/key/tunnel address, local tunnel CIDR, and NTP settings.

Provision the board from the repository root with:

```bash
cargo run -p microtun-provision -- flash path/to/device.json \
  --target stm32 --chip STM32H753ZITx --address 0x081e0000 --probe 0483:374e
```

### ESP32-C3 Embassy/Wi-Fi example

`examples/esp32-c3` is the RISC-V ESP32-C3 equivalent of the STM32 demo. It uses
the current Espressif `esp-radio` + `esp-rtos` Embassy integration, Wi-Fi station
mode with DHCP/DNS, boot-time SNTP, the same pinned Peers API configuration, and
the same TCP/23 shell reachable only through the inner microtun stack. The example
is intentionally pinned to `riscv32imc-unknown-none-elf`; it does not carry Xtensa
or other ESP chip feature sets.

ESP Wi-Fi itself requires an allocator, so this firmware installs the heaps required
by `esp-radio`. The example also enables `microtun-embassy/alloc`, reusing that
allocator to move microtun's large bounded core state off the async task stack while
retaining Embassy's smaller active-table limits. Device-specific settings are stored
in one dedicated 4 KiB `microtun` flash partition at `0x003f0000`. The partition
contains the same versioned header + JSON provisioning record consumed by the STM32
example.

The `microtun-provision` package exposes a `no_std` library that owns the schema, JSON
decoding, record header, CRC validation, and CIDR validation, plus a host CLI behind
its default `cli` feature. Embedded examples depend on it with
`default-features = false`; the CLI builds/inspects records and programs either target
through `espflash` or `probe-rs`. See each example README for target-specific flash
instructions.

## Running

Start the server. It terminates the tunnel itself and serves the Peers API on
port 80 *inside* it, so no off-tunnel caller can reach it. Peer records reload
from the file while it runs.

```bash
microtun-apiserver /etc/microtun/apiserver.conf
```

See `microtun-apiserver/apiserver.example.conf`. Optional `[Group.name]` and
`[Link.name]` sections can restrict peer discovery: groups define membership,
while a link names one group for an internal mesh or two groups for mutual
cross-group visibility.

Then start a client. It needs `CAP_NET_ADMIN` for the TUN device and
`CAP_NET_RAW` to pin lookups to the tunnel interface.

```bash
microtun /etc/microtun/microtun.conf
```

See `microtun-linux/config.example.conf`.

## Feature flags

The important ones:

* `alloc` (core, api, jsonrpc; forwarded by embassy) — use heap-backed storage.
  `microtun-embassy/alloc` specifically forwards to `microtun-core/alloc`; it is off
  by default so allocator-free Embassy firmware keeps working.
* `async` (core) — turns the engine's methods into async ones in place. It is
  not a second API. Both runtime crates enable it.
* `defmt` / `log` (core, embassy) — pick a logging backend.
* `sync` vs `async` (jsonrpc) — blocking or async I/O. They are mutually
  exclusive; `tokio` layers Tokio transports on top of `async`.

## Documentation

* `docs/microtun-peers-api.md` — the Peers API protocol.
* `docs/microtun-relay-protocol.md` — the relay extension.

Crate-level docs are the reference for everything else: `cargo doc --open`.

---

WireGuard is a registered trademark of Jason A. Donenfeld. This project is not
sponsored or endorsed by him.

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

