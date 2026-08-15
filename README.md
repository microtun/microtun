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
| `microtun-device-config` | Portable device configuration: provisioning INI schema/validation, versioned 4 KiB record encode/decode, CRC32, and CIDR parsing. | `no_std`, no alloc |
| `microtun-provision` | Host CLI that validates device configuration, builds provisioning records, and flashes/verifies ESP32 or STM32 targets. | host binary |
| `microtun-linux` | Linux daemon (`microtun`). TUN setup, the same device configuration INI schema from `microtun-device-config`, logging. | host binary |
| `microtun-apiserver` | The Peers API server. Reads a device-config-compatible INI extended with peer sections, using its own config types. | host binary |

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
there is no separate trie-node capacity to tune.

**A session slot is not one per peer.** A peer can hold four at once —
`current`, `previous`, `next` and `handshake` — and holding two of them is
ordinary steady state rather than a transient: a rotation parks the outgoing
session in `previous` until it reaches `Reject-After-Time`, which against the
whitepaper's 120-second rekey and 180-second lifetime is a third of every
cycle. Size `S` at `4 × P`, or `2 × P` as a workable minimum. Sizing `S == P`
has two failure modes, and the second is the expensive one:

* the slot allocator falls through to evicting the least-recently-active
  *established* session, so a live peer has to handshake again — which needs a
  slot, which evicts another peer;
* `Under-Load-Free-Slots` is an absolute count of free slots, so a pool with
  no headroom never has that many free and the engine is permanently "under
  load", answering every initiation with a cookie challenge forever.

One replay word tracks 64 counters and one word is reserved for recycling, so
`REPLAY_WORDS = 128` gives the reference-compatible 8,128-counter trailing
window at roughly 1.2 KiB per session slot. That window exists for multi-core
senders that genuinely reorder that far; a constrained device on a single link
does not, and `REPLAY_WORDS = 32` still accepts packets 1,984 counters behind
the high-water mark at roughly 0.4 KiB per slot. **If the memory for a larger
pool is not there, take it from `REPLAY_WORDS` rather than from `S`.** The
shipped ESP32-C3 and Nucleo profile is `P = 8, S = 32, REPLAY_WORDS = 32,
RT = 8` — four times the session capacity of an eight-slot, 128-word pool for
about 2 KiB more RAM.

Runtime policy is separate from these capacities and lives in `CoreConfig`,
and it is the embedding's to choose rather than the core's. `microtun-core` is
sans-IO: it does not know whether it is driving a microcontroller or a hub,
and it cannot know, because the peer-table capacity that most policy should
scale against is a const generic chosen by the shell. So the core publishes
storage ceilings (`MAX_CORE_*`) and a `CoreConfig::validate_against_limits()`
check, and each shell injects its own profile:

* `microtun-embassy` — `runner::embedded_core_config()`
* `microtun-std` — `runner::host_core_config()`

Both are applied automatically unless you supply a `CoreConfig` of your own,
in which case yours is kept untouched. Start from one and adjust rather than
restating it. `CoreConfig::default()` is deliberately conservative and varies
only in *storage* sizing between the `alloc` and allocation-free backends; a
firmware that forwards `microtun-core/alloc` purely to move tables off its
task stacks does not thereby acquire host-scale policy.

With the `alloc` feature the same limits still apply, but storage moves to the
heap and a `Core` value becomes pointer-sized. Hosts use this by default.
Heap-capable firmware can opt into it as well when task-stack pressure matters;
allocator-free firmware keeps the inline backend.

## Tunnel MTU

`MAX_UDP_SIZE` and `MAX_INNER_SIZE` are buffer and accept bounds — they do not
subtract the outer IP and UDP headers, so an inner packet at `MAX_INNER_SIZE`
becomes a 1,516-byte IPv4 datagram and fragments on an ordinary path. Validate
a configured MTU against `RECOMMENDED_MAX_MTU` (1,408), or against
`RECOMMENDED_MAX_RELAYED_MTU` (1,328) anywhere a peer might be reached through
a relay: a relayed packet pays the transport overhead twice plus the envelope
header, and exceeding that budget is not a fragmentation problem but a silent
drop with no ICMP notification generated. Both shells default to 1,280, the
IPv6 minimum link MTU, which is inside every one of these.

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
NUCLEO-H753ZI onboard wired Ethernet, optional boot-time STM32 RTC synchronization
via SNTP when `[NTP]` is provisioned, microtun/WireGuard, Peers API resolver, and an
interactive shell on TCP/23 over the tunnel. It is deliberately excluded from the
Cargo workspace; build it from that directory.

Device-specific configuration is provisioned separately from the firmware. The
last 128 KiB internal-flash erase sector is reserved for provisioning, with the
portable 4 KiB MTUN record stored at `0x081e0000`. `provision.x` asserts at link
time that the firmware image does not grow into the reserved sector.

Provision the board from the repository root with:

```bash
cargo run -p microtun-provision -- path/to/device.conf \
  --target stm32 --chip STM32H753ZITx --address 0x081e0000 --probe 0483:374e
```

### ESP32-C3 Embassy/Wi-Fi example

`examples/esp32-c3` is the RISC-V ESP32-C3 equivalent of the STM32 demo. It uses
the current Espressif `esp-radio` + `esp-rtos` Embassy integration, Wi-Fi station
mode with DHCP/DNS, optional boot-time SNTP when `[NTP]` is provisioned, the same
pinned Peers API configuration, and the same TCP/23 shell reachable only through the
inner microtun stack. The example is intentionally pinned to
`riscv32imc-unknown-none-elf`; it does not carry Xtensa or other ESP chip feature sets.

ESP Wi-Fi itself requires an allocator, so this firmware installs the heaps required
by `esp-radio`. The example also enables `microtun-embassy/alloc`, reusing that
allocator to move microtun's large bounded core state off the async task stack while
retaining Embassy's smaller active-table limits. Device-specific settings are stored
in one dedicated 4 KiB `microtun` flash partition at `0x003f0000`. The partition
contains the same versioned header + INI provisioning record consumed by the STM32
example.

The `microtun-device-config` crate is the reusable `no_std` layer that owns the
schema, INI decoding, record header, CRC validation, and CIDR validation. Embedded
examples and `microtun-linux` depend on it directly. The separate
`microtun-provision` crate is a host-only CLI that validates and builds those records,
then programs and verifies either target through `espflash` or `probe-rs`. See
`microtun-provision/README.md` for target-specific configuration, chip, address, and
flash instructions.

## Running

Start the server. It terminates the tunnel itself and serves the Peers API on
port 80 *inside* it, so no off-tunnel caller can reach it. Peer records reload
from the file while it runs.

```bash
microtun-apiserver /etc/microtun/apiserver.conf
```

See `microtun-apiserver/apiserver.example.conf`. Its base `[Microtun]`, `[Tunnel]`,
`[ApiServer]`, optional `[WiFi]`, and optional `[NTP]` sections keep the same shape
as device configs, but the API server owns and validates its config
types itself. The server-specific extension is repeated `[Peer]` sections. Every
configured peer can resolve every other configured peer by key or tunnel address.

Then start a client. It needs `CAP_NET_ADMIN` for the TUN device and
`CAP_NET_RAW` to pin lookups to the tunnel interface. The Linux TUN device name
is a CLI option rather than part of the configuration file; when omitted it
defaults to `microtun0`.

```bash
microtun /etc/microtun/microtun.conf
# Override the default interface name when needed:
microtun --interface mtun7 /etc/microtun/microtun.conf
# Equivalent short form:
microtun -i mtun7 /etc/microtun/microtun.conf
```

See `microtun-linux/config.example.conf`. The Linux daemon accepts the same `[Microtun]`, `[Tunnel]`, `[ApiServer]`, optional `[WiFi]`, and optional `[NTP]` schema validated by `microtun-device-config`; Linux ignores the Wi-Fi and NTP sections.

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

