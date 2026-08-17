# Nucleo H753ZI example

## NUCLEO-H753ZI hardware used by this example

The target is ST's **NUCLEO-H753ZI / MB1364** board with an
`STM32H753ZIT6`. The firmware runs the Cortex-M7 at 400 MHz (the MCU is rated
for up to 480 MHz), uses the onboard 10/100 Ethernet PHY/RJ45 in RMII mode,
and uses the board RTC for wall-clock time.

| Board function | MCU pin | Firmware behavior |
| --- | --- | --- |
| LD1 green user LED | PB0 | Active-high; provisioning identify LED and operational shell LED 1 |
| LD2 yellow user LED | PE1 | Active-high; operational shell LED 2 |
| LD3 red user LED | PB14 | Active-high; operational shell LED 3 |
| B1 USER button | PC13 | Active-high; shell status input only |
| Ethernet RMII REF_CLK | PA1 | 50 MHz reference clock from onboard PHY |
| Ethernet RMII CRS_DV | PA7 | Onboard Ethernet |
| Ethernet RMII RXD0/RXD1 | PC4 / PC5 | Onboard Ethernet |
| Ethernet RMII TXD0/TXD1 | PG13 / PB13 | Onboard Ethernet |
| Ethernet RMII TX_EN | PG11 | Onboard Ethernet |
| Ethernet MDIO / MDC | PA2 / PC1 | PHY management |

The LED mappings above follow the board's default solder-bridge configuration.
LD1 can be rerouted to PA5 by changing the board solder bridges, in which case
this example's PB0 mapping must be adjusted as well.

## Tunnel management shell

On a normal provisioned boot, TCP/23 exists **only on the inner microtun
interface**. The outer wired-Ethernet interface does not expose Telnet. The
plaintext management protocol therefore remains inside the authenticated,
encrypted tunnel.

The Nucleo and ESP32 PLC examples use [`microtun-telnet-cli`](https://github.com/microtun/microtun-telnet-cli) for the allocation-free line editor, history, tokenization, typed argument validation, generated help/completion, command dispatch, and TELNET framing/negotiation. Each firmware passes its accepted Embassy `TcpSocket` directly to a `Session` and keeps only board-specific status formatting and command handlers locally. They keep the same noun-first command shape. Bare paths inspect state and deeper paths select a property or action:

```text
help
help io
sys
sys version
sys id
sys reset-reason
sys temp
sys uptime
sys time
sys memory
net
net link
net ip
net mac
net phy
ping net 8.8.8.8
ping tunnel 10.0.0.1 3
tunnel
tunnel show
tunnel key
provision
provision clear
io
io led
io led 1
io led 1 on
io led all toggle
io button
fw
fw show
fw update
identify
reboot
exit
```

`sys version` reports the app package version from `app/Cargo.toml`. That `x.y.z` release SemVer is the canonical firmware version and the anti-rollback floor. Bump it for every release and sign the MCUboot envelope with the same value via `imgtool sign -v x.y.z`.

`fw` / `fw show` reports the running version together with the Embassy Boot trial state. `fw update` uses the same transport and authentication mechanism as the ESP32 example: it hands the TELNET socket to YMODEM-1K/CRC, streams a signed MCUboot envelope through `microtun-mcuboot`, verifies the configured Ed25519 public key and microtun firmware component ID, and writes only the authenticated native STM32 payload to the DFU partition. The first vector-table entries are also checked for a valid STM32H753 stack pointer and a reset vector inside the linked ACTIVE application range.

The update identity uses the same human-readable names as MCUboot `imgtool`: `--vid firmware.microtun.dev --cid nucleo-h753zi`. The firmware derives the UUIDv5 VID/CID pair internally and requires both protected TLVs to match, so no raw UUID byte array needs to be copied into the application.

The H753 OTA path now uses a small first-stage `embassy-boot-stm32` loader in `bootloader/`; it no longer relies on application-controlled `SWAP_BANK`. The 2 MiB internal flash is split into a 128 KiB first stage, a 768 KiB ACTIVE application, a 128 KiB boot-state sector, an 896 KiB DFU partition, and the existing 128 KiB provisioning sector. Embassy Boot requires DFU to be at least one erase sector larger than ACTIVE so it can swap power-fail-safely, which makes the maximum native application payload **768 KiB** on the H753.

After a complete signed image verifies, the updater marks Embassy Boot state `Swap` and resets. The first stage swaps the candidate into ACTIVE and boots it as a trial. The candidate remains unconfirmed while Ethernet, DHCP, the tunnel, and the long-running tunnel task start; after the virtual tunnel link is up and the service survives a 30-second health window, the app calls `mark_booted()`. A panic/HardFault/reset before that call returns control to the first stage, which restores the previously confirmed firmware automatically. Provisioning remains isolated in physical bank 2 sector 7 and is outside every swap partition.

The native payload inside the MCUboot envelope must be the Nucleo application binary linked for `0x0802_0000`; `memory.x` and `app/microtun.x` enforce the ACTIVE address and 768 KiB limit. Existing boards using the old SWAP_BANK-only layout need a one-time trusted SWD/service reflash to install the first-stage bootloader before they can use automatic rollback. As part of that migration, restore the STM32 `SWAP_BANK` option bit to its normal **disabled** state; the new layout uses fixed physical banks and never toggles that option bit.

The build embeds the Ed25519 verification key from `MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH`, exactly like the ESP32 example. Set that environment variable to the public key corresponding to the private key used to sign MCUboot update envelopes before building the Nucleo firmware. The native payload inside the envelope must be the Nucleo binary linked for `0x0802_0000`; the linker scripts reject images that would overlap the 768 KiB ACTIVE boundary.

The STM32-specific DFU sink and Embassy Boot state handling live in `app/src/firmware.rs`; the immutable swap/revert engine lives in `bootloader/`, while `app/src/main.rs` controls the delayed health confirmation.


`io led` reports the three active-high user LEDs in numeric order. `io led N`
reads one LED, while `on`, `off`, and `toggle` modify it; `all` applies the same
action to all three. `identify` blinks all three LEDs and restores their previous states. `io button`
reports the current B1 USER state as `pressed` or `released`. The USER button does not
erase or otherwise modify provisioning state.

`sys time` uses the shared `unix=<seconds>.<nanoseconds>` representation on both embedded targets.

The top-level `net` output includes a concise PHY summary with negotiated speed,
duplex, and auto-negotiation state. `net phy` reports the same LAN8742 link-mode
diagnostics as individual fields. Speed and duplex are reported as `n/a` while the
link is down or negotiation is incomplete.

`ping <net|tunnel> <addr> [count]` sends ICMP echo requests through an explicit
interface. `net` selects the physical/uplink interface and `tunnel` selects the
inner tunnel interface, so comparing the two quickly separates uplink failures
from tunnel or peer reachability problems. The default count is 4; counts from 1
through 16 are accepted. Both IPv4 and IPv6 literals are supported when the
selected interface has an address of that family.

`tunnel` and `tunnel show` are equivalent and print an operational
view; `tunnel key` prints only the local tunnel public key. The interface section includes the local tunnel address, public key, and
listening port; each installed peer includes its pinned versus dynamically
resolved origin, session state, endpoint/relay, allowed tunnel address, latest
successful handshake, authenticated transport byte counters, and persistent
keepalive. The snapshot is published by the tunnel runner from `microtun-core`
state, so the shell does not reach into the live crypto engine.

`reboot` is a direct action and does not use the old confirmation syntax.

## Provisioning mode

The board-independent provisioning-mode protocol lives in the workspace
`microtun-provisioning` crate, while shared mDNS networking lives in
`microtun-net-util`. This example only supplies STM32-specific identity,
flash storage, Embassy socket ownership, LD1 identify behavior, and reset.

The firmware normally loads the single 4 KiB provisioning record from physical flash
bank 2, sector 7 (`0x081e_0000`). The new Embassy Boot layout never remaps the banks, so
this sector has one fixed CPU address and lies outside BOOTLOADER, ACTIVE, STATE, and DFU.
If that record is absent, corrupt, or contains an invalid configuration, the board
does not panic. It brings up wired Ethernet and enters
provisioning mode instead, using an existing DHCP service when present or an isolated
fallback subnet when it is not.

### Reprovisioning an operational device

A provisioned board does not need to erase its provisioning sector or return to the
outer provisioning interface. Connect to the normal `microtun> ` shell through the
tunnel and run the same `provision` command. The firmware receives
and validates the replacement INI, rewrites the provisioning record, verifies it, and
reboots directly into the new configuration.

To discard the installed configuration instead, run `provision clear`. The firmware
erases the provisioning sector and reboots, so the next boot enters provisioning mode.
B1 remains a read-only shell input via `io button`; it is not a provisioning-reset
control. The black RESET button (B2) is unchanged.

### Automatic provisioning address

An unprovisioned board starts Ethernet as a DHCP client first. This lets it avoid
starting a second DHCP server if the cable is already connected to a managed LAN.
Whenever the board is a DHCP client, it sends `microtun-<device_id>` as DHCP Option 12,
matching the bare label used by its `microtun-<device_id>.local` mDNS hostname.
After link-up it waits up to 30 seconds for a lease:

- If an existing DHCP server answers, the board stays on that lease and enters
  provisioning mode there. It advertises `_microtun._tcp.local` over
  mDNS/DNS-SD, so `microtun-telnet discover` can find the leased address automatically.
- If no lease arrives, the board switches to the isolated fallback address
  `192.168.7.1/24` and starts a small DHCP server. A directly connected laptop left
  in its normal automatic/DHCP mode is assigned an address from
  `192.168.7.2` through `192.168.7.20`, so no manual interface configuration is
  needed. No default gateway or DNS server is advertised.

In either case the board advertises the provisioning service as
`microtun-<device_id>._microtun._tcp.local`, with
`microtun-<device_id>.local` pointing at its current IPv4 address. If several boards
are on the same managed provisioning LAN, use `microtun-telnet discover` to list their
addresses, then connect to the intended board by IP address.

The 30-second probe is deliberately a heuristic rather than proof that no DHCP
server exists. The intended fallback setup remains a direct cable between laptop and
board, or an isolated switch used with one board powered at a time. Do not rely on the
fallback logic as protection against accidentally introducing a DHCP server onto an
untrusted or unusually slow shared LAN. Because provisioning mode is unauthenticated,
only use the existing-DHCP path on a trusted provisioning LAN.

On the isolated fallback subnet the address is fixed rather than derived per device,
so **only one unprovisioned board may be attached to that provisioning link at a
time**.

Confirm the direct-link fallback path with:

```bash
ping 192.168.7.1
```

### Stable identity

Every STM32H753 has a 96-bit factory unique-device ID. Because the MCU does not
provide a factory Ethernet MAC, the firmware deterministically derives a stable locally
administered 48-bit MAC from those immutable UID bytes. The `device_id` is then simply
that MAC encoded as the same fixed-width 10-character lower-case base36 value used on
every platform. The mapping from MAC to device ID is reversible and remains stable
across resets.

The device ID is reported by `sys id`, and `identify` blinks the user LEDs so an
operator can confirm the physical board before writing to it. Use discovery to find the
board's IP address and `sys id`/`identify` after connecting to confirm the target. These
checks guard against operator mistakes but are **not authentication**; the provisioning
shell itself is unauthenticated and should only be exposed on the controlled
provisioning link described above.

### Provisioning Telnet CLI

Provisioning mode serves the same main `microtun> ` Telnet shell used after
provisioning, on the outer interface at standard TCP port `23`. On the isolated fallback
link the endpoint is `192.168.7.1:23`; when an existing DHCP server is used,
mDNS/DNS-SD advertises the leased address and the same port. There is no separate
WebSocket provisioning endpoint or provisioning-only shell.

The prompt remains `microtun> `. `sys`, `net`, `ping net`, `io`, `fw`, `identify`,
`reboot`, and `quit` remain usable before a tunnel configuration exists. `sys` reports
`mode` as `provisioning` and `provisioned` as `false`. Tunnel-dependent operations fail
cleanly:

```text
microtun> tunnel show
unavailable: tunnel is not configured in provisioning mode

microtun> ping tunnel 100.64.0.1
unavailable: tunnel is not configured in provisioning mode
```

Bare `provision` starts the receive flow in this same shell. The firmware prints
`MICROTUN-PROVISION-YMODEM-1K READY` and hands the same Telnet socket to YMODEM-1K/CRC.
The standard YMODEM block 0 supplies the filename and exact decimal file size. The
receiver rejects a declared size above `MAX_INI_LEN` before accepting payload bytes and
discards transfer padding beyond the advertised length.

After the transfer, the firmware validates the INI, erases the single global
provisioning sector, writes the new record, reads it back, and validates the stored
record again. On success it prints `configuration stored; rebooting`, flushes the
Telnet connection, and resets through the normal boot path. A transfer error, invalid
config, storage failure, or verification failure leaves the device in provisioning
mode.

Provisioning mode is served only when the normal provisioning record cannot be loaded.
A configured device normally stays operational while being reprovisioned: run
`provision` through its tunnel shell, transfer the replacement INI, and let the
successful write reboot the board into the new configuration. Run `provision clear` to
erase the current provisioning sector and reboot into provisioning mode; there is no
button-driven clear path.


## Bootloader and application build

The board directory contains two independent Cargo projects, `app/` and `bootloader/`. Each has its own `.cargo/config.toml`; neither project inherits Cargo configuration from the other. The shared `memory.x` stays one level above them so both builds consume the same physical flash map.

`fw update` enforces the same guarantees as the ESP32 example:

* **Anti-rollback.** The updater compares the signed MCUboot header version against the running firmware's package SemVer. An update older than the running `x.y.z` is rejected. Release envelopes must be signed with the same version as `app/Cargo.toml`, for example `imgtool sign -v 0.4.0 ...`.
* **Read-back verification.** After the transfer completes and the trailing partial write word is flushed, the DFU slot is read back and the canonical MCUboot digest — `header || payload-from-flash || protected TLVs` — is recomputed and compared against the digest the signature already covered, as `bootutil_img_validate` does upstream. The header and protected TLVs are retained from the transfer since they are the only parts of the container not written to the slot; the image format is unchanged.
* **No erase before it is safe.** The DFU partition holds the image Embassy Boot reverts to, so it is no longer erased up front. Sectors are erased lazily as the stream reaches them, and `fw update` refuses outright unless the boot state is `Boot` — a trial image still pending verification would otherwise have its rollback copy destroyed. The old behaviour also stalled the executor for seconds erasing all 896 KiB, long enough for the tunnel carrying the update to time out.
* **Watchdog.** IWDG1 is armed at 20 s with a petting task, and the trial wait for the inner tunnel link is bounded (120 s), so a trial image that boots but never reaches the tunnel resets into rollback instead of running unconfirmed forever. A 128 KiB H7 sector erase blocks the executor for on the order of a second and cannot yield, so the flash paths pet directly.
* **TELNET binary mode is confirmed, not assumed.** The updater waits for the peer's `WILL`/`DO BINARY` before starting YMODEM.

Note that the IWDG keeps counting while the core is halted, so a board stopped at a breakpoint will reset after ~20 s. Freeze it through `DBGMCU` (or comment out `start_watchdog`) for interactive debugging sessions.

Automatic rollback requires the first-stage loader in `bootloader/`. Install it once through SWD, then flash/build the application separately. Both builds use the same top-level `memory.x`; it defines the complete flash layout once, and the bootloader selects its own link region with `__microtun_link_bootloader`.

```sh
# First-stage recovery loader (one-time / manufacturing-service update)
cd bootloader
cargo build --release
cargo run --release
cd ..

# Application (requires your normal firmware verification key)
cd app
export MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH=/path/to/firmware-public.pem
cargo build --release --locked
cargo run --release --locked
```

The application vector table is at `0x0802_0000`. Normal OTA never erases the bootloader sector or provisioning sector. When migrating a device from the former SWAP_BANK implementation, also clear/disable the STM32 `SWAP_BANK` option bit before first boot with this layout.
