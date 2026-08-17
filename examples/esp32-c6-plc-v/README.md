# ESP32-C6 example (ICBBUY ESP32-C6-PLC-V)

This example is the ESP32-C6/RISC-V counterpart of `examples/esp32-c3`, with
board support aimed at the ICBBUY **ESP32-C6-PLC-V V1.6** evaluation/PLC board.
The attached board schematic uses an `ESP32-C6-WROOM-1U-N4`, so this example
uses the app-local 4 MiB flash layout in `app/partitions.csv`; the Rust
application lives in `app/` and targets `riscv32imac-unknown-none-elf`.

It runs microtun over Wi-Fi using Embassy, `esp-radio`, and `esp-rtos`. A
provisioned device joins the configured Wi-Fi network as a station and sends
`microtun-<device_id>` as DHCP Option 12; an unprovisioned device starts the same
recovery/provisioning access point used by the ESP32-C3 example. The DHCP hostname
matches the bare label of the device's `microtun-<device_id>.local` mDNS hostname.

## ICBBUY ESP32-C6-PLC-V board mapping

The example uses the evaluation board's GPIO mapping directly:

| Board function | ESP32-C6 GPIO | Firmware behavior |
| --- | ---: | --- |
| RUN user LED | GPIO8 | Active-low; provisioning identify LED and operational shell LED 1 |
| BOOT user button | GPIO9 | Active-low; shell status input only |
| Relay 1 | GPIO22 | Active-high; starts off |
| Relay 2 | GPIO11 | Active-high; starts off |
| Relay 3 | GPIO10 | Active-high; starts off |
| Relay 4 | GPIO23 | Active-high; starts off |
| IN1 | GPIO1 | Opto-isolated; asserted field input reads low |
| IN2 | GPIO2 | Opto-isolated; asserted field input reads low |
| IN3 | GPIO3 | Opto-isolated; asserted field input reads low |
| IN4 | GPIO15 | Opto-isolated; asserted field input reads low |

The schematic rates the opto-isolated field inputs for up to 30 VDC. The relay
GPIOs only drive the onboard transistor stages; do not connect field voltages
directly to ESP32 GPIO pins.

The UEXT headers expose the board's documented peripheral pins as well:

- UART: RXD GPIO4, TXD GPIO5
- I2C: SDA GPIO6, SCL GPIO7
- SPI2: MOSI GPIO18, MISO GPIO20, CLK GPIO19, CS GPIO21

These are left free by this example.

### Reprovisioning an operational device

A provisioned board does not need to erase its provisioning record or return to the
open provisioning access point. Connect to the normal `microtun> ` shell through the
tunnel and run the same `provision` command. The firmware receives
and validates the replacement INI, rewrites the provisioning record, verifies it, and
reboots directly into the new configuration.

To discard the installed configuration instead, run `provision clear`. The firmware
erases the provisioning record and reboots, so the next boot starts the provisioning
access point. The BOOT button remains available as the read-only `io button` shell input
and retains its normal ESP32-C6 boot-strap behavior during hardware reset.

## Board I/O over the tunnel shell

On a normal provisioned boot, TCP/23 exists only on the inner microtun interface.
This example uses [`microtun-telnet-cli`](https://github.com/microtun/microtun-telnet-cli) for the bounded no-std line editor, history, tokenization, typed argument validation, generated help/completion, command dispatch, and TELNET framing/negotiation. The firmware passes its accepted Embassy `TcpSocket` directly to a `Session`, while board-specific status formatting and command handlers remain local to this example. It uses the same root command vocabulary:

```text
help
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
net wifi
ping net 8.8.8.8
ping tunnel 10.0.0.1 3
tunnel
tunnel show
tunnel key
provision
provision clear
io
io input
io input 1
io relay
io relay 1
io relay 1 on
io relay 1 off
io relay 1 toggle
io led
io led 1
io led 1 on
io led 1 off
io led 1 toggle
io button
fw
fw show
fw update
identify
reboot
exit
```

`sys version` reads the version from the ESP-IDF application descriptor embedded in the running application image. That descriptor now uses the app package version from `app/Cargo.toml`; this `x.y.z` release SemVer is the canonical firmware version and anti-rollback floor.

`fw` / `fw show` also reads the running image's ESP application metadata and reports its version, project name, build date/time, secure version, and ESP-IDF compatibility version alongside the active OTA slot/state. The ESP application descriptor remains the native firmware identity, while the signed outer MCUboot header carries the same `x.y.z` for update anti-rollback.

`fw update` receives a signed MCUboot envelope over YMODEM, verifies the configured Ed25519 signature and component ID, and writes only the inner native ESP application image to the inactive OTA slot. While streaming, the updater captures and validates the inner image's `esp_app_desc_t` at image offset `0x20`. After the MCUboot envelope verifies, the accepted version/project/secure-version shown to the operator come from that authenticated ESP metadata rather than the MCUboot header.

The update identity uses the same human-readable names as MCUboot `imgtool`: `--vid firmware.microtun.dev --cid esp32-c6-plc-v`. The firmware derives the UUIDv5 VID/CID pair internally and requires both protected TLVs to match, so no raw UUID byte array needs to be copied into the application.

The ESP-specific firmware/OTA implementation lives in `app/src/firmware.rs`. Newly selected images are deliberately left in `NEW`/`PENDING_VERIFY` while Wi-Fi, DHCP, the tunnel, and its long-running tasks start. After the tunnel has remained operational for a 30-second trial-health window, `app/src/main.rs` marks the image `VALID`. A panic before that checkpoint performs a software reset; the rollback-capable ESP-IDF bootloader then rejects the unconfirmed image and returns to the previous valid OTA slot.

Three things happen before the new slot can become bootable:

1. **Anti-rollback.** The updater compares the signed MCUboot header version against the running app package SemVer. An update older than the running `x.y.z` is rejected. Bump `app/Cargo.toml` for each release and sign the envelope with the same value, for example `imgtool sign -v 0.4.0 ...`.

    The inner image's `esp_app_desc_t.secure_version` is reported to the operator but deliberately not enforced here. ESP-IDF's `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` uses the chip's eFuse `secure_version` as a monotonic bootloader-enforced floor. On ESP32-C6 that field is only 16 bits wide, so it provides at most 16 irreversible security-version increments over the lifetime of the device; it is an epoch/revocation counter rather than a full `major.minor.patch` release version. Burning those eFuse bits is permanent and would also make routine development/service downgrades progressively impossible. For those reasons this example keeps `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` disabled and uses the signed MCUboot `x.y.z` SemVer gate above instead.

    This is a deliberate trade-off, not equivalent hardware protection. The SemVer floor is enforced by the currently running application, whereas ESP-IDF eFuse anti-rollback is checked by the second-stage bootloader on every boot. A deployment that must prevent an older image from being installed or selected through direct flash access should use an appropriate production boot chain (for example Secure Boot plus ESP-IDF eFuse anti-rollback), or move an authenticated SemVer floor into the bootloader.
2. **Read-back verification.** Streaming verification only proves the bytes on the wire were authentic. Once the transfer completes, the partition is read back and the canonical MCUboot digest — `header || payload-from-flash || protected TLVs` — is recomputed and compared against the digest the signature already covered, the same check `bootutil_img_validate` performs before booting a slot. The header and protected TLVs are the only parts of the container not written to the partition, so they are retained from the transfer; no non-standard hash and no image-format change is involved. A partial or failed program therefore cannot be activated.
3. **A single activation write.** The image state is staged into the otadata entry that activation is about to claim, before the sequence number is bumped. `set_current_app_partition` preserves the state field it finds there, so activating first and setting `NEW` afterwards left a window where a reset could select the new slot carrying a stale `VALID` from that slot's previous life — skipping the trial and disabling rollback entirely.

Note what the version gate does and does not buy: it is enforced by the running application, so anyone with physical access can write the OTA partition directly and bypass it, exactly as they can bypass the signature check itself without Secure Boot v2. What it does cover is the realistic attack against this example — reaching `fw update` over the tunnel, or over the unauthenticated provisioning AP, with an old but validly signed release.

The trial wait for the inner tunnel link is bounded (120 s) and the RWDT is armed at 20 s with a petting task, so a trial image that boots but wedges is reset into rollback instead of running unconfirmed forever. Synchronous flash work runs with the cache and interrupts disabled, so those paths pet the watchdog directly.

`fw update` also now waits for the peer to actually agree to TELNET binary mode (`WILL`/`DO BINARY`) before starting YMODEM, rather than requesting it and assuming. A client that refuses or never answers fails fast with a clear message instead of producing a corrupt transfer that only fails later at signature verification.

This behavior depends on the **second-stage bootloader** being built with ESP-IDF application rollback enabled. `bootloader/Dockerfile.boot` builds that bootloader into `bootloader/target/bootloader.bin`, and `app/espflash.toml` requires that output, so `espflash` cannot silently fall back to a stock non-rollback bootloader.


`io input` reports logical `active`/`inactive` states, hiding the optocoupler's
active-low MCU polarity. `io relay` reports relay state in numeric order, and
`io relay N on|off|toggle` controls one relay. All relay GPIOs are initialized
low so the relays start de-energized.

`io led` and `io led 1` report the logical RUN LED state, while `io led 1 on`,
`io led 1 off`, and `io led 1 toggle` control it without exposing the active-low
GPIO8 polarity. `identify` blinks the RUN LED three times and restores its previous state.
`io button` reports the active-low BOOT button as `pressed` or `released`. The button
does not erase or otherwise modify provisioning state.

`sys time` uses the shared `unix=<seconds>.<nanoseconds>` representation on both embedded targets.

`net mac` reports the station interface MAC address, matching the Nucleo example.
The top-level `net` output also includes a concise Wi-Fi summary with SSID, channel,
RSSI, and reconnect count (or `disconnected` when not associated). `net wifi` reports
those diagnostics in full plus the currently associated BSSID. BSSID, channel, and
RSSI are reported as `n/a` while AP metadata is unavailable.

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

## Build and flash

Install the ESP32-C6 Rust target and `espflash`. Build the rollback-capable second-stage bootloader once (and again whenever its configuration changes), then build the Rust application from its independent `app/` Cargo project:

```bash
rustup target add riscv32imac-unknown-none-elf
cargo install espflash --locked
cd examples/esp32-c6-plc-v/bootloader

mkdir -p target
docker build -f Dockerfile.boot \
  --output type=local,dest=./target \
  .

cd ../app
cargo build --locked
```

`app/espflash.toml` pins `../bootloader/target/bootloader.bin`; if it is missing, flashing fails instead of using a bootloader without rollback. The app-local Cargo runner flashes its own `partitions.csv` and opens a monitor:

```bash
cd examples/esp32-c6-plc-v/app
cargo run --release
```

For an already-deployed board, the rollback-capable second-stage bootloader must be installed through your trusted manufacturing/service process before relying on trial-boot recovery. Merely updating the Rust application cannot change the behavior of an older bootloader already present at `0x0`.

The ICBBUY schematic exposes native USB/JTAG on `USB1` and also provides an
ESP-PROG header. `espflash` normally auto-detects the connected ESP32-C6, so the
runner does not hard-code a serial port.

## Provisioning mode

The board-independent provisioning-mode protocol lives in the workspace
`microtun-provisioning` crate, while shared mDNS networking lives in
`microtun-net-util`. This example supplies ESP32-C6 identity, flash
storage, Embassy socket ownership, the board's active-low GPIO8 RUN LED, and
reset.

The firmware normally loads the 4 KiB provisioning record from the dedicated
`microtun` partition at `0x003f0000`. If that record is absent, corrupt, or
contains an invalid configuration, the board does not panic. It starts its own
open Wi-Fi access point and enters provisioning mode instead.

### Per-device SSID

The access point's SSID is the device ID behind a fixed prefix:

```text
microtun-<device_id>
```

For example, a factory eFuse base MAC of `54:32:04:aa:bb:cc` produces the SSID
`microtun-0wtbtgcuz0`. The `device_id` is the 48-bit base MAC itself encoded as the
same fixed-width 10-character lower-case base36 value used by every platform; no
separate device-ID hash is applied. The SSID is therefore stable across resets, and
the device ID can be decoded back to the base MAC.

### Automatic addressing

The provisioning access point uses:

```text
192.168.7.1/24
```

and runs a small DHCP server that assigns the provisioning host an address from
`192.168.7.2` through `192.168.7.20`. Leave the host Wi-Fi interface configured for
automatic/DHCP addressing; no manual address setup is required. No default gateway or
DNS server is advertised.

The board advertises `_microtun._tcp.local` over mDNS/DNS-SD and publishes
`microtun-<device_id>.local` for its current address. Provisioning mode serves the
Telnet CLI directly at `192.168.7.1:23` on this isolated AP.

### Security

**The provisioning access point is open.** Provisioning mode is an
unauthenticated recovery/provisioning interface. Provision unconfigured boards
in a controlled radio environment, or add a build-time WPA2 passphrase in
`start_provisioning_ap` if that is not acceptable for your deployment.

Use `sys id`/`identify` after connecting to confirm the target before running
`provision`. This protects against operator mistakes but is not authentication.

### Provisioning Telnet CLI

Provisioning mode serves the same main `microtun-telnet-cli` shell used after
provisioning, but on the outer provisioning interface at TCP port `23`. On the isolated
AP that is `192.168.7.1:23`. The prompt remains `microtun> ` and the normal command set
is available, including `sys`, `net`, `io`, `fw`, `identify`, `reboot`, and `quit`.

`sys` reports `mode` as `provisioning` and `provisioned` as `false`, alongside the normal
board, ID, version, reset, temperature, uptime, time, and memory fields. Interface details
such as the MAC remain available through `net mac`, and board-I/O queries continue to
work. Tunnel-dependent operations fail
cleanly until configuration exists:

```text
microtun> tunnel show
unavailable: tunnel is not configured in provisioning mode

microtun> ping tunnel 100.64.0.1
unavailable: tunnel is not configured in provisioning mode
```

Bare `provision` starts the receive flow in this same shell. It prints
`MICROTUN-PROVISION-YMODEM-1K READY` and hands that same Telnet connection to
YMODEM-1K/CRC. The sender supplies the filename and exact decimal file size in the
standard YMODEM block 0. The receiver rejects a declared size above `MAX_INI_LEN` before
accepting payload bytes and discards normal transfer padding beyond the advertised
length. After a successful transfer, the firmware validates and encodes the config,
erases and rewrites the 4 KiB `microtun` partition, reads it back, validates the stored
record again, prints `configuration stored; rebooting`, and resets. If transfer,
validation, write, or verification fails, the board remains in provisioning mode.

Provisioning mode is served only when the normal provisioning record cannot be loaded.
A configured device normally stays operational while being reprovisioned: run
`provision` through its tunnel shell, transfer the replacement INI, and let the
successful write reboot the board into the new configuration. Run `provision clear` to
erase the current provisioning record and reboot into provisioning mode; there is no
button-driven clear path.

## Provisioning from the host

Connect the provisioning host to the board's `microtun-<device_id>` access point and
leave the Wi-Fi interface on automatic/DHCP addressing. Discover the board, then connect
using its IP address:

```bash
cargo run -p microtun-telnet -- discover
cargo run -p microtun-telnet -- 192.168.7.1
```

At the remote `microtun> ` prompt, run `provision` manually. After the board prints the
READY marker and enters YMODEM receive mode, press `Ctrl-]` and run
`ymodem path/to/device.conf`. To reprovision an already-operational board, connect
directly to its tunnel IP (`cargo run -p microtun-telnet -- <TUNNEL_IP>`) and follow the
same sequence. For firmware, manually run `fw update`, then use local
`ymodem path/to/app.mcuboot` after the receiver starts. See `microtun-telnet/README.md`
for the full client behavior.

## Bootloader

The rollback-capable ESP-IDF second-stage bootloader is intentionally separate from the Rust application. From `examples/esp32-c6-plc-v/bootloader/`, build it with:

```bash
mkdir -p target

docker build -f Dockerfile.boot \
  --output type=local,dest=./target \
  .
```

This writes `bootloader/target/bootloader.bin` relative to the example root. The Rust application in `app/` consumes that artifact only when flashing; its partition table and Cargo build settings remain app-local.