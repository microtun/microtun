# esp32-c3-dongle

ESP32-C3 dongle firmware integrated into the microtun firmware workspace.
It keeps the existing setup/management/OTA/tunnel behavior and adds an RFC 2217
Telnet COM-PORT-OPTION server on TCP port **2217** for the board's physical RS232
port.

Both operational TCP services are reachable on the **microtun inner interface**:

- TCP 23 — existing management Telnet shell.
- TCP 2217 — single-client RFC 2217 RS232 bridge.

Setup mode is intentionally unchanged: an unconfigured device exposes only the
existing setup Telnet service on its temporary Wi-Fi AP. The RFC 2217 service is
started after the operational tunnel is up.

## Hardware / pinout

This target is for the **LEOTRO ESP32-C3 RS232 Adapter V1.1** schematic. The
SP3232 level shifter is already on the board, so these are MCU-side GPIOs; do not
connect raw RS232 voltages directly to ESP32-C3 pins.

| Function | ESP32-C3 GPIO | Board net | DE-9 pin | Direction from ESP32-C3 |
|---|---:|---|---:|---|
| RS232 TX | GPIO10 | `MCU_TX` / `RS232_TX` | 3 | output |
| RS232 RX | GPIO4 | `MCU_RX` / `RS232_RX` | 2 | input |
| RS232 RTS | GPIO0 | `MCU_RTS` / `RS232_RTS` | 7 | output |
| RS232 CTS | GPIO1 | `MCU_CTS` / `RS232_CTS` | 8 | input |
| Ground | — | GND | 5 | — |
| BOOT button | GPIO9 | `BOOT` | — | input, active low |
| USB D- / D+ | GPIO18 / GPIO19 | `DN` / `DP` | USB-C | native USB |

The board LED is wired as a power LED, not to a GPIO. The management shell's
`identify` operation therefore remains a no-op, matching the source firmware's
board profile.

The SP3232 inverts the handshake signals. The firmware consequently drives
GPIO0 low for asserted RS232 RTS and treats GPIO1 low as asserted RS232 CTS.
UART1 is used for the data path so the exposed serial port is independent of
firmware diagnostics.

## RFC 2217 behavior

The implementation uses the `microtun-telnet` `ServerSession` API for
RFC 854/RFC 1143 negotiation, typed RFC 2217 request decoding, notification
masks, flow-control suspend/resume state, confirmations, and modem/line-state
notifications. The firmware itself only owns the ESP32-C3 UART/GPIO policy and
the TCP/UART byte pump. Serial defaults are 115200 8N1. The server supports:

- baud-rate queries/changes from 1 through 5,000,000 baud (subject to ESP32-C3
  UART clock tolerance);
- 5, 6, 7, or 8 data bits;
- none, odd, or even parity;
- 1, 1.5, or 2 stop bits when accepted by the UART hardware;
- RFC 856 BINARY mode and IAC escaping for arbitrary serial data;
- RTS control and CTS modem-state reporting;
- no-flow-control, XON/XOFF, or RTS/CTS flow-control requests;
- line-state and modem-state masks/notifications, including an initial modem-state snapshot for clients such as pySerial;
- receive purge (best effort), flow-control suspend/resume, and BREAK requests.

Board/hardware limitations are reported by acknowledging the setting that is
actually in effect rather than pretending a physical feature exists:

- MARK and SPACE parity are not implemented by the selected `esp-hal` UART API.
- DTR is not routed on this adapter, so DTR is tracked logically for RFC 2217
  clients but has no physical effect.
- XON/XOFF is implemented in software. Incoming XOFF (`0x13`) pauses UART TX
  and XON (`0x11`) resumes it; the control bytes are consumed rather than
  forwarded as serial payload. Inbound software flow control sends XOFF/XON
  while UART RX delivery is backpressured. UART TX is limited to short bursts
  so a peer's XOFF is observed promptly.
- RTS/CTS flow control is software-gated using the board GPIOs so CTS can also be
  reported as MODEMSTATE. It is not UART-peripheral hardware gating.
- `BREAK ON` emits a finite approximately 250 ms UART break and records the
  logical RFC 2217 break state; the HAL does not expose a latched break output.
- Receive purge drains bytes already available from the UART RX side. The HAL
  has no public API for discarding bytes already committed to the TX FIFO.

Only one RFC 2217 client is accepted at a time. The existing management Telnet
server is independent and remains available concurrently.

## Client example

With pySerial:

```python
import serial

ser = serial.serial_for_url(
    "rfc2217://<device-tunnel-address>:2217",
    baudrate=115200,
    bytesize=8,
    parity="N",
    stopbits=1,
    xonxoff=False,
    timeout=1,
)
ser.write(b"hello\r\n")
print(ser.read(128))
```

For a device configured for software flow control (for example a Zebra printer
using `^SC9600,8,N,1,X,N`), set `baudrate=9600` and `xonxoff=True` so the RFC
2217 client asks the dongle to enable XON/XOFF handling.

Use the device's configured **tunnel address**, not its Wi-Fi DHCP address, if
you want the same access boundary as the management shell.

## Dependencies

This target is a member of the repository's `firmware/` Cargo workspace and uses the local microtun crates, including `microtun-telnet` for the RFC 2217 server. Its package version is inherited from the firmware workspace so OTA/version policy remains aligned with the other firmware targets.

## Build

Build the rollback-capable ESP-IDF second-stage bootloader first:

```sh
cd bootloader
docker buildx build \
  --file Dockerfile.boot \
  --output type=local,dest=target \
  .
cd ../app
```

That creates `bootloader/target/bootloader.bin`, which `app/espflash.toml` references. For a local application build/flash from `app/`:

```sh
cargo build --release
cargo run --release
```

Release images use the repository's normal firmware signing flow. From the repository root:

```sh
scripts/make-mcuboot-image.sh esp32-c3-dongle
```