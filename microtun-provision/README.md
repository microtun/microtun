# microtun-provision

`microtun-provision` is the host-side provisioning utility for Microtun embedded devices. It validates a device INI configuration, encodes it as the portable 4 KiB MTUN provisioning record used by `microtun-device-config`, writes that record to device flash, and verifies the write.

The repository currently contains two firmware examples with different flash layouts and provisioning requirements:

| Example | Hardware / chip | `--target` | Provisioning address | Configuration notes |
| --- | --- | --- | --- | --- |
| `examples/esp32-c3` | ESP32-C3, RISC-V `riscv32imc-unknown-none-elf` | `esp32` | `0x003f0000` | `[WiFi]` is required by this firmware; `[NTP]` is optional. |
| `examples/nucleo-h753zi` | NUCLEO-H753ZI / STM32H753ZI (`STM32H753ZITx` in probe-rs) | `stm32` | `0x081e0000` | Wired Ethernet; `[WiFi]` is not needed; `[NTP]` is optional. |

The addresses above are part of the example firmware layouts. Do not substitute an address from one target for the other.

## Build

From the repository root:

```bash
cargo build -p microtun-provision
```

You can either run the resulting `microtun-provision` binary directly or use `cargo run -p microtun-provision -- ...` as shown below.

## Configuration format

The input is the same device INI schema consumed by `microtun-device-config`, the embedded examples, and `microtun-linux`:

```ini
[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = Device

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10
# IPv4 and IPv6 are supported; a bare address becomes /32 or /128.
# Optional:
# MTU = 1280
# ListenPort = 51820
# EnableForwarding = true

[ApiServer]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
# A bare address is sufficient. If a CIDR is supplied, its host address is used.
TunnelAddress = 100.64.0.1

# Optional on targets that use NTP.
[NTP]
Host = time.google.com
Port = 123
```

For the ESP32-C3 example, add Wi-Fi credentials:

```ini
[WiFi]
SSID = YOUR_WIFI_SSID
Password = YOUR_WIFI_PASSWORD
```

`[WiFi]` is optional in the shared schema because wired targets exist, but `examples/esp32-c3` explicitly requires it at runtime. The NUCLEO-H753ZI example uses wired RMII Ethernet and does not require a `[WiFi]` section.

A complete starting point is available at `microtun-device-config/device.example.conf`. Replace the example keys, addresses, host, and credentials with values for the device being provisioned.

Before touching flash, `microtun-provision` parses and validates the INI. The encoded record is 4096 bytes and includes the MTUN header, the original INI payload, a CRC32, and erased-flash (`0xff`) padding.

## ESP32-C3 example

The ESP32-C3 example defines a dedicated 4 KiB `microtun` partition in `examples/esp32-c3/partitions.csv`:

```text
microtun,  0x40, 0x00,  0x3f0000, 0x1000,
```

The firmware reads its provisioning record from `0x003f0000`, so provision it with:

```bash
cargo run -p microtun-provision -- path/to/esp32-c3.conf \
  --target esp32 \
  --address 0x003f0000
```

If more than one serial device is present, select the port explicitly:

```bash
cargo run -p microtun-provision -- path/to/esp32-c3.conf \
  --target esp32 \
  --address 0x003f0000 \
  --port /dev/ttyUSB0
```

The ESP32 backend invokes `espflash`. By default it looks for `espflash` in `PATH`; use `--espflash /path/to/espflash` to override the executable.

Do **not** pass `--chip` for the ESP32 target. The current provisioning CLI only uses `--chip` with the STM32/probe-rs backend and rejects it with `--target esp32`. The firmware example itself is specifically configured for ESP32-C3 (`riscv32imc-unknown-none-elf`).

For ESP32, verification is explicit: the tool writes the 4 KiB record with `espflash write-bin`, reads the same range back with `espflash read-flash`, compares the bytes, and decodes the returned record again.

## NUCLEO-H753ZI / STM32H753ZI example

`examples/nucleo-h753zi` targets the NUCLEO-H753ZI board and enables Embassy's `stm32h753zi` support. Its Cargo runner identifies the MCU to probe-rs as:

```text
STM32H753ZITx
```

The firmware reserves the final 128 KiB internal-flash erase sector so application code cannot grow into provisioning storage. The portable 4 KiB record starts at physical flash address `0x081e0000`.

Provision the example from the repository root with:

```bash
cargo run -p microtun-provision -- path/to/nucleo-h753zi.conf \
  --target stm32 \
  --chip STM32H753ZITx \
  --address 0x081e0000
```

To select a particular debug probe, add `--probe`; the repository's example command uses `0483:374e`:

```bash
cargo run -p microtun-provision -- path/to/nucleo-h753zi.conf \
  --target stm32 \
  --chip STM32H753ZITx \
  --address 0x081e0000 \
  --probe 0483:374e
```

The STM32 backend invokes `probe-rs`. By default it looks for `probe-rs` in `PATH`; use `--probe-rs /path/to/probe-rs` to override the executable.

`--chip` is mandatory with `--target stm32`. For this example use the exact probe-rs chip identifier `STM32H753ZITx`, not the board name `NUCLEO-H753ZI`.

The firmware source reads the same location as offset `0x001e0000` through the STM32 flash peripheral API. That is an offset from the STM32 internal-flash base; the host flashing address passed to probe-rs is the absolute address `0x081e0000`.

The tool flashes the raw record with `probe-rs download --binary-format=bin --base-address=... --verify`, so probe-rs performs write verification.

## Command-line options

```text
microtun-provision <CONFIG> --target <esp32|stm32> --address <ADDRESS> [OPTIONS]
```

Important options:

- `CONFIG`: path to the device INI file; it is validated before flashing.
- `--target esp32|stm32`: selects the flashing backend.
- `--address <ADDRESS>`: provisioning-record flash address. Decimal and `0x`/`0X` hexadecimal forms are accepted.
- `--chip <CHIP>`: required for STM32 and invalid for ESP32.
- `--port <PORT>`: optional serial port passed to `espflash`.
- `--probe <SELECTOR>`: optional debug-probe selector passed to `probe-rs`.
- `--espflash <PATH>`: override the `espflash` executable; defaults to `espflash`.
- `--probe-rs <PATH>`: override the `probe-rs` executable; defaults to `probe-rs`.

Run `microtun-provision --help` for the CLI-generated help for the version you built.

## Safety and layout notes

Provisioning writes directly to flash. Always use the address defined by the firmware/partition layout for the exact target you are flashing.

For the ESP32-C3 example, `0x003f0000` is a dedicated 4 KiB custom partition. For the STM32H753ZI example, `0x081e0000` is the start of a 4 KiB record inside an entire 128 KiB sector deliberately reserved from the application image because STM32 erase granularity is larger than the portable record.

Flashing firmware and provisioning data are separate operations. Rebuilding the firmware does not create device-specific provisioning data, and the examples expect a valid MTUN record to be present when they boot.
