# microtun-provision

Provisioning format library and host utility for the microtun embedded examples.

The package deliberately contains two Cargo targets:

- the library (`microtun_provision`) is always `#![no_std]` and owns the JSON schema,
  validation, record header, CRC32, and record encode/decode logic;
- the `microtun-provision` binary is host-only and gated by the default `cli` feature.

Embedded firmware should disable default features:

```toml
microtun-provision = { path = "../../microtun-provision", default-features = false }
```

The host utility validates a JSON configuration, builds the portable 4 KiB record
in memory, flashes it, and verifies the write:

```sh
cargo run -p microtun-provision -- device.json \
  --target esp32 --address 0x003f0000 --port /dev/ttyACM0

cargo run -p microtun-provision -- device.json \
  --target stm32 --chip STM32H753ZITx --address 0x081e0000 --probe 0483:374e
```

To explicitly verify the embedded library without pulling in the CLI dependency:

```sh
cargo check -p microtun-provision --no-default-features --lib
```

The CLI selects a flashing backend, not a concrete MCU variant. `--target esp32`
uses `espflash`, which identifies the connected ESP chip, while `--target stm32`
uses `probe-rs download` and takes the probe-rs target name from `--chip`. The
provisioning address is always supplied with `--address` because it belongs to
the firmware/board flash layout rather than to the MCU family.

The ESP32-C3 and STM32H753 examples still use the same 4 KiB on-flash record;
their example commands simply provide their own layout address (and, for STM32,
the probe-rs chip name).

The record CRC is for corruption detection only; it does not provide encryption or
authentication.
