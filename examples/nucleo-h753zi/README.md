# microtun Nucleo-H753ZI example

This example is built once and provisioned separately. Device-specific WireGuard
keys, tunnel addresses, API server details, and NTP settings are stored in flash
rather than compiled into the firmware.

## Flash layout

The STM32H753ZI has 2 MiB of internal flash. The final 128 KiB erase sector is
reserved for provisioning:

- firmware: `0x08000000..0x081e0000`
- reserved provisioning sector: `0x081e0000..0x08200000`
- portable MTUN record: first 4 KiB at `0x081e0000`

`provision.x` adds a linker assertion so a growing firmware image fails to link
instead of silently overlapping the provisioning sector.

## Provision

Copy `provision.example.json`, replace the placeholder keys/settings, and from
the repository root run:

```sh
cargo run -p microtun-provision -- path/to/device.json \
  --target stm32 --chip STM32H753ZITx --address 0x081e0000 --probe 0483:374e
```

The host utility validates the JSON with the same `microtun-provision` `no_std`
library used by firmware and uses `probe-rs download --verify` to program the
single 4 KiB record at `0x081e0000`. No firmware rebuild is required.

