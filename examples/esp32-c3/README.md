# microtun ESP32-C3 example

This example is built once and provisioned separately. Device-specific Wi-Fi,
WireGuard keys, tunnel addresses, API server details, and NTP settings are not
compiled into the firmware.

## Flash layout

`partitions.csv` targets a 4 MiB ESP32-C3 flash:

- factory application: `0x00010000..0x003f0000`
- `microtun` custom provisioning partition: `0x003f0000..0x003f1000`
- one portable 4 KiB provisioning record fills the partition

The record is a small versioned binary header followed by the original JSON and
`0xff` padding. The same record format is also used by the STM32H753 example.

## Provision

Copy `provision.example.json`, replace the placeholder credentials/keys, and from
the repository root run:

```sh
cargo run -p microtun-provision -- path/to/device.json \
  --target esp32 --address 0x003f0000 --port /dev/ttyACM0
```

The command validates the JSON using the same `microtun-provision` `no_std` library
as the firmware, writes the single provisioning record with `espflash`, and reads
it back for verification. No firmware rebuild is required.

The CRC detects corruption; it does not encrypt or authenticate provisioning data.
