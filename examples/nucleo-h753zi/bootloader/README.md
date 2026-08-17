# NUCLEO-H753ZI first-stage bootloader

This is the immutable recovery stage for the Nucleo example. It uses
`embassy-boot-stm32` to swap the ACTIVE and DFU partitions power-fail-safely.
A candidate application remains a trial until the application calls
`BlockingFirmwareState::mark_booted()`. Any reset before that confirmation
causes the next bootloader pass to restore the previously confirmed ACTIVE
image.

Build/flash this project through SWD before flashing the application:

```sh
cargo build --release
cargo run --release
```

The bootloader and sibling `../app/` project both consume the shared `../memory.x`, which defines the
complete physical flash map once. The bootloader selects the `BOOTLOADER` region while the
application selects `ACTIVE`; Embassy Boot partition offsets are derived from those regions.
The application itself is linked at `0x0802_0000`; do not erase sector 0 when performing
normal application updates.
