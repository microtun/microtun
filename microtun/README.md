# microtun

The unified host-side `microtun` executable.

All former host binaries are exposed as subcommands of one binary and are built from this single crate:

```text
microtun tunnel [-i mt0] /path/to/device.toml
microtun tracker /etc/microtun/tracker.toml
microtun console device.example.net
microtun console --serial device.example.net
microtun serial device.example.net --port 2217 --name ttyMT0
microtun serial device.example.net --baudrate 115200 --data-bits 8 --name ttyMT0
```

`microtun run` is an alias for `microtun tunnel`.

## `tunnel`

Runs the Linux Microtun daemon. It combines `microtun-std` with Linux TUN setup, host configuration, logging, and process lifecycle.

## `tracker`

Runs the Tracker and serves the Peers API from the tunnel. `TRACKER_CONFIG` can be used instead of the positional configuration path.

## `console`

Interactive console client with a terminal UI and YMODEM upload support. By default, `microtun console TARGET` opens a Telnet console on port 23. `microtun console --serial TARGET` opens an RFC 2217 serial console, negotiates COM-PORT-OPTION immediately, and defaults to port 2217. `--port` overrides either default.

Serial consoles can request their initial line settings from the command line with one canonical option per setting: `--baudrate`, `--data-bits`, `--parity`, `--stop-bits`, and `--flow-control`. Unspecified parameters are left unchanged. For example:

```text
microtun console --serial --baudrate 115200 --data-bits 8 device.example.net
microtun console --serial --baudrate 57600 --data-bits 7 --parity even --stop-bits 2 --flow-control rts-cts device.example.net
```

The two console variants are deliberately distinct in the UI: there is no Telnet/serial mode selector. A normal Telnet console exposes only the common commands. A `--serial` console adds `Ctrl-A P` for serial parameters and `Ctrl-A F` for a 250 ms BREAK pulse. The serial parameters screen edits baud rate, data bits, parity, stop bits, flow control, DTR, and RTS directly; it does not contain a mode toggle. If the server refuses COM-PORT-OPTION, the serial console exits with an error rather than falling back to Telnet.

The common command prefix follows Minicom where the operations line up: `Ctrl-A Z` opens help, `Ctrl-A S` sends a file, `Ctrl-A B` opens the scrollback buffer, `Ctrl-A C` clears the screen, and `Ctrl-A Q` quits. In scrollback mode, use the arrow keys for one line, PageUp/PageDown for one page, Space for page down, and Esc to return to the live console.

## `serial`

Connects to a remote serial COM-PORT-OPTION server and exposes the connection as a Linux CUSE serial character device. The resulting `/dev/NAME` accepts normal termios and common serial ioctls.

The same canonical startup line-setting options as `console --serial` are available: `--baudrate`, `--data-bits`, `--parity`, `--stop-bits`, and `--flow-control`. Requested settings are applied immediately after RFC 2217 negotiation and before the remote state is discovered; unspecified parameters are discovered without being changed. Normal termios/ioctl changes on `/dev/NAME` can override them later. For example:

```text
microtun serial device.example.net --baudrate 115200 --data-bits 8 --name ttyMT0
microtun serial device.example.net --baudrate 57600 --data-bits 7 --parity even --stop-bits 2 --flow-control rts-cts --name ttyMT0
```

This subcommand is Linux-only because CUSE is a Linux interface. Building it on Linux requires the libfuse3 development headers and `pkg-config`.

## Internal layout

The binary is deliberately organized by command rather than by the crates the tools used to live in:

```text
src/
├── main.rs                 # parse + dispatch only
├── cli.rs                  # clap surface
├── logging.rs              # process-wide tracing setup
└── commands/
    ├── tunnel/             # Linux tunnel implementation + non-Linux stub
    ├── tracker/            # tracker server, registry, resolver, RPC, virtual TCP
    │   └── config/         # TOML event parser separated from validation
    ├── serial_settings.rs  # shared serial CLI values + RFC2217 startup settings
    ├── console/            # Telnet client, TUI, key handling, uploads
    └── serial/             # RFC2217 session + Linux virtual serial device
        ├── cuse/           # generic CUSE wrapper and C shim
        └── device/         # serial/termios adapter built on that wrapper
```

Command-private code stays under its command. Shared serial CLI/protocol settings live in `commands/serial_settings.rs`, while the only crate-root support module is `logging`. This keeps command dependencies visible and avoids the old flat module namespace where unrelated tracker, console, and serial implementation details could refer to each other accidentally.
