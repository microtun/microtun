# microtun-serial

`microtun-serial` is the serial character-device companion to `microtun-console`. It connects to a remote serial COM-PORT-OPTION server and exposes the connection as a Linux CUSE serial character device.

```text
microtun-serial device.example.net --port 2217 --name microtun0
```

The resulting `/dev/microtun0` accepts normal termios and common serial ioctls; configuration changes are translated to serial commands and remote line/modem state is reflected back to local users.

This package is Linux-only because CUSE is a Linux interface. For an interactive serial console, use `microtun-console`, press `Ctrl-A P`, and enable serial mode from the communication-parameters popup.
