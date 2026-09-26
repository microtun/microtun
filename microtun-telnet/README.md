# microtun-telnet

Interactive Telnet client with a terminal UI and YMODEM upload support.

TELNET BINARY negotiation, receive-side framing, and IAC escaping are provided by `microtun-telnet-proto`, the same protocol core used by the embedded firmware transfer path.

Serial-console support is selected from inside the TUI rather than on the command line. Connect to the desired endpoint normally:

```text
microtun-telnet device.example.net --port 2217
```

The command prefix follows Minicom where the operations line up: `Ctrl-A Z` opens help, `Ctrl-A S` sends a file, `Ctrl-A C` clears the screen, `Ctrl-A Q` quits, `Ctrl-A P` opens communication parameters, and `Ctrl-A F` sends BREAK.

Press `Ctrl-A P` to open the communication-parameters popup. The first row switches the live connection between normal Telnet mode and serial mode. Use the arrow keys to navigate the popup; Enter or Space chooses/toggles the selected item and Escape closes it.

Enabling serial mode negotiates Telnet binary/suppress-go-ahead and the serial COM-PORT-OPTION on the existing connection. It does **not** set the remote baud rate, data bits, parity, stop bits, flow control, DTR, or RTS. The client only queries the current serial state after serial mode becomes active, so if the remote UART is already configured correctly its logging/output bytes are displayed immediately, including while serial negotiation is still in progress.

Baud rate, data bits, parity, stop bits, flow control, DTR, and RTS are changed only when explicitly requested in the communication-parameters popup. BREAK can be sent either with `Ctrl-A F` from the terminal or `F` while that popup is open. Turning the first row back off restores the Telnet option state from before serial mode was enabled.

For applications that need a normal Linux `/dev` serial character device and termios/ioctl behavior, use the companion `microtun-serial` binary instead.
