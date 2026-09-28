# microtun-telnet

A `no_std` Telnet protocol core shared by Microtun's embedded shell and desktop client.

It provides:

- RFC 854 framing and IAC/subnegotiation decoding.
- RFC 1143 Q-method option negotiation with independent local/remote capability policy.
- Shared RFC 856 BINARY negotiation/state helpers and IAC-safe application-data framing.
- A runtime-agnostic RFC 856 BINARY byte-stream adapter for protocols such as YMODEM. On an
  established Telnet connection, `BinaryMode::with_telnet` borrows the existing negotiation state
  so RFC 1143 state survives interactive/binary mode handoffs.
- Atomic subnegotiation framing with IAC escaping.
- Serial COM-PORT-OPTION (option 44) command constants, typed decode/encode support, server acknowledgement command offsets, line/modem state masks, purge controls, and all SET-CONTROL values.
- A runtime-free `client::ClientSession` that owns terminal/serial option policy, serial activation/refusal, serial-state tracking, initial discovery queries, and client command encoding.
- A matching runtime-free `server::ServerSession` with RFC 2217 negotiation, typed client requests, confirmation/notification helpers, and generic line/modem mask plus suspend/resume state.

The embedded transfer path, desktop `microtun console` client, and host `microtun serial` bridge use the same framing and negotiation core. Serial clients share `client::ClientSession`, while RFC 2217 access servers can use `server::ServerSession`; TCP/Tokio/Embassy I/O, timeout policy, UART configuration, and UI/device orchestration remain outside this crate.

The crate deliberately does not own a UART, socket, timeout policy, or file-transfer state machine. Lower-level endpoints can still supply a custom `Policy` directly to `Telnet`; serial clients can use `ClientSession` for the standard Microtun client policy and state tracking. This keeps the protocol state machine usable by a terminal client, an embedded shell, or a serial access server without pulling in `std` or a particular async runtime.

For serial mode, `ClientSession::enter_serial_mode` requests the required TELNET options and reports activation/refusal through `ClientEvent`. `queue_initial_serial_query` and the `set_*` helpers encode the common client operations. `ServerSession::start` provides the complementary access-server negotiation; `ServerEvent::Serial` yields typed requests and the `confirm_*`/`notify_*` helpers encode server-origin replies. Lower-level users can continue to use `serial::decode`/`decode_from` and `serial::encode` directly. The conventional RFC 2217 TCP port is available as `serial::DEFAULT_PORT`.
