# microtun-ymodem

`microtun-ymodem` is a small `no_std`, allocation-free YMODEM-1K/CRC receiver for
embedded transports.

It requires the standard YMODEM block 0 and parses the filename and decimal file
size from that metadata block. The receiver therefore knows the exact file length
without an out-of-band size argument and strips padding before data reaches the
sink.

Data blocks may use either 128-byte `SOH` or 1024-byte `STX` framing with
CRC-16/XMODEM. A transfer completes with the normal YMODEM EOT handshake followed
by an empty block 0 terminating the one-file batch.

```sh
cargo test -p microtun-ymodem
```
