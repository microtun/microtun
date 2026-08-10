# Microtun Relay Protocol

## 1. Purpose

Microtun can deliver a WireGuard packet through an authenticated relay when the
final peer is not directly reachable.

Let `A` be the sender, `B` the destination, and `R` the relay. `A` first builds
the ordinary end-to-end WireGuard packet for `B`:

```text
I = WG(A -> B, payload)
```

It then submits that complete packet to `R` using Microtun transport message
**private type `0xF0` (240)**:

```text
A -- WG0xF0(A -> R, B.static_key || len(I) || I) --> R -- I --> B
```

`R` authenticates `A` and learns the requested destination `B`, but `I` remains
encrypted and authenticated end to end between `A` and `B`.

The relay protocol is deliberately single-hop. A relay forwards `I` only to a
directly reachable destination. It never wraps the request for another relay.

## 2. Relay message type `0xF0`

Types 1-4 keep their standard WireGuard meanings. Microtun defines:

```text
0xF0 (240) = relay transport data
```

The relay identifier is intentionally high and non-sequential. WireGuard v1
uses the 8-bit type namespace with three following reserved zero bytes and
currently assigns types 1 through 4. Keeping the relay at `0xF0` avoids the
obvious future allocation path (`5`, `6`, ...) while preserving WireGuard's
three zero reserved bytes. `0xF0` is a Microtun-private value, not an upstream
WireGuard allocation.

Relay type `0xF0` has the same outer transport layout as WireGuard type 4:

```text
struct RelayTransport {
    u8  type;          // 0xF0
    u8  reserved[3];   // zero
    u32 receiver_le;
    u64 counter_le;
    u8  encrypted_payload[];
    u8  tag[16];
}
```

It uses the existing hop-local WireGuard session with the relay: the same
receiver index, transport keys, monotonically increasing counter, replay
window, 16-byte plaintext padding, rekey timers, keepalives, and endpoint
learning rules.

There is no relay-specific handshake.

### 2.1 Authenticated type selector

Standard WireGuard type 4 continues to use empty AEAD associated data.

For relay type `0xF0`, Microtun authenticates the literal four-byte message
prefix:

```text
F0 00 00 00
```

as AEAD associated data. This binds the type selector to the ciphertext, so an
attacker cannot change a valid type-4 packet into relay type `0xF0`, or vice
versa, without causing authentication to fail.

No separate protocol-name string or relay version field is used. This document
defines the semantics of relay type `0xF0` directly. It is the only relay wire
encoding; older relay encodings are not accepted as compatibility modes.

## 3. Relay plaintext

After successful relay-message decryption, the plaintext is:

```text
struct RelayEnvelope {
    u8  destination_public_key[32];
    u32 inner_len_le;
    u8  inner_wireguard_packet[inner_len];
}
```

The destination key is the peer's 32-byte X25519 static public key. The sender
cannot provide an arbitrary UDP destination.

There is no envelope version, hop limit, or path. The fixed relay header is 36
bytes. The four-byte length field places the embedded WireGuard datagram on a
natural four-byte boundary.

### 3.1 Inner length and padding

`inner_len` gives the exact length of the inner WireGuard datagram. The relay
requires:

```text
36 + inner_len <= decrypted_plaintext_length
```

and requires the decrypted plaintext length to be exactly the normal 16-byte
padded size of `36 + inner_len`. Every byte after the inner datagram must be
zero padding.

The explicit length keeps relay framing independent of the inner WireGuard
message's own padding rules.

A nested relay-type (`0xF0`) packet is rejected. Relay forwarding is not composable by the
relay itself.

## 4. Relationships and configuration

Relaying uses two independent WireGuard relationships:

```text
A <-> B   end-to-end tunnel
A <-> R   relay transport
```

A peer may be configured with:

```text
relay(B) = R
```

This changes only how packets for `B` are delivered. It does not replace the
A-B identity or end-to-end session.

`R` must itself be directly reachable from `A`. A peer configured through a
relay cannot also be used as the next relay hop for this protocol.

At forwarding time, `R` must know `B` and have a direct endpoint for it.

## 5. Sending through a relay

For traffic routed to `B`, Microtun first performs normal WireGuard processing
for `B`. The resulting inner datagram may be a handshake initiation, handshake
response, cookie reply, or type-4 transport packet.

If `B` is directly reachable, Microtun sends that datagram normally.

If `relay(B) = R`, Microtun builds the relay plaintext:

```text
B.static_public_key || LE32(len(I)) || I
```

and seals it under the A-R transport session as message type `0xF0`.

If the A-R session is not established, Microtun starts the ordinary WireGuard
handshake with `R` and does not emit the relay packet yet. Handshake-path
messages retain their normal handshake retry timers; an IP-data caller receives
`RelayUnavailable` and may retry after the relay session becomes usable.

## 6. Processing at a relay

A relay processes a relay packet in this order:

```text
classify outer message as type 0xF0
    -> locate A-R session by receiver index
    -> authenticate/decrypt using AD = F0 00 00 00
    -> apply replay/session state
    -> parse destination key and inner WireGuard datagram
    -> authorize A.static_key -> B.static_key
    -> resolve B by static public key
    -> require B to have a direct endpoint
    -> send inner datagram unchanged to B
```

The submitter identity used for authorization is the static peer identity bound
to the authenticated A-R session, never the UDP source address alone.

If the destination is unknown, denied by policy, has no direct endpoint, or is
itself configured through another relay on `R`, the request is dropped.

## 7. Inner-packet validation

The relay cannot authenticate the inner datagram, because its cryptographic
relationship is between `A` and `B`. It does require the inner bytes to be
wire-format-plausible as a standard WireGuard message:

- type 1: standard 148-byte handshake initiation;
- type 2: standard 92-byte handshake response;
- type 3: standard 64-byte cookie reply;
- type 4: at least the standard 32-byte transport overhead and 16-byte aligned;
- reserved type-prefix bytes must be zero;
- relay type `0xF0` and unknown message types are rejected.

This keeps the relay from becoming a generic authenticated UDP forwarder to
configured peer endpoints. Cryptographic validation of `I` still belongs to
`B`.

## 8. Forwarding authorization

After authenticating the outer relay packet and parsing its envelope, the
relay evaluates:

```text
Authorize(source_static_key, destination_static_key)
```

Forwarding is opt-in. A deployment may allow every configured pair, deny all
forwarding, or implement a source/destination policy.

Authorization happens before destination resolution or forwarding.

## 9. Final delivery and endpoint learning

The relay sends the inner WireGuard datagram unchanged to `B`'s direct endpoint.
`B` processes it normally under its end-to-end relationship with `A`.

For a peer configured through a relay, the configured relay remains the
outbound routing authority. Microtun must not learn the relay's UDP address as
the relayed peer's direct endpoint merely because an end-to-end packet arrived
through it.

## 10. Security properties

The extension provides:

- authenticated relay submission through the existing A-R WireGuard session;
- an authenticated `0xF0` selector, preventing type-4/relay-type confusion;
- end-to-end confidentiality and integrity of the inner WireGuard packet;
- routing by destination cryptographic identity rather than a submitted socket;
- explicit source/destination forwarding policy;
- no relay-side re-wrapping, route discovery, hop limits, or forwarding loops.

The relay still learns the submitter identity, destination public key, packet
size and timing, and destination endpoint. It may drop, delay, replay, or
reorder packets subject to normal hop-local and end-to-end WireGuard
protections.

## 11. Wire-size limit

Microtun's maximum outer UDP datagram is 1500 bytes.

Relay type `0xF0` adds the normal 32-byte transport overhead plus a 36-byte relay header.
The inner type-4 WireGuard datagram is 16-byte aligned, so the largest complete
inner datagram that fits after relay-message padding is **1408 bytes**. Subtracting the
inner packet's 32-byte transport overhead leaves a maximum relayed IP plaintext
of **1376 bytes**. The default 1280-byte tunnel MTU therefore fits without
special handling.

## 12. Summary

The complete relay operation is:

```text
I = WG(A -> B, payload)
E = B.static_public_key || LE32(len(I)) || I
O = WG0xF0(A -> R, E, AD = F0 00 00 00)
```

`R` authenticates `A`, parses `E`, authorizes `A -> B`, and sends `I` unchanged
to a directly reachable `B`.

That is the whole extension: one new transport message type, one 36-byte relay
header, and one forwarding policy decision. There is no envelope version, hop
limit, multi-hop re-wrapping, path discovery, or separate relay handshake.
