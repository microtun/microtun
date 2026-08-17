# Microtun Peers API

## Abstract

The Microtun Peers API lets a Microtun node resolve peer records and keep the
records it actually uses up to date. The API is served over the Microtun tunnel
as a WebSocket (RFC 6455) on one persistent connection.

Version 1 has two side-effect-free lookup methods, an explicit keyed watch
method, an idempotent unwatch notification, and two key-only server
invalidations:

```text
peer.by_key      {"public_key": "<44-character base64>"}  -> LookupResult
peer.by_address  {"address": "10.0.0.5"}                  -> LookupResult
peer.watch       {"public_key": "<44-character base64>"}  -> LookupResult
peer.unwatch     {"public_key": "<44-character base64>"}  -> client notification
peer.changed     {"public_key": "<44-character base64>"}  -> server notification
peer.removed     {"public_key": "<44-character base64>"}  -> server notification
```

The server tracks watched peer keys per connection and indexes those watches by
key.
The reference server sends `peer.changed` / `peer.removed` only to
connections watching the changed key. Both notifications contain
only the peer public key.

A retaining client establishes interest with `peer.watch`. For either
invalidation it performs an ordinary `peer.by_key` refresh. That lookup
returns either the complete current record or the explicit `{"not_found":{}}`
result that authoritatively means the registry no longer has a record for that
peer. In particular, `peer.removed` is an invalidation hint rather than
replacement state; confirming it by key makes remove/re-add races converge on
the registry's current state.

`peer.watch` atomically establishes the keyed subscription and samples the
current record, so a registry change cannot slip between the initial
snapshot and subscription. Reconnect recovery replays `peer.watch` for the
peer keys the client still holds.

The wire shapes in this document are normative for `microtun-api`,
`microtun-tracker`, `microtun-std`, and `microtun-embassy`.

## 1. Design goals

The protocol is designed to provide:

- bounded messages suitable for fixed-buffer clients;
- side-effect-free ordinary peer lookup;
- explicit keyed subscriptions for retained peer records;
- lightweight key-only change/removal notifications delivered only to watchers;
- server dispatch work proportional to the number of connections watching the
  changed key rather than all connected clients;
- a single authoritative removal path through `peer.by_key` returning
  `{"not_found":{}}`;
- reconnect recovery using only keys the client already retains;
- a clear distinction between authoritative misses and transient failures;
- authentication inherited from the tunnel connection rather than from
  request fields.

The base protocol does not provide:

- peer records inside notifications;
- separate `added` and `updated` notifications;
- registry revisions, cursors, or replay logs;
- batch lookup operations;
- request-level authentication, TLS, or HTTP semantics;
- address- or prefix-level subscriptions for arbitrary route-topology changes.

### 1.1 Why notifications carry only a key

Both server notifications are invalidations, not replicated state. They mean:

> Whatever state you derived for this key may no longer be current.

`peer.changed` tells the client the server observed an addition or modification;
`peer.removed` tells it the server observed disappearance. Neither carries a
peer object and neither is authoritative replacement state. An interested
client learns the current state through the same by-key lookup path used
initially.

This has three useful properties:

1. a notification cannot install stale peer data because it carries no peer data;
2. remove/re-add and lookup races converge through one current-state lookup;
3. clients that do not care about the named key discard the notification
   without any lookup.

A client pays one additional round trip only for an invalidated peer it
considers relevant.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
express protocol requirements.

- **Caller**: the Microtun peer that opens the API connection.
- **Tracker**: the peer that serves the registry and terminates the
  caller's authenticated tunnel session.
- **Peer record**: a `PeerInfo` object describing one peer.
- **Held peer**: a peer record the client currently retains locally.
- **Watched peer**: a peer key for which the current connection successfully
  completed `peer.watch` and has not subsequently unwatched or disconnected.
- **Peer invalidation**: a `peer.changed` or `peer.removed` notification naming one watched peer key.
- **Authoritative miss**: a successful lookup whose result is exactly
  `{"not_found":{}}`; the requested target is absent from the shared registry.
- **Authoritative removal**: an authoritative miss from a by-key refresh for a
  peer the client still holds.
- **Transient failure**: an error response, a malformed response, a timeout, an
  oversized message, or a transport failure.
- **Connection epoch**: the lifetime of one WebSocket connection, from a
  successful handshake to a close or transport failure.

## 3. Transport

### 3.1 Network path

The client opens a TCP connection to the configured inner tunnel address of the
Tracker on port `80`, and upgrades it to a WebSocket.

The connection MUST travel through the Microtun secure tunnel. The protocol
does not define TLS, bearer tokens, or a request-level identity field. The
authenticated tunnel peer that owns the connection is the caller. This is why
the scheme is `ws://` and not `wss://`: the tunnel already authenticates and
encrypts the path, and a second layer inside it would have to be given its own
trust anchors to be worth anything.

### 3.2 Caller identity and admission

A server MUST serve Peers API operations only to a caller that is present in
the current peer registry.

All admitted callers query the same registry. A configured peer may resolve any
other configured peer by public key or tunnel address; there is no per-caller
visibility filter in version 1.

The reference server binds each accepted connection to the static public key of
the tunnel protocol peer that delivered it. Identity is therefore fixed for the
connection and is never supplied in message parameters.

A server SHOULD refuse an unadmitted caller **at the handshake**, with HTTP
`403`, rather than upgrading and then closing. Refusing before the upgrade is
what makes the refusal legible: a status is a stated reason, where a close
frame on an established session is one more way for a connection to end.

A request that races a mid-connection loss of admission may receive error
`5` (§8). The server MUST NOT report this condition as `{"not_found":{}}`,
because loss of caller admission says nothing about the requested target.

### 3.3 Opening handshake

The client performs the RFC 6455 handshake:

```text
GET /v1/peers HTTP/1.1
Host: microtun
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <16 random bytes, base64>
Sec-WebSocket-Version: 13
```

```text
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <base64(sha1(key ++ GUID))>
```

The URL path is the version negotiation for the whole API. A server MUST serve
the API at `/v1/peers` and MUST refuse an upgrade for any other path.

`Host` carries no meaning here. A client reaches exactly one server — the one
its tunnel route leads to — so the header selects nothing and the reference
server does not read it. The reference client sends the fixed value above
rather than rendering its dialled address into text.

No extension is negotiated. A server MUST NOT accept `permessage-deflate` or
any other extension, and both ends MUST treat a frame with a reserved bit set
as a protocol error: an endpoint that believes an extension is active is
framing the rest of the stream by rules the other end does not implement, so
the fault is the whole connection rather than one frame.

### 3.4 Messages

Each protocol message is one WebSocket **text** frame containing exactly one
compact UTF-8 JSON object. There is no in-band delimiter: the frame is the
message boundary.

A conforming sender SHOULD send each message unfragmented. A receiver MUST
reassemble continuation frames.

Binary frames are not part of this protocol. A receiver MUST refuse one with
close code `1003`.

Ping and pong frames are permitted in both directions and belong to the
transport. A receiver answers a ping with a pong and continues; neither reaches
the protocol above. Either end MAY use them for keepalive in addition to, or
instead of, TCP keep-alive.

Close frames end the connection. Codes this protocol uses:

| Code | Meaning |
| ---: | --- |
| `1000` | Normal closure. |
| `1002` | Protocol error: a malformed frame, a reserved bit, a masking violation, or an unassemblable fragment sequence. |
| `1003` | A binary message. |
| `1008` | Policy violation. The reference server uses this when a caller loses admission on an already-upgraded connection. |
| `1009` | The message exceeded the receiver's buffer (§3.5). |

### 3.5 Message size limits

The supplied implementations use fixed receive buffers:

| Direction | Traffic | Maximum message |
| --- | --- | ---: |
| Client to server | lookup/watch requests and unwatch notifications | 256 bytes |
| Server to client | lookup responses and peer invalidations | 1024 bytes |

A complete message MUST fit in the receiving buffer. A receiver MUST refuse a
larger one with close code `1009` rather than truncating it, and MUST NOT
grow a buffer whose size the sender would then be choosing.

A peer record contains one address prefix, and the 1024-byte record buffer is
sized with ample headroom for the largest valid lookup response. Both peer
invalidations are much smaller but travel in the same direction.

The opening handshake is separately bounded. A server MUST bound the HTTP head
it will read — the reference server accepts 2 KiB, which is comfortable for a
browser's request — and refuse a larger one.

### 3.6 Message envelope

A message is one JSON object in one of four shapes:

```json
{"id":1,"method":"peer.by_key","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
{"id":1,"result":{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","address":"10.0.0.3/32"}}}
{"id":1,"error":{"code":3,"message":"params member is not a valid public key or address"}}
{"method":"peer.changed","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

A message carrying an `id` is a **request** and expects exactly one response
naming that same `id`. A message with no `id` is a **notification** and expects
no reply, in either direction. A response carries exactly one of `result` or
`error`.

Request IDs MUST be JSON integers in `0..=4294967295`. A response MUST echo the
request ID exactly. An error that cannot be attributed to any request — a
message the receiver could not parse at all — MAY be sent with no `id`, and the
peer will have nothing to correlate it with beyond a log line.

The envelope is intentionally minimal because WebSocket already owns framing and
the versioned URL path owns version negotiation. Batches are not supported. An
absent or explicit null `id` means no reply is expected. Error codes
are the small positive application codes defined in §8.

A receiver MUST treat a message it cannot parse as ending the conversation.
There is no resynchronization point: a peer that is not producing this envelope
is a peer whose *next* message cannot be assumed to be one either.

### 3.7 Version namespace

The API version appears once, in the path `/v1/peers`. Method names carry no
version prefix.

This is a change from the previous revision, where every method name began
`v1.`. Versioning at the handshake path fails a mismatched client at connection
time, with one check, rather than failing every call it makes on a connection
that should never have opened.

Clients conforming to this document MUST send only the methods defined here and
MUST ignore unsupported server notification methods. Unknown request methods
receive error `2` (§8).

## 4. Common data types

### 4.1 PublicKey

A public key is a JSON string containing a 32-byte static public key:

- standard base64 alphabet;
- exactly 44 characters;
- required trailing `=` padding;
- decodes to exactly 32 bytes;
- canonical final unused bits.

Example:

```text
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=
```

URL-safe and unpadded variants are not equivalent spellings.

### 4.2 IpAddress

An address query is a JSON string containing one IPv4 or IPv6 address. It MUST
NOT contain a CIDR prefix length or port.

IPv4-mapped IPv6 addresses are normalized to native IPv4 before route lookup.

### 4.3 Endpoint

An endpoint is an IP address and UDP port:

```text
203.0.113.5:51820
[2001:db8::5]:51820
```

Hostnames are not part of the wire schema. IPv6 endpoints use brackets.

### 4.4 Cidr

A tunnel prefix is an IPv4 or IPv6 CIDR such as `10.1.2.0/24` or
`2001:db8:1::/64`.

A conforming sender includes the prefix length, including on host prefixes.
Each peer record contains exactly one prefix.

### 4.5 PeerInfo

`PeerInfo` is the complete peer-record wire type returned by a successful
lookup.

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
  "endpoint": "203.0.113.5:51820",
  "relay": "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=",
  "address": "10.1.2.0/24",
  "persistent_keepalive": 25
}
```

| Field | Type | Required | Meaning |
| --- | --- | :---: | --- |
| `public_key` | `PublicKey` | yes | Static public key of the described peer. |
| `endpoint` | `Endpoint` | no | Current directly reachable outer UDP endpoint. |
| `relay` | `PublicKey` | no | Static key of the relay through which this peer is reached. |
| `address` | `Cidr` | yes | The tunnel prefix owned by the peer. |
| `persistent_keepalive` | integer `0..65535` | no | Keepalive interval in seconds. `0` and omission disable it. |

The reference server may replace a configured endpoint with the most recently
observed authenticated direct endpoint. This is runtime state projected into
the same `PeerInfo` shape.

Clients MUST apply their local installation policy after decoding a record. The
wire schema alone does not grant a peer permission to impersonate pinned peers,
claim a default route, relay through the local node, or otherwise violate local
routing policy.

### 4.6 LookupResult

Every successful lookup response includes a `result` member containing
exactly one externally tagged variant.

Found:

```json
{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","address":"10.0.0.3/32"}}
```

Not found:

```json
{"not_found":{}}
```

No other variants are defined. JSON `null`, a missing `result`, an unknown
variant, or a malformed `found` payload is not an authoritative miss and MUST
be treated as a transient failure.

## 5. Lookup result semantics

Both lookup methods and `peer.watch` return `LookupResult`.

| Response | Meaning | Required client behavior |
| --- | --- | --- |
| `{"found": <PeerInfo>}` | Peer found | Validate the record for the request and, if accepted, treat it as the complete current record. |
| exactly `{"not_found":{}}` | Authoritative miss | Treat the requested target as absent. On a by-key refresh for a held peer, this is authoritative removal. |
| An error response, a malformed response, a timeout, an oversized message, or connection loss | Transient failure | Do not convert to not-found. Retain already installed state and retry through normal resolver flow. |

Only the explicit `not_found` variant is authoritative. A condition about the
caller, request syntax, server load, or transport is not evidence that the
requested target does not exist.

## 6. Methods

### 6.1 `peer.by_key`

**Direction:** client request -> server response.

Params:

```json
{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}
```

Result: `LookupResult`.

Behavior:

1. Decode the public key.
2. Look up exactly that key in the current published registry.
3. Return `{"found": <PeerInfo>}` when present.
4. Return `{"not_found":{}}` when the key is valid but absent.
5. Return invalid-params for an undecodable key.

A positive response MUST name the key that was requested.

### 6.2 `peer.by_address`

**Direction:** client request -> server response.

Params:

```json
{"address":"10.0.0.5"}
```

Result: `LookupResult`.

Behavior:

1. Parse the address.
2. Perform longest-prefix match over the published peer prefixes.
3. Return the owning peer as `{"found": <PeerInfo>}`.
4. Return `{"not_found":{}}` when no peer owns the address.
5. Return invalid-params for an undecodable address.

A client accepting the positive response MUST verify that the returned record
actually contains the queried address.

### 6.3 `peer.watch`

**Direction:** client request -> server response.

Params are identical to `peer.by_key`. Result: `LookupResult`.

For a valid peer key, the server MUST establish interest in that key
and sample the corresponding `LookupResult` as one atomic registry operation. A
peer transition therefore cannot occur between the returned snapshot and watch
registration without also producing a later invalidation for this connection.

If the key is absent, the server returns `{"not_found":{}}` and MUST
NOT establish a watch. An undecodable key is invalid params.

Calling `peer.watch` again for an already-watched key is idempotent and
returns a fresh current snapshot.

### 6.4 `peer.unwatch`

**Direction:** client notification -> server.

Params are identical to `peer.by_key`. There is no response.

The server removes the key from this connection's interest set. Unwatching a
key that is not currently watched is idempotent. Closing the connection removes
all of its watches. A notification already being written may still arrive after
`unwatch`; a client that no longer holds the key ignores that late hint.

### 6.5 `peer.changed`

**Direction:** server notification -> client.

Params:

```json
{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}
```

The reference server emits this notification to connections watching the named
key when that peer is added or when its effective published record changes,
including configuration changes to its endpoint, relay, address, or
keepalive and authenticated endpoint changes.

### 6.6 `peer.removed`

**Direction:** server notification -> client.

Params are identical to `peer.changed`.

The reference server emits this notification to connections watching the named
key when the peer disappears from the published registry.

`peer.removed` is deliberately still an invalidation rather than authoritative
replacement state. A remove may race a re-add or an in-flight lookup response;
a current `peer.by_key` lookup is the single source of truth.

### 6.7 Common notification handling

Both notifications carry only `public_key`; neither carries a result, peer
record, revision, or replacement state. A connection receives invalidations
only for keys it has successfully watched.

For either notification the client:

1. decodes the key;
2. coalesces duplicate pending invalidations for the key when useful;
3. re-looks up the key with `peer.by_key`;
4. applies a valid `found` response as a complete replacement;
5. treats an explicit `not_found` response as authoritative removal;
6. treats every other failure as transient and retains the current record.

## 7. Keyed subscription and reconciliation lifecycle

### 7.1 Server-side keyed interest

Each API connection has an explicit set of watched peer keys. The reference
server additionally maintains a reverse index from peer key to the connections
watching it. A peer transition therefore wakes and queues work only for actual
watchers of that key rather than every admitted API connection.

The reference server coalesces multiple pending invalidations for the same key
per connection. A later transition replaces an earlier queued kind; the
notification remains only a hint, so the subsequent `peer.by_key` refresh
still determines the authoritative current state.

### 7.2 Atomic watch and snapshot

`peer.watch(K)` establishes interest and samples the current record under the
same registry critical section. This closes the usual lookup-then-subscribe
race:

```text
lookup K
                    K changes
subscribe K
```

A successful watch instead guarantees either that its returned snapshot already
reflects the transition or that a subsequent invalidation for `K` is queued.

For address resolution, the client first performs side-effect-free
`peer.by_address(A)`. If that returns peer `K`, the client then calls
`peer.watch(K)` and treats the watch response, not the earlier address lookup,
as the authoritative record it installs.

Repeated invalidations for one key SHOULD be coalesced.

### 7.3 Local peer eviction

When the core drops a dynamic peer, the resolver removes that key from its local
held set, drops pending invalidations for it, and sends `peer.unwatch(K)` on
the current connection. The notification is idempotent.

A later lookup may cause the client to watch and hold the key again.

### 7.4 Reconnection

Watches are scoped to one connection and are not replayed by the server. After
a connection is lost, the client re-establishes every dynamic peer key it still
holds with `peer.watch`.

For each retained key `K`:

```text
call peer.watch(K)
found      -> validate and replace local record
not_found  -> authoritatively remove local record
failure    -> keep old record and retry through normal reconnect flow
```

This recovers changes missed because of transport failure or server restart.

Removing the caller's own registry record closes all of that caller's
subscriptions. Reconnect and re-watch then re-establish admission and retained
watches.

### 7.5 Bounded keyed queues

The reference server keeps one coalescing pending-invalidations map per
connection. Repeated changes to a hot watched key occupy one pending entry
rather than growing a FIFO with duplicate hints. Work for a peer transition is
indexed by that peer key and is not broadcast to unrelated connections.

Allocation-free clients may still have bounded local notification queues. If a
local queue overflows, the reference client reconnects and re-watches its held
keys instead of guessing which invalidations were lost.

### 7.6 Address-resolution consequence

Keyed peer watches intentionally do not subscribe to arbitrary address or route
topology changes. A newly added or changed *unheld* peer can therefore alter
longest-prefix routing for an address without invalidating a peer the client
already watches.

For example, a client may hold a peer owning `10.0.0.0/24`; later an unrelated
peer may acquire `10.0.0.5/32`. The client does not watch that unrelated key and
therefore does not immediately discover the new more-specific route.

Deployments that require immediate reaction to arbitrary route-topology changes
need an address/prefix subscription or a future coarse registry-change
mechanism. That is outside the minimal v1 resolver behavior.

## 8. Errors

An error response carries a small positive integer code and a human-readable
message. The message is advisory and never machine-parsed.

| Code | Name | Typical cause |
| ---: | --- | --- |
| `1` | Bad message | A message that is not a well-formed Peers API envelope. |
| `2` | Unknown method | A request method this version does not define — including a `v1.`-prefixed name from the previous revision. |
| `3` | Invalid params | Missing params, wrong JSON shape, undecodable key, or undecodable address. |
| `4` | Internal | Serialization or another internal response failure. |
| `5` | Not admitted | The caller's own key has no registry record. |
| `6` | Rate limited | The caller exceeded its request budget. |

The set is deliberately small: what a caller can *do* differs across only three
of these — fix the request, wait, or give up — and a code no caller branches on
exists to be logged, which the message already covers.

Codes `1` and `4` describe the message or the responder; `2` and `3` describe
the request; `5` and `6` describe the caller. **None of them describes the
target**, which is why none may be substituted for `{"not_found":{}}` and why
all of them are transient in the client's classification.

Faults in the transport itself — a malformed frame, a message over the size
limit, a binary message — are not error responses. They are WebSocket close
codes (§3.4), because a stream whose framing is in doubt has no reliable place
to put a reply.

Examples that are invalid params, not misses:

```json
{"public_key":123}
{"public_key":"not-a-key"}
{"address":"not-an-ip"}
```

Unknown notifications receive no response. Clients ignore notification methods
other than `peer.changed` and `peer.removed`.

## 9. Conformance rules

- A client MUST connect to `/v1/peers`, and a server MUST refuse a WebSocket
  upgrade for any other path.
- Neither end may negotiate a WebSocket extension, and both MUST treat a
  reserved frame bit as a protocol error.
- Every protocol message MUST be one complete JSON object in one text message.
- A receiver MUST refuse a message larger than its buffer with close code
  `1009` rather than truncating it.
- A server SHOULD refuse an unadmitted caller with HTTP `403` at the
  handshake, before upgrading.
- Clients and servers MUST use the exact method names defined in this
  document, without a version prefix.
- `peer.by_key` and `peer.by_address` MUST be side-effect free.
- A successful `peer.watch` MUST atomically establish per-connection interest
  in the key and return a current `LookupResult`.
- `peer.watch` returning `not_found` MUST leave that key unwatched.
- `peer.unwatch` MUST be an idempotent client notification.
- The server MUST deliver peer invalidations only to connections currently
  watching the named key.
- `peer.changed` and `peer.removed` MUST carry only `public_key`.
- `peer.changed` identifies an observed add/modify transition;
  `peer.removed` identifies an observed removal transition. Clients MUST
  still confirm either notification with `peer.by_key` before replacing
  held peer state.
- The explicit `{"not_found":{}}` `LookupResult` is the authoritative removal
  result applied by the reference clients.
- Missing, null, unknown, or malformed results MUST be treated as transient
  failures, never as authoritative misses.
- A `found` result MUST carry one complete `PeerInfo` record.
- A client MUST validate lookup results before installing them.
- A client MUST tolerate either peer invalidation racing an in-flight refresh.
- A client SHOULD coalesce repeated pending invalidations for one key.
- A reconnecting client MUST re-watch the peer keys it still holds.
- A server MAY coalesce multiple pending invalidations for the same watched key.
- Senders MUST omit optional object fields rather than sending JSON `null`.
- Clients MUST treat accepted peer records as complete replacements.
- Clients MUST NOT add request-level identity claims that override the
  authenticated tunnel identity.
- Servers MUST NOT answer loss of caller admission with `{"not_found":{}}`.
- Servers MUST answer undecodable lookup arguments with error `3`, not
  `{"not_found":{}}`.
- Receivers MUST treat an unparseable message as ending the conversation
  rather than skipping it.

## 10. Security and resource bounds

### 10.1 Trust boundary

The tunnel authenticates the connection, but a syntactically valid `PeerInfo`
is still remote input. Clients MUST apply local resolver and routing policy
before installing it.

The Tracker is a routing authority for dynamic peers. Compromise of it
can redirect permitted dynamic address space subject to the client's local
validation rules.

A peer invalidation cannot install anything directly because it contains only
a key. It can only cause a client to re-query through the normal validated
lookup path.

### 10.2 Enumeration behavior

The API intentionally returns the same `{"not_found":{}}` result for:

- a valid but unknown peer key;
- a valid address no configured prefix contains.

An undecodable key or address receives invalid-params instead. Loss of caller
admission and rate limiting are also distinct transient errors because neither
says anything about whether the target exists.

### 10.3 Keyed dispatch cost

Explicit watches trade bounded server subscription state for substantially less
fan-out. For each effective peer transition, the reference server indexes the
changed key and queues one small key-only invalidation only for connections
actually watching that key. Unrelated API connections are not woken for the
transition.

The expensive operation remains the client refresh. A client performs at most
one coalesced `peer.by_key` per invalidated watched key, plus re-watch
reconciliation when necessary.

Servers SHOULD bound concurrent connections per authenticated peer and
rate-limit lookup/watch requests. Rate-limit rejection MUST be error `6`, not
an authoritative miss.

Clients SHOULD jitter reconnect attempts and SHOULD offset the first refresh of
a synchronized change burst so a fleet does not re-query in lockstep. The
reference clients use their existing jitter logic for both cases.

## 11. Reference client flow

```text
held_keys = set()
pending_changes = coalescing queue

connect to <tracker-inner-address>:80 through the tunnel
upgrade: GET /v1/peers

on resolve by_key(K):
    call peer.watch(K)
    if found(peer) and peer passes local validation:
        install peer
        held_keys.add(K)

on resolve by_address(A):
    call peer.by_address(A)
    if found(peer K):
        call peer.watch(K)
        install the watch response if valid
        held_keys.add(K)

on peer.changed(K) or peer.removed(K):
    queue/coalesce K

while processing pending changes:
    call peer.by_key(K)
    if found(peer) and peer passes validation:
        replace local record for K
    if not_found:
        remove local record for K
        held_keys.remove(K)
    if transient failure:
        retain current local record
        reconnect/retry according to resolver policy

on local peer eviction K:
    held_keys.remove(K)
    discard queued K
    send peer.unwatch(K)

on connection loss or local notification-queue overflow:
    reconnect with jitter
    for each K in held_keys:
        call peer.watch(K)
        apply found/not_found as above
```

The central v1 invariant is intentionally small:

> The client explicitly watches the peer keys it retains; the server dispatches
> key-only invalidations only to those watchers, and lookup remains the only
> source of authoritative peer state.

## 12. A browser client

Nothing in this document is written for browsers specifically, and no part of
the protocol bends toward them. They are simply the clients a WebSocket lets in
that a byte-stream protocol did not, so it is worth writing down what a
conforming one looks like — and, first, what it still needs from its
surroundings.

### 12.1 What a page still needs

The trust model in §3.1 is unchanged: the connection carries no authentication
of its own and gets all of it from the tunnel. A page therefore has to be
running somewhere whose network stack is already inside the tunnel — a browser
on a node that runs Microtun, an embedded webview on a device that does. A page
loaded from the public internet cannot reach a Tracker, and if some
deployment arranges for it to, that deployment has thrown away the property
that makes it safe to install a peer record at all.

The API is `ws://`, so the page must be served over `http://` as well: current
browsers refuse an insecure WebSocket from a secure origin.

### 12.2 A conforming client

```js
const ws = new WebSocket("ws://10.0.0.9/v1/peers");

let nextId = 1;
const pending = new Map();

function call(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);

  // A notification: an invalidation, or a method this client does not know.
  if (message.id === undefined) {
    if (message.method === "peer.changed" || message.method === "peer.removed") {
      invalidate(message.params.public_key);
    }
    return;
  }

  const waiter = pending.get(message.id);
  if (!waiter) return;              // A response to a call we gave up on.
  pending.delete(message.id);
  if (message.error) waiter.reject(message.error);
  else waiter.resolve(message.result);
};

// `result` is `{found: {...}}` or `{not_found: {}}` — and only the second
// authoritatively means the peer is gone (§5).
const result = await call("peer.watch", { public_key: key });
```

Three things a client written this way still has to get right, none of which
the transport does for it:

1. **Only `{"not_found":{}}` is a removal.** A rejected promise, a closed
   socket, and a result of any other shape are transient (§5). Treating them as
   removal is the one failure mode this protocol is most carefully built to
   prevent.
2. **An invalidation is a hint.** `invalidate` must re-look up the key with
   `peer.by_key` and apply *that* result. The notification carries no record
   and may race a re-add (§6.7).
3. **Reconnect must re-watch.** Watches live on the connection (§7.4). A
   browser that reconnects on `onclose` and does not replay `peer.watch` for
   the keys it still holds will keep serving state that has stopped being
   updated, silently.

A page that only ever performs one-shot lookups and holds nothing needs none of
this: it can call `peer.by_key` or `peer.by_address` and forget the answer.
Everything above is the price of retaining a record.
