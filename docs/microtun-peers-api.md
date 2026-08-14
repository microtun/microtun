# Microtun Peers API

## Abstract

The Microtun Peers API lets a Microtun node resolve peer records and keep the
records it actually uses up to date. The API is served over the Microtun tunnel
using JSON-RPC 2.0 on one persistent, newline-delimited TCP stream.

Version 1 has two side-effect-free lookup methods, an explicit keyed watch
method, an idempotent unwatch notification, and two key-only server
invalidations:

```text
v1.peer.by_key      {"public_key": "<44-character base64>"}  -> LookupResult
v1.peer.by_address  {"address": "10.0.0.5"}                  -> LookupResult
v1.peer.watch       {"public_key": "<44-character base64>"}  -> LookupResult
v1.peer.unwatch     {"public_key": "<44-character base64>"}  -> client notification
v1.peer.changed     {"public_key": "<44-character base64>"}  -> server notification
v1.peer.removed     {"public_key": "<44-character base64>"}  -> server notification
```

The server tracks watched peer keys per connection and indexes those watches by
key. It applies the caller-specific group-link policy when establishing a watch.
The reference server sends `v1.peer.changed` / `v1.peer.removed` only to
connections currently watching the changed key. Both notifications contain
only the peer public key.

A retaining client establishes interest with `v1.peer.watch`. For either
invalidation it performs an ordinary `v1.peer.by_key` refresh. That lookup
returns either the complete current record or the explicit `{"not_found":{}}`
result that authoritatively means the caller no longer has a visible record for
that peer. In particular, `peer.removed` is an invalidation hint rather than
replacement state; confirming it by key makes remove/re-add races converge on
the registry's current state.

`v1.peer.watch` atomically establishes the keyed subscription and samples the
current visible record, so a registry change cannot slip between the initial
snapshot and subscription. Reconnect recovery replays `v1.peer.watch` for the
peer keys the client still holds.

The wire shapes in this document are normative for `microtun-api`,
`microtun-apiserver`, `microtun-std`, and `microtun-embassy`.

## 1. Design goals

The protocol is designed to provide:

- bounded messages suitable for fixed-buffer clients;
- side-effect-free ordinary peer lookup;
- explicit keyed subscriptions for retained peer records;
- lightweight key-only change/removal notifications delivered only to watchers;
- server dispatch work proportional to the number of connections watching the
  changed key rather than all connected clients;
- a single authoritative removal path through `v1.peer.by_key` returning
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
- **Peers API server**: the peer that serves the registry and terminates the
  caller's authenticated tunnel session.
- **Peer record**: a `PeerInfo` object describing one peer.
- **Held peer**: a peer record the client currently retains locally.
- **Watched peer**: a peer key for which the current connection successfully
  completed `v1.peer.watch` and has not subsequently unwatched or disconnected.
- **Peer invalidation**: a `v1.peer.changed` or `v1.peer.removed` notification naming one watched peer key.
- **Authoritative miss**: a successful lookup whose result is exactly
  `{"not_found":{}}`; the requested target is absent from the caller's visible
  registry, whether because it is unconfigured or hidden by policy.
- **Authoritative removal**: an authoritative miss from a by-key refresh for a
  peer the client still holds.
- **Transient failure**: a JSON-RPC error, malformed response, timeout,
  oversized frame, or transport failure.
- **Connection epoch**: the lifetime of one TCP connection.

## 3. Transport and framing

### 3.1 Network path

The client connects to the configured inner tunnel address of the Peers API
server on TCP port `80`.

The connection MUST travel through the Microtun/WireGuard tunnel. The protocol
does not define TLS, HTTP, bearer tokens, or a request-level identity field.
The authenticated tunnel peer that owns the TCP connection is the caller.

### 3.2 Caller identity and admission

A server MUST serve Peers API operations only to a caller that is present in
the current peer registry.

The reference server binds each accepted API connection to the static public
key of the WireGuard peer that delivered it. Identity is therefore fixed for
the connection and is never supplied in JSON-RPC params.

If the caller is not admitted, the server SHOULD refuse or close the connection.
A request that races a mid-connection loss of admission may receive error
`-32001`. The server MUST NOT report this condition as `{"not_found":{}}`,
because loss of caller admission says nothing about the requested target.

### 3.3 Stream framing

Each message is one UTF-8 JSON object followed by a newline byte (`\n`). Both
directions share one full-duplex TCP connection.

```text
<JSON object>\n
<JSON object>\n
...
```

Receivers trim surrounding ASCII whitespace, including the `\r` in CRLF.
Senders SHOULD emit one compact JSON object followed by `\n`.

Batch requests are not supported. A JSON array is malformed traffic.

### 3.4 Frame limits

The supplied implementations use fixed receive buffers:

| Direction | Traffic | Maximum frame buffer |
| --- | --- | ---: |
| Client to server | lookup/watch requests and unwatch notifications | 256 bytes |
| Server to client | lookup responses and peer invalidations | 1024 bytes |

A complete newline-terminated frame MUST fit in the receiving buffer. An
oversized incoming frame is a transient connection failure.

A peer record contains at most four address prefixes, and the 1024-byte record
buffer is sized for the largest valid lookup response. Both peer invalidations
are much smaller but travel in the same direction.

### 3.5 JSON-RPC envelope

Messages use JSON-RPC version `2.0`.

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"v1.peer.by_key","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

Positive response:

```json
{"jsonrpc":"2.0","id":1,"result":{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","addresses":["10.0.0.3/32"]}}}
```

Authoritative miss:

```json
{"jsonrpc":"2.0","id":1,"result":{"not_found":{}}}
```

Peer invalidation examples:

```json
{"jsonrpc":"2.0","method":"v1.peer.changed","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
{"jsonrpc":"2.0","method":"v1.peer.removed","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

Request IDs MUST be JSON integers representable as signed 64-bit values. A
response MUST echo the request ID exactly. Notifications MUST omit `id` and do
not receive responses.

### 3.6 Version namespace

Every Peers API method begins with the API-version prefix `v1.`. The prefix
versions the Peers API contract, not JSON-RPC itself; `"jsonrpc":"2.0"` remains
unchanged.

Clients conforming to this document MUST send only the v1 methods defined here
and MUST ignore unsupported server notification methods. Unknown request
methods receive JSON-RPC method-not-found.

## 4. Common data types

### 4.1 PublicKey

A public key is a JSON string containing the canonical WireGuard spelling of a
32-byte static public key:

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

A conforming sender includes the prefix length, including on host prefixes. A
peer record contains at most four prefixes.

### 4.5 PeerInfo

`PeerInfo` is the complete peer-record wire type returned by a successful
lookup.

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
  "endpoint": "203.0.113.5:51820",
  "relay": "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=",
  "addresses": ["10.1.2.0/24", "2001:db8:1::/64"],
  "persistent_keepalive": 25
}
```

| Field | Type | Required | Meaning |
| --- | --- | :---: | --- |
| `public_key` | `PublicKey` | yes | Static public key of the described peer. |
| `endpoint` | `Endpoint` | no | Current directly reachable outer UDP endpoint. |
| `relay` | `PublicKey` | no | Static key of the relay through which this peer is reached. |
| `addresses` | array of `Cidr` | yes | Tunnel prefixes owned by the peer; maximum four. |
| `persistent_keepalive` | integer `0..65535` | no | Keepalive interval in seconds. `0` and omission disable it. |

The reference server may replace a configured endpoint with the most recently
observed authenticated direct endpoint. This is runtime state projected into
the same `PeerInfo` shape.

Clients MUST apply their local installation policy after decoding a record. The
wire schema alone does not grant a peer permission to impersonate pinned peers,
claim a default route, relay through the local node, or otherwise violate local
routing policy.

### 4.6 LookupResult

Every successful lookup response includes a JSON-RPC `result` member containing
exactly one externally tagged variant.

Found:

```json
{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","addresses":["10.0.0.3/32"]}}
```

Not found:

```json
{"not_found":{}}
```

No other variants are defined. JSON `null`, a missing `result`, an unknown
variant, or a malformed `found` payload is not an authoritative miss and MUST
be treated as a transient failure.

## 5. Lookup result semantics

Both lookup methods and `v1.peer.watch` return `LookupResult`.

| Response | Meaning | Required client behavior |
| --- | --- | --- |
| `{"found": <PeerInfo>}` | Peer found | Validate the record for the request and, if accepted, treat it as the complete current record. |
| exactly `{"not_found":{}}` | Authoritative miss | Treat the requested target as absent. On a by-key refresh for a held peer, this is authoritative removal. |
| JSON-RPC error, malformed response, timeout, overflow, or connection loss | Transient failure | Do not convert to not-found. Retain already installed state and retry through normal resolver flow. |

Only the explicit `not_found` variant is authoritative. A condition about the
caller, request syntax, server load, or transport is not evidence that the
requested target does not exist.

## 6. Methods

### 6.1 `v1.peer.by_key`

**Direction:** client request -> server response.

Params:

```json
{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}
```

Result: `LookupResult`.

Behavior:

1. Decode the public key.
2. Look up exactly that key in the current published registry and apply the
   caller's group-link policy.
3. Return `{"found": <PeerInfo>}` when present and visible.
4. Return `{"not_found":{}}` when the key is valid but absent or hidden.
5. Return invalid-params for an undecodable key.

A positive response MUST name the key that was requested.

### 6.2 `v1.peer.by_address`

**Direction:** client request -> server response.

Params:

```json
{"address":"10.0.0.5"}
```

Result: `LookupResult`.

Behavior:

1. Parse the address.
2. Perform longest-prefix match over the published peer prefixes.
3. Apply the caller's group-link policy and return the owning peer as
   `{"found": <PeerInfo>}` only when it is visible.
4. Return `{"not_found":{}}` when no visible peer owns the address.
5. Return invalid-params for an undecodable address.

A client accepting the positive response MUST verify that the returned record
actually contains the queried address.

### 6.3 `v1.peer.watch`

**Direction:** client request -> server response.

Params are identical to `v1.peer.by_key`. Result: `LookupResult`.

For a valid, visible peer key, the server MUST establish interest in that key
and sample the corresponding `LookupResult` as one atomic registry operation. A
peer transition therefore cannot occur between the returned snapshot and watch
registration without also producing a later invalidation for this connection.

If the key is absent or hidden, the server returns `{"not_found":{}}` and MUST
NOT establish a watch. An undecodable key is invalid params.

Calling `v1.peer.watch` again for an already-watched key is idempotent and
returns a fresh current snapshot.

### 6.4 `v1.peer.unwatch`

**Direction:** client notification -> server.

Params are identical to `v1.peer.by_key`. There is no response.

The server removes the key from this connection's interest set. Unwatching a
key that is not currently watched is idempotent. Closing the connection removes
all of its watches. A notification already being written may still arrive after
`unwatch`; a client that no longer holds the key ignores that late hint.

### 6.5 `v1.peer.changed`

**Direction:** server notification -> client.

Params:

```json
{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}
```

The reference server emits this notification to connections watching the named
key when that peer is added or when its effective published record changes,
including configuration changes to its endpoint, relay, addresses, or
keepalive and authenticated endpoint changes.

### 6.6 `v1.peer.removed`

**Direction:** server notification -> client.

Params are identical to `v1.peer.changed`.

The reference server emits this notification to connections watching the named
key when the peer disappears from the published registry.

`peer.removed` is deliberately still an invalidation rather than authoritative
replacement state. A remove may race a re-add or an in-flight lookup response;
a current `v1.peer.by_key` lookup is the single source of truth.

### 6.7 Common notification handling

Both notifications carry only `public_key`; neither carries a result, peer
record, revision, or replacement state. A connection receives invalidations
only for keys it has successfully watched.

For either notification the client:

1. decodes the key;
2. coalesces duplicate pending invalidations for the key when useful;
3. re-looks up the key with `v1.peer.by_key`;
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
notification remains only a hint, so the subsequent `v1.peer.by_key` refresh
still determines the authoritative current state.

### 7.2 Atomic watch and snapshot

`v1.peer.watch(K)` establishes interest and samples the current record under the
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
`v1.peer.by_address(A)`. If that returns peer `K`, the client then calls
`v1.peer.watch(K)` and treats the watch response, not the earlier address lookup,
as the authoritative record it installs.

Repeated invalidations for one key SHOULD be coalesced.

### 7.3 Local peer eviction

When the core drops a dynamic peer, the resolver removes that key from its local
held set, drops pending invalidations for it, and sends `v1.peer.unwatch(K)` on
the current connection. The notification is idempotent.

A later lookup may cause the client to watch and hold the key again.

### 7.4 Reconnection

Watches are scoped to one connection and are not replayed by the server. After
a connection is lost, the client re-establishes every dynamic peer key it still
holds with `v1.peer.watch`.

For each retained key `K`:

```text
call v1.peer.watch(K)
found      -> validate and replace local record
not_found  -> authoritatively remove local record
failure    -> keep old record and retry through normal reconnect flow
```

This recovers changes missed because of transport failure or server restart.

The reference server closes keyed subscriptions when the group-link policy
changes. Reconnect and re-watch then reconcile records that became hidden
without requiring the server to enumerate newly-hidden keys. Removing the
caller's own registry record also closes all of that caller's subscriptions.

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

The protocol uses standard JSON-RPC errors plus two application errors.

| Code | Name | Typical cause |
| ---: | --- | --- |
| `-32700` | Parse error | Malformed JSON or unsupported batch input. |
| `-32600` | Invalid Request | Invalid JSON-RPC message envelope. |
| `-32601` | Method not found | Unknown, unprefixed, or unsupported-version request method. |
| `-32602` | Invalid params | Missing params, wrong JSON shape, undecodable key, or undecodable address. |
| `-32603` | Internal error | Serialization or another internal response failure. |
| `-32001` | Not admitted | The caller's own key has no registry record. |
| `-32002` | Rate limited | The caller exceeded its request budget. |

Examples that are invalid params, not misses:

```json
{"public_key":123}
{"public_key":"not-a-key"}
{"address":"not-an-ip"}
```

Unknown notifications receive no response. Clients ignore notification methods
other than `v1.peer.changed` and `v1.peer.removed`.

## 9. Conformance rules

- Clients and servers MUST use the exact v1 method names defined in this
  document.
- `v1.peer.by_key` and `v1.peer.by_address` MUST be side-effect free.
- A successful `v1.peer.watch` MUST atomically establish per-connection interest
  in the visible key and return a current `LookupResult`.
- `v1.peer.watch` returning `not_found` MUST leave that key unwatched.
- `v1.peer.unwatch` MUST be an idempotent client notification.
- The server MUST deliver peer invalidations only to connections currently
  watching the named key.
- `v1.peer.changed` and `v1.peer.removed` MUST carry only `public_key`.
- `v1.peer.changed` identifies an observed add/modify transition;
  `v1.peer.removed` identifies an observed removal transition. Clients MUST
  still confirm either notification with `v1.peer.by_key` before replacing
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
- Servers MUST answer undecodable lookup arguments with `-32602`, not
  `{"not_found":{}}`.

## 10. Security and resource bounds

### 10.1 Trust boundary

The tunnel authenticates the connection, but a syntactically valid `PeerInfo`
is still remote input. Clients MUST apply local resolver and routing policy
before installing it.

The Peers API server is a routing authority for dynamic peers. Compromise of it
can redirect permitted dynamic address space subject to the client's local
validation rules.

A peer invalidation cannot install anything directly because it contains only
a key. It can only cause a client to re-query through the normal validated
lookup path.

### 10.2 Enumeration behavior

The API intentionally returns the same `{"not_found":{}}` result for:

- a valid but unknown peer key;
- a valid address no configured prefix contains;
- a configured peer hidden from the authenticated caller;
- a valid address whose owning peer is hidden from the caller.

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
one coalesced `v1.peer.by_key` per invalidated watched key, plus re-watch
reconciliation when necessary.

Servers SHOULD bound concurrent connections per authenticated peer and
rate-limit lookup/watch requests. Rate-limit rejection MUST be a JSON-RPC
error, not an authoritative miss.

Clients SHOULD jitter reconnect attempts and SHOULD offset the first refresh of
a synchronized change burst so a fleet does not re-query in lockstep. The
reference clients use their existing jitter logic for both cases.

## 11. Reference client flow

```text
held_keys = set()
pending_changes = coalescing queue

connect to <peers-api-server-inner-address>:80 through the tunnel

on resolve by_key(K):
    call v1.peer.watch(K)
    if found(peer) and peer passes local validation:
        install peer
        held_keys.add(K)

on resolve by_address(A):
    call v1.peer.by_address(A)
    if found(peer K):
        call v1.peer.watch(K)
        install the watch response if valid
        held_keys.add(K)

on v1.peer.changed(K) or v1.peer.removed(K):
    queue/coalesce K

while processing pending changes:
    call v1.peer.by_key(K)
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
    send v1.peer.unwatch(K)

on connection loss or local notification-queue overflow:
    reconnect with jitter
    for each K in held_keys:
        call v1.peer.watch(K)
        apply found/not_found as above
```

The central v1 invariant is intentionally small:

> The client explicitly watches the peer keys it retains; the server dispatches
> key-only invalidations only to those watchers, and lookup remains the only
> source of authoritative peer state.
