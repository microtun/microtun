# Microtun Peers API

## Abstract

The Microtun Peers API lets a Microtun node resolve peer records and keep the
records it installs up to date. The Peers API server serves it over the Microtun
Tunnel itself using JSON-RPC 2.0 on a persistent, newline-delimited TCP stream.

The protocol has two side-effect-free lookup methods, one explicit watch
request, one explicit unwatch notification, and one server notification:

```text
v1.peer.by_key      {"public_key": "<44-character base64>"}  -> LookupResult
v1.peer.by_address  {"address": "10.0.0.5"}                  -> LookupResult
v1.peer.watch       {"public_key": "<44-character base64>"}  -> LookupResult
v1.peer.unwatch     {"public_key": "<44-character base64>"}  -> client notification
v1.peer.changed     {"public_key": "<44-character base64>"}  -> server notification
```

Lookups do not mutate watch state. A client that wants to retain a peer record
calls `v1.peer.watch` for that peer's public key. `v1.peer.watch` adds the key to the
connection watch set and samples its current by-key state in one atomic server
operation, returning the same `LookupResult` shape as `v1.peer.by_key`. This makes
the subscription explicit without opening a race between the state a client
installs and the watch that is supposed to keep it current.

When a watched peer changes or disappears, the server sends `v1.peer.changed` naming
only the key. The notification carries no record and no removal flag; it means
*whatever you hold for this key may no longer be current*. The client answers
it with an ordinary side-effect-free `v1.peer.by_key`. A reconnecting client
reissues `v1.peer.watch` for every record it still holds so the new connection
recreates the subscriptions and reconciles current state in the same round trip.

`v1.peer.unwatch` removes explicit watch state when the client drops a record. It is
best-effort for correctness: a change notification can race an eviction, so the
client must still ignore notifications for keys it no longer holds.

This deliberately does **not** make an address lookup a permanent subscription
to an address or prefix. If a more-specific prefix is later assigned to an
unrelated peer, a client watching only the original peer is not notified. This
is the principal limitation of the key-only design. The protocol takes it in
exchange for a much smaller wire surface and client state machine.

The wire shapes in this document are normative for
[`microtun-api`](../microtun-api),
[`microtun-apiserver`](../microtun-apiserver),
[`microtun-std`](../microtun-std), and
[`microtun-embassy`](../microtun-embassy).

## 1. Goals and non-goals

The protocol is designed to provide:

- bounded messages suitable for fixed-buffer clients;
- side-effect-free lookup methods with explicit key subscriptions;
- an atomic `v1.peer.watch` response that establishes both the initial watched
  state and the subscription without a lookup-to-watch race;
- payload-free invalidations, so no server-side write ordering between state
  responses and notifications can produce a stale install;
- a clear distinction between authoritative misses and transient failures,
  with the authoritative miss reserved for statements about the *target* rather
  than about the caller or its arguments;
- reconnect recovery using only public keys already retained by the client;
- explicit, idempotent watch-set mutation with best-effort cleanup;
- authentication inherited from the tunnel connection rather than request
  fields.

The base protocol does not provide:

- a live subscription to an arbitrary destination address;
- notification when a newly added, more-specific prefix changes longest-prefix
  match for an already routed address;
- state inside notifications, and therefore no way to converge without a round
  trip per changed key;
- registry-wide revisions, cursors, or replay logs;
- batch lookup, watch, or unwatch operations;
- request-level authentication, TLS, or HTTP semantics.

Deployments that require immediate reaction to arbitrary route-topology changes
need an additional mechanism, such as address-query subscriptions or a coarse
registry-change notification. Those mechanisms are outside this protocol.

### 1.1 Why notifications carry no record

A notification with no payload cannot be stale, so it cannot be reordered into
a stale install. That is why `v1.peer.changed` names a key and nothing else.

A notification carrying the record would put one key's state on the wire twice,
from two snapshots, through two code paths. The server would then owe the client
a cross-task write-ordering guarantee: a lookup response must never be written
after a notification describing a newer state of the same key. That guarantee is
invisible when violated, a per-connection writer mutex does not provide it, and
the client has no way to detect its absence. A payload-free notification owes
nothing.

Omitting the payload also keeps authoritative removal in the ordinary lookup
path: the re-lookup returns the explicit `not_found` result variant. This
reduces notification handling on a lagging connection to re-sending one key
name.

The protocol pays one round trip per changed key per interested client. A
re-lookup draws on the client's resolve budget (`REMOTE_RESOLVE_PER_SEC`,
`MAX_INFLIGHT_RESOLVES`), so convergence after a large registry reload takes
time proportional to that budget. Size those limits for the registry.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
express protocol requirements.

- **Caller**: the Microtun peer that opens the API connection.
- **Peers API server**: the peer that serves the registry and terminates the
  caller's WireGuard session.
- **Peer record**: a `PeerInfo` object describing one network peer.
- **Watched key**: a public key subscribed on one connection.
- **Watch set**: the set of watched keys on one connection.
- **Invalidation**: a `v1.peer.changed` notification for a watched key.
- **Authoritative miss**: a successful lookup or watch whose result is the
  explicit `{"not_found":{}}` variant. It states that the registry holds no
  record for the *requested target*, and nothing else.
- **Authoritative removal**: an authoritative miss for a key the client still
  holds.
- **Transient failure**: a JSON-RPC error, malformed response, timeout,
  oversized frame, or transport failure.
- **Registry snapshot**: the complete validated peer registry published by the
  server at one instant.
- **In-flight state request**: a `v1.peer.by_key`, `v1.peer.by_address`, or
  `v1.peer.watch` request whose response has not yet been applied.
- **Connection epoch**: the lifetime of one TCP connection. Its watch set does
  not survive reconnect.

## 3. Transport and framing

### 3.1 Network path

The client connects to a configured inner tunnel address of the Peers API server
on TCP port `80`.

The connection MUST travel through the Microtun/WireGuard tunnel. The protocol
does not define TLS, HTTP, bearer tokens, headers, or a request-level identity
field. Confidentiality, integrity, and peer authentication come from the
tunnel.

### 3.2 Caller identity and admission

The server binds each accepted TCP connection to the static public key of the
WireGuard peer whose authenticated session carried it. That identity is fixed
for the connection lifetime and MUST NOT be overridden by request parameters.

The server MUST fail closed when a stream cannot be attributed to an
authenticated peer key.

Admission is checked at accept and enforced for the connection's lifetime. A
caller whose authenticated key has no registry record is not permitted to
resolve peers, and the server MUST refuse it by closing the connection:

- at accept, the server MUST close the connection without answering;
- if an admitted caller is later removed from the registry, the server MUST
  close its connection before delivering further updates;
- a request that arrives in the window between that removal and the close MUST
  be answered with error `-32001`, never with `{"not_found":{}}`;
- `v1.peer.unwatch` notifications from an unadmitted caller are ignored.

A refused connection is a transient failure, which is the point: a client that
cannot reach the API keeps the records it holds. Answering an unadmitted caller
with `{"not_found":{}}` would instead tell it that every peer it holds has been
deleted, and a configuration mistake that briefly drops one caller's own record
would erase that client's whole routing table rather than merely disconnecting
it. See §11.2 for why this does not weaken enumeration resistance.

An invalid lookup value and an unknown lookup target remain distinguishable
from each other only in that the first is a caller error (§9) and the second is
an authoritative miss; neither reveals anything about the registry's contents.

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
| Client to server | lookups, `v1.peer.watch`, and `v1.peer.unwatch` | 256 bytes |
| Server to client | lookup responses and `v1.peer.changed` | 1024 bytes |

A complete newline-terminated frame MUST fit in the receiving buffer. An
oversized incoming frame is a transient connection failure.

The server-to-client buffer is sized by lookup and `v1.peer.watch` responses. The record
schema is bounded so a valid worst-case response fits in 1024 bytes, and a
record contains at most four address prefixes. A `v1.peer.changed` notification
carries one key name and fits comfortably below the small-frame bound, but it
shares the response direction and is therefore read from the same buffer.

### 3.5 JSON-RPC envelope

Messages use JSON-RPC version `2.0`.

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"v1.peer.by_key","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

Successful positive response:

```json
{"jsonrpc":"2.0","id":1,"result":{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","addresses":["10.0.0.3/32"]}}}
```

Authoritative miss:

```json
{"jsonrpc":"2.0","id":1,"result":{"not_found":{}}}
```

Notification:

```json
{"jsonrpc":"2.0","method":"v1.peer.changed","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

Request IDs MUST be JSON integers representable as signed 64-bit values
(`-9223372036854775808` through `9223372036854775807`). String IDs,
fractional numbers, and integers outside that range are invalid JSON-RPC
message envelopes. A response MUST echo the request ID exactly. Notifications
MUST omit `id` and do not receive responses.

### 3.6 API version namespace

Every Peers API method name begins with an API-version prefix. This document
defines version `v1`, whose prefix is `v1.`; for example,
`v1.peer.by_key` and `v1.peer.changed`.

The prefix versions the Peers API wire contract, not JSON-RPC itself:
`"jsonrpc":"2.0"` remains unchanged. A request selects the response schema by
the version in its method name, while server-to-client notifications carry that
same version explicitly in their own method names.

Clients conforming to this document MUST send only `v1.` methods and MUST
ignore unsupported server notification methods. Servers conforming to this
document MUST implement the `v1.` methods defined in §6. An unprefixed method
such as `peer.by_key`, or a method using an unsupported version prefix, is an
unknown method and is handled according to §9.

Keeping the version in the method namespace allows a future server to implement
multiple API generations on one transport without changing the JSON-RPC
framing, connection setup, or request-ID rules.

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
For example, `::ffff:10.0.0.5` and `10.0.0.5` select the same IPv4 route.

### 4.3 Endpoint

An endpoint is a JSON string containing an IP address and UDP port:

```text
203.0.113.5:51820
[2001:db8::5]:51820
```

Hostnames are not part of the wire schema. IPv6 endpoints use brackets.
IPv4-mapped IPv6 endpoints are normalized to native IPv4 by the client codec.

### 4.4 Cidr

A tunnel prefix is a JSON string containing an IPv4 or IPv6 CIDR, such as
`10.1.2.0/24` or `2001:db8:1::/64`.

A sender MUST include the prefix length, including on host prefixes:
`10.1.2.3/32`, never `10.1.2.3`. A receiver SHOULD accept the abbreviated form
and read it as `/32` or `/128`, and SHOULD accept a prefix carrying host bits
and clear them (`10.1.2.3/24` means `10.1.2.0/24`). Both are unambiguous, and
tolerating them costs a receiver nothing; neither is ever produced by a
conforming sender.

A peer record contains at most four prefixes.

### 4.5 PeerInfo

`PeerInfo` is the complete peer-record wire type. A successful positive lookup
or `v1.peer.watch` returns it as the payload of the `found` `LookupResult`
variant.

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

Wire decoding validates field lengths and syntax. Trust and installation policy
remain the client's responsibility.

The reference `microtun-apiserver` treats a configured `Endpoint` as a fallback.
Once its tunnel authenticates direct traffic from that public key, the last
observed outer UDP source becomes the `endpoint` served for that peer and takes
precedence over later configuration-only endpoint changes. This is runtime
state, not a new wire field: clients consume the same `PeerInfo` shape and do
not need to distinguish configured from observed provenance.

A client currently rejects a decoded dynamic record when, for example, it:

- does not name the key requested by `v1.peer.by_key` or `v1.peer.watch`;
- does not contain the address requested by `v1.peer.by_address`;
- names the local interface or a pinned peer;
- relays through itself;
- has no addresses;
- claims a default route.

These are client installation rules, not additional wire fields.

### 4.6 LookupResult

Every successful lookup or `v1.peer.watch` response MUST include the JSON-RPC
`result` member. `LookupResult` is externally tagged: the single top-level
member names the variant and its value is that variant's payload.

Exactly two variants are defined.

Found:

```json
{
  "found": {
    "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
    "addresses": ["10.0.0.3/32"]
  }
}
```

Not found:

```json
{
  "not_found": {}
}
```

A `found` result MUST contain exactly one member named `found`, whose value is
a valid `PeerInfo`. A `not_found` result MUST be exactly `{"not_found":{}}`.
No other variant names are defined, and a result MUST NOT contain more than one
variant member.

This wire representation is the standard shape of an externally tagged Serde
enum with an empty struct variant, for example:

```rust
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum LookupResult {
    Found(PeerInfo),
    NotFound {},
}
```

The empty `NotFound {}` variant is an object rather than a bare string so both
variants use the same externally tagged object form. Implementations MUST
preserve and enforce this exact representation regardless of the JSON codec
used.

JSON `null` is not a valid lookup result. Receivers MUST NOT infer an
authoritative miss from an absent `result` member, `result: null`, an absent or
unknown variant, a decode default, or any other malformed result. Such
responses are transient failures.

## 5. Lookup result semantics

`v1.peer.by_key`, `v1.peer.by_address`, and `v1.peer.watch` all return the same
`LookupResult`. The response shape says what state the server observed; the
method says whether watch membership changed.

| Response | Meaning | Required client behavior |
| --- | --- | --- |
| `result` is `{"found": <PeerInfo>}` and the payload is valid | Peer found | Validate the record for the request that produced it. A lookup response does **not** create a watch. A `v1.peer.watch` response means the key is now watched and this record is the atomically sampled initial watched state. |
| `result` is exactly `{"not_found":{}}` | Authoritative miss | Treat as not found. A `v1.peer.watch` miss creates no watch. If this was a refresh for a key the client still holds, the miss is authoritative removal. |
| `error`, malformed response, timeout, overflow, or connection loss | Transient failure | Do not convert to not-found. Retain installed state and retry through normal resolver flow. This includes `-32001` (caller not admitted), `-32002` (rate limited), and `-32602` (undecodable argument). |

Only a well-formed successful `not_found` variant is authoritative. A missing
`result`, `result: null`, a missing or unknown variant, a malformed `found`
payload, or any other malformed result is a transient failure, not a deletion
signal.

The miss is also scoped: it answers a question about the target, so a server
MUST NOT produce it for a condition that is really about the caller. A caller
with no registry record, a caller over its request budget, and an argument that
is not a decodable key or address are each a JSON-RPC error (§9), because none
of them is evidence that the named peer stopped existing.

A Microtun client that intends to install and retain a newly resolved record
MUST establish the watch before treating the record as current:

- for a known public key, it SHOULD call `v1.peer.watch` directly instead of doing
  `v1.peer.by_key` followed by `v1.peer.watch`;
- for an address lookup, it first calls `v1.peer.by_address` to discover a
  candidate key, then calls `v1.peer.watch` for that key and uses the **watch
  response**, not the earlier address response, as the record it presents to
  the core. The final record must still cover the originally queried address.

This sequence makes lookup side effects explicit while preserving the same
race-free installation property as the previous implicit-subscription design.

The Microtun core uses a configurable negative TTL, 60 seconds by default.
Installed routes are consulted before negative address entries, so a stale
negative entry cannot suppress an already installed route.

## 6. Methods

### 6.1 `v1.peer.by_key`

Resolves one peer by static public key. This method is side-effect free: it
never changes the connection watch set.

#### Direction

Client-to-server request.

#### Params

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
}
```

#### Result

`LookupResult`.

#### Behavior

1. The server admission-checks the authenticated caller.
2. The server decodes the canonical WireGuard public key.
3. If the key exists, the server returns a `found` variant carrying the complete
   peer record.
4. If the key does not exist, the server returns `{"not_found":{}}`.
5. If the key is not decodable, the server returns `-32602`. If the caller is
   not admitted, the server returns `-32001`. Neither is a miss.
6. The server MUST NOT add or remove any watch because of this request.

A `found` record MUST name the requested key.

#### Example: found

```json
{"jsonrpc":"2.0","id":1,"result":{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","endpoint":"203.0.113.5:51820","addresses":["10.0.0.3/32"],"persistent_keepalive":25}}}
```

#### Example: not found

```json
{"jsonrpc":"2.0","id":2,"result":{"not_found":{}}}
```

### 6.2 `v1.peer.by_address`

Resolves the peer selected by longest-prefix match for one tunnel address. This
method is also side-effect free; it does not subscribe to the queried address,
matched prefix, or returned peer key.

#### Direction

Client-to-server request.

#### Params

```json
{
  "address": "10.0.0.5"
}
```

#### Result

`LookupResult`.

#### Behavior

1. The server admission-checks the authenticated caller.
2. The server parses and normalizes the address.
3. The registry searches all configured tunnel prefixes.
4. When multiple prefixes contain the address, the longest prefix wins.
5. On a match, the server returns a `found` variant carrying the owner's complete
   peer record.
6. If no prefix matches, the server returns `{"not_found":{}}`.
7. If the address is not parsable, the server returns `-32602`. If the caller
   is not admitted, the server returns `-32001`. Neither is a miss.
8. The server MUST NOT change the watch set.

A client that wants to install the result persistently calls `v1.peer.watch` for
the returned public key and validates the watch response against the original
address query before installation.

#### Example

Client:

```json
{"jsonrpc":"2.0","id":3,"method":"v1.peer.by_address","params":{"address":"10.0.0.5"}}
```

Server:

```json
{"jsonrpc":"2.0","id":3,"result":{"found":{"public_key":"u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=","addresses":["10.0.0.0/24"]}}}
```

No watch exists yet because of this response alone.

### 6.3 `v1.peer.watch`

Explicitly subscribes the connection to one peer key and returns that key's
current state.

This is a **request**, not a notification. Returning `LookupResult` is
intentional: the server can add the watch and sample the record in one critical
section, so the client never has to install state from a snapshot taken before
its subscription became active.

#### Direction

Client-to-server request.

#### Params

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
}
```

#### Result

`LookupResult`.

#### Behavior

1. The server admission-checks the authenticated caller.
2. The server decodes the key.
3. Under the watch-creation critical section in §7.1, if the key exists the
   server inserts it into the connection watch set and reads the current peer
   record.
4. The server returns a `found` variant carrying that current record.
5. If the key does not exist, the server returns `{"not_found":{}}` and
   creates no watch. If the key is not decodable the server returns `-32602`,
   and if the caller is not admitted it returns `-32001`; neither is a miss,
   and neither creates a watch.
6. Repeating `v1.peer.watch` for an already watched key is idempotent. Watch sets
   are sets, not reference counts.

A successful found response MUST name the requested key.

#### Example

```json
{"jsonrpc":"2.0","id":4,"method":"v1.peer.watch","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

```json
{"jsonrpc":"2.0","id":4,"result":{"found":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","addresses":["10.0.0.3/32"]}}}
```

### 6.4 `v1.peer.changed`

Tells the client that its state for one watched key may no longer be current.

#### Direction

Server-to-client notification.

#### Params

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
}
```

| Field | Type | Required | Meaning |
| --- | --- | :---: | --- |
| `public_key` | `PublicKey` | yes | Watched key whose current state should be re-read. |

The notification carries no other members. A server MUST NOT include a record.
It does not distinguish modification from removal; only a subsequent
`v1.peer.by_key` does.

#### Behavior

- The server sends the notification only for a key in the connection's watch
  set.
- The server SHOULD notify only watched keys whose record actually changed
  across a registry reload, but a spurious notification is harmless.
- Repeated notifications for one key are valid. Clients SHOULD coalesce them.
- If a connection falls behind the change queue, the server MAY discard the
  queue and send one notification per watched key.
- The notification is not acknowledged and creates no pending server state.

Because the notification carries no state, its position in the stream relative
to lookup or watch responses cannot itself install stale data. The client-side
in-flight rule in §7.2 handles a notification that races a state request for the
same key.

#### Client handling

On receiving `v1.peer.changed(K)`:

- if the client still holds `K`, schedule side-effect-free `v1.peer.by_key(K)`,
  coalescing duplicates;
- otherwise discard the notification.

The refresh response is subject to the same record validation as any other
by-key result. A well-formed `not_found` authoritatively removes the held peer.

#### Example

```json
{"jsonrpc":"2.0","method":"v1.peer.changed","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

### 6.5 `v1.peer.unwatch`

Removes one public key from the connection watch set.

Clients SHOULD send this notification when the core no longer retains the
record, including when the core rejects a positive answer that the resolver had
already watched. Correct clients must nevertheless tolerate a lost or delayed
unwatch because a buffered `v1.peer.changed` can always cross an eviction.

#### Direction

Client-to-server notification.

#### Params

```json
{
  "public_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
}
```

#### Behavior

- The message MUST omit `id`.
- Removing an unknown or already removed key is an idempotent no-op.
- Invalid params, an invalid key, or a non-admitted caller are silently ignored.
- Sending `v1.peer.unwatch` as a request is unsupported and receives method not
  found.
- No behavior other than watch-set membership may depend on receiving it.

The notification is unacknowledged. A client MUST NOT wait for confirmation.

#### Example

```json
{"jsonrpc":"2.0","method":"v1.peer.unwatch","params":{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}
```

## 7. Subscription lifecycle

### 7.1 Watch creation atomicity

`v1.peer.watch(K)` both creates the subscription and returns the current state for
`K`. The server MUST perform the positive watch-set insertion and published-state
read atomically with respect to configuration replacement, authenticated endpoint
observation, and change dispatch.

A single critical section is sufficient:

1. admission-check the caller and decode `K`;
2. resolve `K` in the current published state;
3. on a hit, insert `K` into the connection watch set while that same state is
   still protected;
4. release the published-state critical section;
5. serialize and write the `LookupResult` later.

The ordering guarantee is: if the watch response describes snapshot S, then any
change to K after S is either already represented by a later snapshot read or
causes `v1.peer.changed(K)` on that connection. Neither a config reload nor an
authenticated endpoint observation can land between the snapshot and watch creation
without one side observing the other.

The response and any later `v1.peer.changed` may be written in either order. That is
safe because the notification carries no state.

### 7.2 Invalidation during an in-flight state request

A `v1.peer.changed(K)` can arrive while `v1.peer.watch(K)` or a refresh
`v1.peer.by_key(K)` is still in flight. The response may have been sampled before
the change named by the notification even if it is written after the
notification.

Therefore, if a client receives `v1.peer.changed(K)` while one of those requests for
K is in flight, it MUST ensure at least one additional `v1.peer.by_key(K)` happens
after that response is processed. Repeated change notifications may coalesce to
one extra refresh.

The supplied clients implement this by queuing invalidated keys while calls are
in flight and draining the queue after the call completes.

A change notification for an unrelated key needs no correlation with the
current request; it is simply queued for that key.

### 7.3 Repeated lookup and watch calls

Repeated `v1.peer.by_key` and `v1.peer.by_address` calls are ordinary independent
reads and never affect watch membership.

Repeated `v1.peer.watch(K)` calls refresh the same set membership and return the
current state. They do not create reference counts or duplicate subscriptions.

### 7.4 Reconnection and reconciliation

Watch state belongs to one connection epoch and is lost when the connection
closes. Installed peer records do not have to be discarded on a transient
disconnect.

After reconnect, the client reissues `v1.peer.watch(K)` for every dynamic peer K it
still retains. Each replayed watch both:

1. recreates the subscription on the new connection; and
2. reconciles the local record against current server state.

A `not_found` watch response authoritatively removes the retained peer and does
not create a watch. A transient failure leaves the installed record in place
and causes normal reconnect/retry behavior.

Note what §3.2 buys here. Replay is the moment a client is most exposed to a
misread miss: it asks about every record it holds, in one burst, and acts on
each answer. If losing admission produced misses, one bad config push would
make every replayed watch authoritative and the client would discard its whole
peer table. Because an unadmitted caller is refused instead, the same event
produces a connect failure, the records survive, and the client retries.

A change-notification refresh uses `v1.peer.by_key`; reconnect replay uses
`v1.peer.watch`. Clients may keep both forms in one reconciliation queue, but they
must preserve that distinction because only `v1.peer.watch` recreates server watch
state.

Replay is linear in the number of retained peers. Clients MAY keep several
requests in flight when their implementation supports correlating JSON-RPC IDs.

### 7.5 Failure handling

A remote JSON-RPC error leaves framing synchronized and MAY be treated as a
transient failure without immediately closing the connection.

A timeout, malformed frame, oversized frame, EOF, or transport error makes
stream position or health unreliable. The client SHOULD discard the connection
and reconnect rather than retrying inline. A `v1.peer.changed` lost to a dropped
connection is recovered because reconnect re-watches every retained key.

Installed records survive transient failures. Only a well-formed successful
`not_found` result from the relevant state request can authoritatively remove
resolver state.

### 7.6 Liveness

The base wire protocol has no dedicated ping method.

A client detects failure when a request times out, a read or write fails, or the
server closes the stream. Deployments that need bounded detection of silent
half-open connections SHOULD enable transport keepalive or periodically issue
`v1.peer.by_key` for a retained watched key as a combined liveness and
reconciliation probe.

Such a probe is side-effect free and creates no new protocol state.

## 8. Consequences of key-only watches after address resolution

`v1.peer.by_address` answers one longest-prefix-match query but creates no
subscription. A Microtun client that retains the answer explicitly watches the
returned **key**, not the address or matched prefix. This keeps endpoint, relay,
keepalive, and changes to that peer's own address set current without adding an
address-subscription abstraction.

### 8.1 Prefix removed or moved away from the watched peer

When the watched peer drops the relevant prefix or is removed, `v1.peer.changed`
reaches the client and its `v1.peer.by_key` refresh returns the new record or
`not_found`. The client replaces or removes that peer record, so the old route
disappears.

The next packet for that destination has no installed route and triggers a new
`v1.peer.by_address`, which can discover the prefix's new owner.

### 8.2 More-specific prefix added to an unrelated peer

If a client currently routes an address through peer A and the registry later
adds a more-specific matching prefix owned by peer B, peer A's record may be
unchanged. The client therefore receives no notification and continues using
its installed route to A.

This is a limitation of the key-only watch model. The new owner is discovered
only after something independently causes a new address lookup, such as the old
route being withdrawn, local eviction/expiry, or an explicit address
revalidation policy outside this protocol.

A deployment that requires immediate convergence for this case needs an
address-query watch or registry-topology invalidation mechanism outside this
base protocol.

### 8.3 Overlapping local records

Clients may temporarily hold records whose prefixes overlap, particularly while
old and new state converge. Longest-prefix routing and the core's normal peer
validation rules remain authoritative locally. The wire protocol does not add a
separate route-generation concept.

## 9. Errors

The protocol uses standard JSON-RPC error codes.

| Code | Name | Typical cause |
| ---: | --- | --- |
| `-32700` | Parse error | Malformed JSON or unsupported batch input. |
| `-32600` | Invalid Request | Invalid JSON-RPC message envelope. |
| `-32601` | Method not found | Unknown, unprefixed, or unsupported-version request method, or notification-only `v1.peer.unwatch` sent as a request. |
| `-32602` | Invalid params | Missing params or params whose JSON shape does not match the method. |
| `-32603` | Internal error | Serialization or another internal response failure. |
| `-32001` | Not admitted | The caller's own key has no registry record. Normally the connection is refused at accept; this code covers a request racing a mid-connection removal. |
| `-32002` | Rate limited | The caller exceeded its request budget. |

An argument that does not parse is a caller error, not a miss:

- `{"public_key": 123}` is invalid params (`-32602`): wrong JSON type;
- `{"public_key": "not-a-key"}` is also invalid params (`-32602`): the member
  is a string, but not a decodable 44-character key;
- `{"address": "not-an-ip"}` is likewise invalid params (`-32602`).

Earlier revisions answered the last two with `{"not_found":{}}` for
enumeration symmetry. That symmetry bought nothing — a caller that cannot spell
a key has learned nothing about who exists — while turning a client bug into a
silent negative-cache entry that looks exactly like a legitimately absent peer.
The pair that must stay indistinguishable is an unknown key and an unclaimed
address, and it still is.

`-32001` and `-32002` describe the caller's own standing rather than the
target. Both are transient, so an installed record survives them; they are kept
apart from each other only so an operator reading a client log can tell a
configuration fault from overload.

Unknown notifications receive no response. The server ignores notification
methods other than `v1.peer.unwatch`; the client ignores notification methods
other than `v1.peer.changed`.

## 10. Conformance rules

There is one revision of this protocol and no version negotiation. Both ends are
built from this document; a mismatch is a bug to fix, not a case to handle.

- Clients and servers MUST use the exact method names in this document.
- `v1.peer.by_key` and `v1.peer.by_address` MUST be side-effect free with respect to
  the connection watch set.
- `v1.peer.watch` MUST be a request returning `LookupResult` and MUST provide the
  watch-creation atomicity in §7.1 on a positive result.
- A `v1.peer.watch` miss MUST create no watch.
- The authoritative miss is exactly the `{"not_found":{}}` `LookupResult`; it
  is the only authoritative removal signal.
- A missing `result`, JSON `null` result, missing or unknown result variant, or
  structurally invalid `LookupResult` MUST be treated as a transient failure,
  never as an authoritative miss.
- A `found` result MUST carry exactly one complete `PeerInfo` payload.
- `v1.peer.changed` MUST carry only `public_key` and MUST NOT be treated as carrying
  or implying removal.
- Servers MUST accept `v1.peer.unwatch`; clients SHOULD send it when they no longer
  retain a watched record, but correctness MUST tolerate it being delayed or
  lost.
- Senders MUST omit optional object fields rather than sending JSON `null`.
- Implementations MUST preserve the distinction between authoritative misses
  and transient failures.
- A client installing a result discovered by `v1.peer.by_address` MUST explicitly
  watch the returned key and validate the watch response against the original
  address query.
- Servers are not required to order response frames against `v1.peer.changed`
  notifications; clients MUST implement the in-flight rule in §7.2.
- Clients MUST treat accepted peer records as complete replacements.
- Clients MUST NOT add request-level identity claims that override the
  authenticated connection identity.
- Servers MUST refuse an unadmitted caller by closing the connection, and MUST
  NOT answer one with `{"not_found":{}}`.
- Servers MUST answer an undecodable `public_key` or `address` with `-32602`,
  not with `{"not_found":{}}`.
- Clients MUST jitter reconnect delays and MUST offset the first refresh of a
  change-driven burst, per §11.3.

## 11. Security and resource bounds

### 11.1 Trust boundary

The tunnel authenticates the connection, but a syntactically valid record is
still remote input. Clients MUST apply local resolver policy before installing
routes or peer state.

The Peers API server is a routing authority for dynamic peers. Compromise of it can
redirect permitted dynamic address space, subject to pinned-peer and local
semantic validation rules.

Because `v1.peer.changed` carries no state, a compromised or buggy server cannot use
notifications to install anything. It can only cause a client to re-ask, and
every answer passes through the same validation as an initial state request.

### 11.2 Enumeration behavior

The API returns the same `{"not_found":{}}` result for:

- an unknown peer key;
- an address no configured prefix contains.

Those are the two outcomes that must stay indistinguishable, because telling
them apart would reveal registry structure. They still are.

Three conditions that earlier revisions folded into the same answer no longer
are, because none of them describes the registry's contents:

- an unadmitted caller — the connection is refused (§3.2);
- an undecodable key or address — `-32602` (§9);
- a rate-limited caller — `-32002`.

Separating them costs nothing in enumeration terms. The connection is already
authenticated by the tunnel, so the peer on the other end is a known,
configured identity — not an anonymous prober — and an admitted peer could
always test key and address candidates regardless. What the old symmetry
actually bought was a client that deleted its entire peer table when its own
admission lapsed, and a class of client bug that produced silent negative-cache
entries indistinguishable from a legitimately absent peer.

### 11.3 Watch-set and request bounds

A key enters a connection's watch set only through a successful
`v1.peer.watch(K)`. The server creates no watch for a miss, and repeated watches do
not duplicate entries. Because a successful watch requires K to exist in the
current registry, the watch set is bounded by the registry's peer-key count for
that connection epoch.

Unlike prefix watches, key watches do not accumulate historical route subjects
when prefixes move between peers.

#### Convergence cost

Registry churn amplifies into refresh traffic: at most one coalesced
`v1.peer.by_key` per changed watched key per connection, plus any conservative
extra refresh needed by §7.2.

Because each changed key costs a round trip and refreshes draw on the client's
resolve budget, convergence time after a reload is bounded below by

```text
t_converge  >=  W_changed / REMOTE_RESOLVE_PER_SEC
```

where `W_changed` is the number of *that connection's* watched keys whose
records changed. With the reference budget of 4 resolves per second, a client
watching 200 peers through a full-registry reload needs roughly 50 seconds to
finish reconciling, and routes it has not yet reached remain stale for that
long. Two multipliers make the worst case larger than the average:

- **Queue overflow.** The server's change queue is finite (256 entries in the
  reference implementation). A connection that falls behind it is sent one
  notification per watched key rather than per *changed* key, so `W_changed`
  degrades to the whole watch set even if one record actually moved.
- **Reconnect.** Replay is one `v1.peer.watch` per retained key and is subject to
  the same budget, so a reconnect during churn pays the cost twice.

Size `REMOTE_RESOLVE_PER_SEC` and `MAX_INFLIGHT_RESOLVES` against the largest
watch set a client will hold, not the typical one. A deployment whose tolerable
staleness window is shorter than `W / REMOTE_RESOLVE_PER_SEC` has not been
sized for its registry.

#### Pacing

The events that drive this traffic are synchronized across the fleet: one
reload invalidates a key for every client watching it at the same instant, and
one server restart drops every connection at the same instant. Unpaced clients
therefore answer in lockstep, concentrating the fleet's entire refresh volume
into one round-trip window.

Accordingly:

- Servers SHOULD bound concurrent connections per authenticated key and
  rate-limit requests. A rate-limit rejection MUST be a JSON-RPC error, never
  `{"not_found":{}}`.
- Clients MUST coalesce repeated notifications for one key into a single
  refresh.
- Clients MUST jitter reconnect attempts. The reference clients spread a
  one-second base delay uniformly over `[500 ms, 1500 ms)`.
- Clients MUST offset the first refresh of a change-driven reconciliation burst
  by a uniformly random delay in `[0, 1000 ms)`. Subsequent refreshes in the
  same burst follow without further delay, and reconnect replay is not offset
  again because the jittered reconnect delay has already spread it.

Jitter that is seeded identically across a fleet is not jitter. A seed MUST
differ between nodes; deriving it from the node's own static public key
satisfies this by construction, whereas a clock-derived seed does not for
devices that boot together from one image.

### 11.4 Cleanup

Watch sets are destroyed when the connection closes, so watch state cannot
accumulate across epochs. A client SHOULD send `v1.peer.unwatch` when it discards a
dynamic peer to stop useless notifications during the current epoch. A lost or
omitted unwatch affects traffic efficiency, not correctness.

## 12. Reference client flow

```text
connect to <peers-api-server-inner-address>:80 through the tunnel
retain desired_keys for dynamic peer records currently installed

on connection established:
    for key in desired_keys:
        call v1.peer.watch(key)
        if valid record for key:
            replace local record
        if result is not_found:
            remove local record and key from desired_keys
        if transient failure:
            discard connection and retry reconciliation later

on unresolved public key K:
    call v1.peer.watch(K)
    if valid record for K:
        install record
        add K to desired_keys
    if result is not_found:
        negative-cache K
    if transient failure:
        retain existing state

on unresolved destination address A:
    call v1.peer.by_address(A)
    if result is not_found:
        negative-cache A
    if transient failure:
        retain existing state
    if candidate record is found with key K:
        call v1.peer.watch(K)
        if valid watched record for K still contains A:
            install watched record
            add K to desired_keys
        if watch result is not_found:
            treat resolution as not found
        if watch fails transiently:
            do not install the earlier candidate record

on v1.peer.changed(K):
    if K in desired_keys:
        queue v1.peer.by_key(K), coalescing duplicates
    else:
        discard

if v1.peer.changed(K) arrives while v1.peer.watch(K) or v1.peer.by_key(K) is in flight:
    ensure one additional v1.peer.by_key(K) runs after that response completes

on local peer eviction or rejected watched answer K:
    remove K from desired_keys
    notify v1.peer.unwatch(K)
    expect no acknowledgement

on timeout, malformed frame, EOF, or transport failure:
    discard connection
    keep installed records
    reconnect and replay desired_keys with v1.peer.watch
```