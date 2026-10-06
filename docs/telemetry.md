# Local telemetry contract

Portal, Vector, the built-in TUI and third-party applications use the same
`nowhere.telemetry` read-only contract. There is no network listener, TCP
fallback, remote endpoint, application authentication token or alternate
transport compatibility path. The [JSON Schema](telemetry/schema.json) covers
registry records and every message. [Examples](telemetry/examples.json) include
valid and invalid commands. This is one fixed contract without
capability negotiation; application release versions do not select a protocol.
Changes to public fields or semantics require a separate compatibility review.

## Discovery and identity

Use the platform system temporary directory, shared with the service. On Unix,
`nowhere-telemetry-<effective UID>/` is owned by that user with mode `0700`.
Each instance publishes `nowhere.<32 lowercase hexadecimal instance ID>.json`
with mode `0600`, atomically at startup. It is not a periodically written log.
Its `endpoint` is a Unix socket in the same private directory; socket filenames
use the first 16 hexadecimal characters of the random ID to fit platform path
limits. The socket also has mode `0600` and is not a data-storage file.

On Windows, the directory suffix is the first 16 bytes of SHA-256 of the current
user's SID, encoded as lowercase hexadecimal. Endpoints are local byte-mode
named pipes named `\\.\pipe\nowhere-telemetry-<user suffix>-<instance ID>`.
Directories, files and pipes restrict access to that user; remote pipe clients
are rejected. Windows `uid` is metadata only and is not an authorization ID.

Registry records contain `protocol`, `instance` (registry name, UID, PID and
process incarnation), `transport` (`unix_socket` or `named_pipe`), `endpoint`
and `namespace`. They contain no business
address, configuration, pseudonym key or traffic history. Validate permissions,
object type, endpoint namespace and peer identity before trusting a record.
The hello instance ID must match discovery. On Linux, namespace identity must
match before PID checks or cleanup. Do not delete files merely because a
connection fails. Remove stale records only after confirming process death or
an incarnation mismatch. An unavailable process identity is not evidence of
death. The registry filename must match its embedded instance identity.
Instance IDs change at every start.

Services remove their registry and socket on normal exit. Initialization fails
closed for telemetry if permissions, identity, entropy or path length cannot
be guaranteed; forwarding continues with a warning. There is no fallback.

## Framing and subscription

Every frame is a four-byte unsigned big-endian payload length followed by
UTF-8 JSON. Read exactly the specified bytes; TCP-style assumptions about one
read per message do not apply to these byte streams. Server payloads are at
most 65536 bytes, client commands at most 1024 bytes. Zero lengths and invalid
JSON are rejected. Preserve 64-bit integer precision (for example, use a
lossless JSON parser rather than ordinary JavaScript Number for counters).

The server first verifies OS access and sends `hello`. The client must send
`subscribe` within five seconds. Until then there are no snapshots or events:

```json
{"type":"subscribe","data":{"request_id":1,"subscription":"detail"}}
```

The server acknowledges the initial subscription with `subscribed`, echoing the
request ID and mode, then sends the current `snapshot` and `lifecycle`. The same
command switches modes; subsequent acknowledgements do not trigger another
initial snapshot or lifecycle. An acknowledgement establishes the new delivery mode; previously sent
messages may still arrive before that acknowledgement. There is no control,
configuration, file access, execution, historical query or replay command.

`summary` receives snapshots and lifecycle. `detail` also receives runtime,
access start/finish and gap events. A finish is self-contained and can arrive
without a start. Late subscribers do not receive an inventory of active flows.

## Values and delivery

All byte counters are cumulative business payload bytes. `tcp_logical_*` and
`udp_logical_*` group by business protocol; `tls_payload_*` and
`quic_payload_*` group by carrier. They exclude encryption headers,
retransmissions and IP overhead, and are not interface bandwidth counters.
Compute bytes/second from counter differences and `uptime_ms` differences.
Independently read atomic counters are not a transactional accounting ledger.

`timestamp_ms` is Unix wall-clock milliseconds; `uptime_ms` is process running
time in milliseconds. Ping is milliseconds, RSS is bytes, CPU is percent of
one CPU and may exceed 100. Unavailable resources and the first CPU sample
are `null`. Snapshots may initially have sequence zero. Active counts describe
logical flows and authenticated carriers separately.

Snapshot sequence numbers count captures. Detailed event sequence numbers
are monotonic within an instance and shared by runtime/start/finish messages.
They are assigned under the same lock as publication. Snapshot/lifecycle
updates coalesce; there is no global ordering across message categories.
Detailed events use a bounded 1024-entry broadcast queue. `gap.data.missed`
reports receiver lag, not a recoverable offset. Summary periods, pre-subscribe
periods and disconnects have no replay guarantee. This is live observation,
not an audit or billing ledger.

## Privacy and trust

Same OS user is the trust boundary. Different ordinary users and remote
clients cannot subscribe. Administrators and compromised same-user processes
are outside this isolation boundary. A collector can retain or forward what
it legitimately receives; the service cannot enforce its later handling.

Client addresses are replaced before publication with short instance-local
numbers such as `C001`; source ports are ignored so successive connections from
the same client IP share a number. Path peers use a separate `P001` numbering
space and retain endpoint-level identity. Numbers reset after restart and have
no identity meaning across instances. Each category caches at most 4096 keyed
identity digests, never raw addresses. When full, the oldest entry is evicted;
a later occurrence gets a new number. Numbers are never reused within a process.
At most 16 path peers are included, with `truncated` marking omitted peers.

Destination domains/IPs and ports are intentionally visible to authorized
collectors as validated `host:port` values (IPv6 is bracketed). This permits
useful routing and connectivity diagnosis, but collectors can learn visited
destinations. URLs, credentials, request paths and query strings are not valid
targets and are replaced with `<redacted>`. Raw paths and session identifiers
are not serialized. Hello metadata includes
validated instance endpoints and an allowlisted effective configuration summary:
listen/Portal/SOCKS endpoints, transports, TLS mode, multiplexing, Morph, rate
limits, legacy dial address or both dial4/dial6 source selections, SNI and pin
presence. Chained Portal options use `next.`
prefixes. Keys, SOCKS credentials, certificate paths and raw configuration URLs
are excluded. Authorized collectors can therefore see configured service
addresses and SNI. In the TUI, `i` opens an aligned configuration view; arrow keys
and PageUp/PageDown scroll options, Home/End jump, and Esc/i closes it.
The endpoint and summary fields default to empty when absent; a collector then
reports metadata as unavailable. Collectors that validate against a closed
instance schema must include these fields in their schema.
Carrier fields retain `tcp` (TLS)
and `udp` (QUIC); a null carrier represents the unresolved Mix policy.
The TUI renders uplink/downlink pairs like `TLS → QUIC` or `MIX → TLS`;
Mix is a configured policy, not a claim about the selected carrier.

Runtime events use `message` for a safe diagnostic template and optional
classified reason, for example `TLS carrier connection failed: connection
refused`. Only known templates and a closed vocabulary of reasons are published;
unknown details become `operation failed`. Access errors use the same vocabulary,
including DNS failure, timeout, certificate failure and connection refusal.
`TLS mux carrier disconnected` reports the first terminal carrier reason as
`application closed`, `idle timeout`, `unexpected EOF`, `mux reader failure`,
`mux writer failure`, or `protocol error`. This reason applies to the physical
carrier and therefore to every logical stream it owned.
Lifecycle messages retain whitelisted reasons such as `STOPPED: START_FAILED`.
Diagnostic inputs include nested error causes, but only classified reasons leave
the publisher. Keys, passwords, tokens, authentication data and raw error chains are never
forwarded. Privacy is enforced by the publisher, identically for TUI and
third-party subscribers. Independent stdout/stderr business logs retain their
own policy.

Example TUI access line:

```text
15:38:02 TCP OK   C001 → example.com:443  TLS → QUIC  462ms ↑1.82 KiB ↓6.28 KiB
```

## Resource limits and failure handling

Each service permits 16 connected collectors (not 16 discovered instances per
TUI). Windows additionally maintains a pending pipe instance. Full services
close newly accepted clients without spawning rejection tasks. Writes have a
two-second deadline. Initial subscription and partial-frame assembly have
five-second deadlines; an idle subscribed client is not disconnected merely
for sending no commands. Commands are limited by a per-connection token bucket
of capacity eight, replenished at four per second. Invalid commands close the
connection; error replies, if sent, contain only fixed codes.

Detailed events contain bounded identifiers, validated targets and lists; their encoded payloads
are below 8192 bytes. No unbounded client queues or disk histories are created.
The TUI retains at most 2048 unfinished starts for correlation; finishes remain
self-contained when that cache is cleared. New access records are built only
while detail subscribers exist. On loss of a
connection, rediscover and resubscribe; do not assume delivery continuity.

## Containers

The supported arrangement is service and collector/TUI in the same container,
with the same user and temporary directory. No telemetry port publication,
host networking, privileges or extra capabilities are needed. Host-to-container,
sidecar and cross-container subscription are not supported by this contract.
Do not share the telemetry directory across namespaces: matching numeric UIDs
and PIDs alone do not establish matching identities. See
[container deployment](platforms.md#container-image) for writable temporary
storage and non-root operation.
