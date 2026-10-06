# Platforms

Nowhere uses one codebase and one configuration model on Linux, macOS, and
Windows. Portal and Vector support the same TLS 1.3, QUIC, SOCKS5,
split-carrier, authentication, flow-control, and failure semantics on every
supported platform.

## Release targets

| Platform | Architecture and toolchain | Archive |
|---|---|---|
| Linux | x86-64 and AArch64, GNU libc | `.tar.gz` |
| Linux | x86-64 and AArch64, musl | `.tar.gz` |
| macOS | Apple Silicon | `.tar.gz` |
| Windows | x86-64 MSVC | `.zip` |

The executable is named `nowhere` on Linux and macOS and `nowhere.exe` on
Windows. Source builds use the normal Rust workflow on every platform:

```text
cargo build --release --locked
cargo test --all-targets --locked
```

## Network exposure

Portal binds one socket for every address selected by each declared carrier.
The endpoint path therefore defines both process listeners and the firewall or
container rules required around the process.

| Endpoint | Required inbound exposure |
|---|---|
| `*:2000` | TCP 2000 and UDP 2000 |
| `*/tcp:2006` | TCP 2006 |
| `*/udp:2017` | UDP 2017 |
| `*/tcp:2006/udp:2017` | TCP 2006 and UDP 2017 |
| `*/tcp4:2006/udp6:2017` | IPv4 TCP 2006 and IPv6 UDP 2017 |

An unrestricted `*` carrier opens separate IPv4 and IPv6 wildcard sockets.
IPv6 sockets use `V6ONLY` on Linux, macOS, and Windows, so an IPv6 firewall
rule does not replace the corresponding IPv4 rule. If the operating system
does not support one family, only an unrestricted wildcard carrier may start
with the available family and a warning. Explicit families and concrete bind
addresses fail startup when unavailable.

A hostname listener resolves once at startup and binds every matching address.
DNS changes take effect after a process restart. Vector and Portal `next`
resolve each remote carrier independently, filter by its `4` or `6` suffix,
and fail rather than crossing the declared family boundary.

## Container image

GHCR publishes `ghcr.io/nodepassproject/nowhere` for exactly two platforms:
`linux/amd64` and `linux/arm64`. Each repository version tag publishes the
matching container tag and refreshes `latest`.

The runtime image uses `scratch`. It contains the statically linked executable
and a CA bundle for default client certificate verification, with no shell,
package manager, or dynamic libraries.

Start a Portal with its generated certificate:

```text
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  ghcr.io/nodepassproject/nowhere:latest \
  "portal://change-me@:2000"
```

Publish separate carrier ports when the endpoint uses an explicit path:

```text
docker run -d --rm --name nowhere-portal \
  -p 2006:2006/tcp \
  -p 2017:2017/udp \
  ghcr.io/nodepassproject/nowhere:latest \
  "portal://change-me@*/tcp:2006/udp:2017"
```

Docker publication is transport-specific. Publishing `2006/udp` does not
expose the TCP carrier, and publishing `2017/tcp` does not expose QUIC. For an
IPv4-only or IPv6-only carrier, align the Docker host binding and host firewall
with the endpoint suffix.

For `tls=2`, mount the CA-issued PEM certificate chain and private key:

```text
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  -v /path/fullchain.pem:/cert.pem:ro \
  -v /path/private-key.pem:/key.pem:ro \
  ghcr.io/nodepassproject/nowhere:latest \
  "portal://change-me@:2000?tls=2&crt=/cert.pem&key=/key.pem"
```

`crt` is the full certificate chain and `key` is its private key. A Vector
verifies the endpoint host by default; `sni=relay.example` can override that name.
The image CA bundle trusts public CAs. For a private CA, mount its root
certificate and set `SSL_CERT_FILE` to the mounted path.

The TUI runs inside the same container as the relay:

```text
docker exec -it nowhere-portal /nowhere tui
```

The relay and TUI must use the same UID and system temporary directory.
Telemetry uses a private Unix socket, not a published network port. Run third-party
collectors inside the same container. Host-to-container, sidecar and cross-container
subscription are outside the supported contract; do not share telemetry directories
across PID or user namespaces.

The image supplies `/tmp` with mode `1777` and does not force a user. A non-root
UID can create its own mode-`0700` directory. Mounted certificates and keys must
also be readable by that UID. Read-only containers need writable temporary storage:

```text
docker run -d --rm --name nowhere-portal \
  --user 10001:10001 --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  -p 2000:2000/tcp -p 2000:2000/udp \
  ghcr.io/nodepassproject/nowhere:latest \
  "portal://change-me@:2000"
docker exec --user 10001:10001 -it nowhere-portal /nowhere tui
```

For Kubernetes, mount an in-memory `emptyDir` at `/tmp`, give the service and
exec/collector the same UID, and ensure the mounted directory permits that UID
to create its private directory. For example, this container/volume fragment
uses a group-writable temporary mount and requires no privileged init process:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
    - name: nowhere
      image: ghcr.io/nodepassproject/nowhere:latest
      args: ["portal://change-me@:2000"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: temporary
          mountPath: /tmp
  volumes:
    - name: temporary
      emptyDir:
        medium: Memory
        sizeLimit: 16Mi
```

A missing, full or unwritable temporary mount disables telemetry with a warning;
forwarding continues. No TCP fallback, extra capabilities or host networking
are needed. Registry files are written once; messages and history are not stored
in the mount. Process memory and tmpfs count against container resource budgets.
Normal shutdown removes instance files; forced termination can leave files until
safe discovery cleanup or destruction of the temporary mount.

## Command lines

Bourne-compatible shells, PowerShell, and Windows Command Prompt accept the
documented double-quoted URLs:

```text
nowhere "vector://secret@portal.example:2000?up=tcp&down=udp&socks=127.0.0.1:1080"
```

In Windows Command Prompt, use the `.exe` name:

```text
nowhere.exe "vector://secret@portal.example:2000?up=tcp&down=udp&socks=127.0.0.1:1080"
```

Certificate and key values accept native filesystem paths. Relative paths are
resolved from the process working directory. Quote a URL whenever a path or
query value contains shell-significant characters.

## Process control

Interactive instances stop with Ctrl+C on every platform. Unix process
managers may send SIGINT or SIGTERM. Windows services should use a wrapper
that forwards a console termination event and allows `NOW_SHUTDOWN_TIMEOUT` to
complete.

Local TUI discovery uses a protected per-user registry in the system temporary
directory and local IPC: Unix domain sockets or Windows named pipes. Linux also
checks boot, PID namespace and user namespace identity before PID-based cleanup.
See the [telemetry contract](telemetry.md).

## Telemetry

The TUI displays lifecycle, transport counts, flow counts, traffic totals, and
carrier state on every platform. Linux additionally obtains process CPU and
resident-memory samples from `/proc`; those fields are unavailable on macOS and
Windows without affecting relay operation. Cross-platform release confidence
comes from the Linux, macOS, and Windows CI matrix.
