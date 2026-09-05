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

## Container image

GHCR publishes `ghcr.io/nodepassproject/nowhere` for exactly two platforms:
`linux/amd64` and `linux/arm64`. Each repository version tag publishes the
matching container tag and refreshes `latest`.

The runtime image uses `scratch`. It contains the statically linked executable,
a CA bundle for `sni` certificate verification, and no shell, package manager,
or dynamic libraries.

Start a Portal with its generated certificate:

```text
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  ghcr.io/nodepassproject/nowhere:latest \
  'portal://change-me@:2000'
```

For `tls=2`, mount the CA-issued PEM certificate chain and private key:

```text
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  -v /path/fullchain.pem:/cert.pem:ro \
  -v /path/private-key.pem:/key.pem:ro \
  ghcr.io/nodepassproject/nowhere:latest \
  'portal://change-me@:2000?tls=2&crt=/cert.pem&key=/key.pem'
```

`crt` is the full certificate chain and `key` is its private key. A Vector
enables verification with `sni=relay.example`; the image CA bundle trusts
public CAs. For a private CA, mount its root certificate and set
`SSL_CERT_FILE` to the mounted path.

The TUI runs inside the same container as the relay:

```text
docker exec -it nowhere-portal /nowhere tui
```

The relay and TUI must use the same UID. The image does not force a user. With
`--user`, the mounted key must be readable by that UID and `/tmp` must be
writable, for example through `--tmpfs /tmp`. Read-only containers need the
same tmpfs for TUI discovery.

## Command lines

Bourne-compatible shells and PowerShell accept the documented single-quoted
URLs:

```text
nowhere 'vector://secret@portal.example:2000?up=tcp&down=udp&socks=127.0.0.1:1080'
```

In Windows Command Prompt, use double quotes and the `.exe` name:

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

Local TUI discovery uses a per-user registry in the operating system's
temporary directory and a loopback TCP control socket. It does not depend on
Unix domain sockets or `/proc`.

## Telemetry

The TUI displays lifecycle, transport counts, flow counts, traffic totals, and
carrier state on every platform. Linux additionally obtains process CPU and
resident-memory samples from `/proc`; those fields are unavailable on macOS and
Windows without affecting relay operation. Cross-platform release confidence
comes from the Linux, macOS, and Windows CI matrix.
