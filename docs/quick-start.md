# Quick Start

## Build

Nowhere uses stable Rust and the 2024 edition:

```bash
git clone https://github.com/NodePassProject/Nowhere.git
cd Nowhere
cargo build --release --locked
./target/release/nowhere --version
./target/release/nowhere --help
```

## Local Portal and Vector

Terminal one:

```bash
./target/release/nowhere 'portal://secret@127.0.0.1:2077?log=debug'
```

Terminal two:

```bash
./target/release/nowhere \
  'vector://secret@127.0.0.1:2077?up=udp&down=udp&sni=none&socks=127.0.0.1:1080&log=debug'
```

The Portal's default certificate is self-signed. This local example uses
`sni=none`, so certificate verification is disabled without an extra warning.

Test TCP through SOCKS5:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Applications with SOCKS5 UDP ASSOCIATE support can use the same listener for
UDP. One association may address multiple targets; Vector maintains one idle-
timed Nowhere UDP flow per target.

## Choose Upload and Download

Set the two Vector direction parameters independently:

```text
up=tcp&down=tcp&pool=5
up=tcp&down=udp
up=udp&down=tcp
up=udp&down=udp
```

Split combinations require Portal `net=mix`, which is the default. `pool` is
effective only for `tcp/tcp`; values over 256 are clamped and all other carrier
pairs report `pool=0`.

## Production TLS

Portal:

```bash
nowhere \
  'portal://secret@:2077?net=mix&tls=2&crt=/etc/nowhere/fullchain.pem&key=/etc/nowhere/privkey.pem'
```

Vector:

```bash
nowhere \
  'vector://secret@relay.example:2077?up=tcp&down=tcp&pool=5&sni=relay.example&socks=127.0.0.1:1080'
```

The configured ALPN defaults to `now/1`. If overridden, supply the identical
nonempty value to Portal and Vector.

## Shutdown

Send Ctrl-C or SIGINT. New connections stop, pending pairs are cancelled,
QUIC endpoints close, and flow tasks drain until `NOW_SHUTDOWN_TIMEOUT`.
