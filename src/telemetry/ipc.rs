// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portable loopback transport and per-user registry discovery.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use super::process::{process_is_alive, process_uid, read_process_incarnation};
use super::{
    ClientMessage, Hello, MAX_FRAME_SIZE, ServerMessage, Subscription, TELEMETRY_VERSION,
    TelemetryHub,
};

const MAX_CLIENTS: usize = 16;
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// A registry identity validated against the live process incarnation where supported.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
pub(crate) struct DiscoveredInstance {
    pub(crate) registry_name: String,
    pub(crate) uid: u32,
    pub(crate) pid: u32,
    pub(crate) incarnation: u64,
}

#[derive(serde::Deserialize, Serialize)]
struct RegistryEntry {
    instance: DiscoveredInstance,
    address: SocketAddr,
}

/// Publishes one process hub to any number of read-only TUI clients.
pub(crate) struct TelemetryServer {
    listener: TcpListener,
    hub: Arc<TelemetryHub>,
    clients: Arc<Semaphore>,
    registry_path: PathBuf,
}

impl TelemetryServer {
    pub(crate) fn bind(hub: Arc<TelemetryHub>) -> Result<Self> {
        if let Some(reason) = hub.unavailable_reason() {
            bail!("telemetry process identity is unavailable: {reason}");
        }
        let descriptor = hub.descriptor();
        let name = descriptor.registry_name();
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("telemetry: failed to bind loopback listener")?;
        listener
            .set_nonblocking(true)
            .context("telemetry: failed to make loopback socket nonblocking")?;
        let entry = RegistryEntry {
            instance: DiscoveredInstance {
                registry_name: name,
                uid: descriptor.uid,
                pid: descriptor.pid,
                incarnation: descriptor.incarnation,
            },
            address: listener.local_addr()?,
        };
        let directory = registry_directory();
        std::fs::create_dir_all(&directory)
            .context("telemetry: failed to create local registry")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
        }
        let registry_path = registry_path(&entry.instance.registry_name);
        let payload = serde_json::to_vec(&entry).context("telemetry: failed to encode registry")?;
        std::fs::write(&registry_path, payload).context("telemetry: failed to publish registry")?;
        Ok(Self {
            listener: TcpListener::from_std(listener)
                .context("telemetry: failed to register loopback socket")?,
            hub,
            clients: Arc::new(Semaphore::new(MAX_CLIENTS)),
            registry_path,
        })
    }

    pub(crate) async fn run(self, shutdown: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = self.listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
                continue;
            };
            let Ok(permit) = Arc::clone(&self.clients).try_acquire_owned() else {
                tokio::spawn(async move {
                    let (_, mut writer) = stream.into_split();
                    let _ = write_frame(
                        &mut writer,
                        &ServerMessage::Error {
                            message: format!("telemetry connection limit reached ({MAX_CLIENTS})"),
                        },
                    )
                    .await;
                });
                continue;
            };
            let hub = Arc::clone(&self.hub);
            let connection_shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve_client(stream, hub, connection_shutdown).await;
            });
        }
    }
}

async fn serve_client(
    stream: TcpStream,
    hub: Arc<TelemetryHub>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = FrameReader::new(reader);
    let mut lifecycles = hub.lifecycle_receiver();
    let initial_lifecycle = lifecycles.borrow_and_update().clone();
    write_frame(
        &mut writer,
        &ServerMessage::Hello(Hello {
            instance: hub.descriptor().clone(),
            lifecycle: initial_lifecycle.state,
            lifecycle_reason: initial_lifecycle.reason,
        }),
    )
    .await?;

    let mut snapshots = hub.snapshot_receiver();
    let mut events = hub.event_receiver();
    let mut subscription = Subscription::Summary;
    let initial_snapshot = snapshots.borrow_and_update().clone();
    write_frame(&mut writer, &ServerMessage::Snapshot(initial_snapshot)).await?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            command = reader.next::<ClientMessage>() => {
                match command? {
                    ClientMessage::Subscribe { subscription: next } => {
                        subscription = next;
                    }
                }
            }
            changed = snapshots.changed() => {
                changed.context("telemetry snapshot source closed")?;
                let snapshot = snapshots.borrow_and_update().clone();
                write_frame(
                    &mut writer,
                    &ServerMessage::Snapshot(snapshot),
                ).await?;
            }
            changed = lifecycles.changed() => {
                changed.context("telemetry lifecycle source closed")?;
                let lifecycle = lifecycles.borrow_and_update().clone();
                write_frame(
                    &mut writer,
                    &ServerMessage::Lifecycle(lifecycle),
                ).await?;
            }
            event = events.recv() => {
                match event {
                    Ok(event) if subscription == Subscription::Detail => {
                        write_frame(&mut writer, &event).await?;
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(missed))
                        if subscription == Subscription::Detail =>
                    {
                        write_frame(
                            &mut writer,
                            &ServerMessage::Gap { missed },
                        ).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

pub(crate) fn discover_instances() -> io::Result<Vec<DiscoveredInstance>> {
    let current_uid = process_uid();
    let mut found = Vec::new();
    let directory = registry_directory();
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(found),
        Err(error) => return Err(error),
    };
    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
        let Ok(payload) = std::fs::read(&path) else {
            continue;
        };
        let Ok(entry) = serde_json::from_slice::<RegistryEntry>(&payload) else {
            continue;
        };
        let instance = entry.instance;
        if instance.uid != current_uid {
            continue;
        }
        if !process_is_alive(instance.pid)
            || (cfg!(target_os = "linux")
                && read_process_incarnation(instance.pid) != Some(instance.incarnation))
        {
            let _ = std::fs::remove_file(path);
            continue;
        }
        found.push(instance);
    }
    found.sort_by_key(|instance| (instance.uid, instance.pid, instance.incarnation));
    found.dedup();
    Ok(found)
}

pub(crate) struct TelemetryClient {
    hello: Hello,
    reader: TelemetryReader,
    writer: TelemetryWriter,
}

impl TelemetryClient {
    pub(crate) async fn connect(
        discovered: &DiscoveredInstance,
        subscription: Subscription,
    ) -> Result<Self> {
        let payload = std::fs::read(registry_path(&discovered.registry_name))
            .context("telemetry: discovered registry disappeared")?;
        let entry: RegistryEntry =
            serde_json::from_slice(&payload).context("telemetry: invalid discovered registry")?;
        if entry.instance != *discovered || !entry.address.ip().is_loopback() {
            bail!("telemetry: discovered registry identity mismatch");
        }
        let stream = TcpStream::connect(entry.address)
            .await
            .with_context(|| format!("telemetry: failed to connect {}", entry.address))?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = FrameReader::new(reader);
        let message = reader.next::<ServerMessage>().await?;
        let hello = match message {
            ServerMessage::Hello(hello) => hello,
            ServerMessage::Error { message } => {
                bail!("telemetry: service rejected connection: {message}")
            }
            _ => bail!("telemetry: service did not begin with hello"),
        };
        validate_hello(&hello, discovered)?;
        write_frame(&mut writer, &ClientMessage::Subscribe { subscription }).await?;
        Ok(Self {
            hello,
            reader: TelemetryReader { inner: reader },
            writer: TelemetryWriter { inner: writer },
        })
    }

    pub(crate) fn hello(&self) -> &Hello {
        &self.hello
    }

    pub(crate) fn into_parts(self) -> (Hello, TelemetryReader, TelemetryWriter) {
        (self.hello, self.reader, self.writer)
    }
}

impl Drop for TelemetryServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.registry_path);
    }
}

fn registry_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "nowhere-{TELEMETRY_VERSION}-telemetry-{}",
        process_uid()
    ))
}

fn registry_path(registry_name: &str) -> PathBuf {
    registry_directory().join(format!("{registry_name}.json"))
}

fn validate_hello(hello: &Hello, discovered: &DiscoveredInstance) -> Result<()> {
    let instance = &hello.instance;
    if instance.telemetry_version != TELEMETRY_VERSION
        || instance.uid != discovered.uid
        || instance.pid != discovered.pid
        || instance.incarnation != discovered.incarnation
        || instance.registry_name() != discovered.registry_name
    {
        bail!("telemetry: hello identity does not match discovered registry");
    }
    Ok(())
}

pub(crate) struct TelemetryReader {
    inner: FrameReader<OwnedReadHalf>,
}

impl TelemetryReader {
    pub(crate) async fn next_message(&mut self) -> Result<ServerMessage> {
        self.inner.next().await
    }
}

pub(crate) struct TelemetryWriter {
    inner: OwnedWriteHalf,
}

impl TelemetryWriter {
    pub(crate) async fn subscribe(&mut self, subscription: Subscription) -> Result<()> {
        write_frame(&mut self.inner, &ClientMessage::Subscribe { subscription }).await
    }
}

async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value).context("telemetry: failed to encode JSON frame")?;
    if payload.len() > MAX_FRAME_SIZE {
        bail!("telemetry: encoded frame exceeds {MAX_FRAME_SIZE} bytes");
    }
    write_payload_with_timeout(writer, &payload, WRITE_TIMEOUT).await
}

async fn write_payload_with_timeout<W>(
    writer: &mut W,
    payload: &[u8],
    timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, write_payload(writer, payload))
        .await
        .context("telemetry: timed out writing frame")?
}

async fn write_payload<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_u32(payload.len() as u32)
        .await
        .context("telemetry: failed to write frame length")?;
    writer
        .write_all(payload)
        .await
        .context("telemetry: failed to write frame payload")?;
    writer
        .flush()
        .await
        .context("telemetry: failed to flush frame")?;
    Ok(())
}

/// Incremental decoder whose offsets live outside the returned future.
///
/// `next` can therefore be cancelled by `tokio::select!` after any partial
/// read and safely called again without losing frame alignment.
struct FrameReader<R> {
    inner: R,
    length_bytes: [u8; 4],
    length_read: usize,
    payload: Vec<u8>,
    payload_read: usize,
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(inner: R) -> Self {
        Self {
            inner,
            length_bytes: [0; 4],
            length_read: 0,
            payload: Vec::new(),
            payload_read: 0,
        }
    }

    async fn next<T>(&mut self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        while self.length_read < self.length_bytes.len() {
            let count = self
                .inner
                .read(&mut self.length_bytes[self.length_read..])
                .await
                .context("telemetry: failed to read frame length")?;
            if count == 0 {
                bail!("telemetry: connection closed while reading frame length");
            }
            self.length_read += count;
        }

        if self.payload.is_empty() {
            let length = u32::from_be_bytes(self.length_bytes) as usize;
            if length == 0 || length > MAX_FRAME_SIZE {
                bail!("telemetry: invalid frame length {length}");
            }
            self.payload.resize(length, 0);
        }

        while self.payload_read < self.payload.len() {
            let count = self
                .inner
                .read(&mut self.payload[self.payload_read..])
                .await
                .context("telemetry: failed to read frame payload")?;
            if count == 0 {
                bail!("telemetry: connection closed while reading frame payload");
            }
            self.payload_read += count;
        }

        let payload = std::mem::take(&mut self.payload);
        self.length_bytes = [0; 4];
        self.length_read = 0;
        self.payload_read = 0;
        serde_json::from_slice(&payload).context("telemetry: failed to decode JSON frame")
    }
}

#[cfg(test)]
#[path = "../tests/telemetry/ipc.rs"]
mod tests;
