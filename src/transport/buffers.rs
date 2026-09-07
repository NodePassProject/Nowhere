// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded reusable relay scratch buffers.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

const TCP_CACHE_LIMIT: usize = 64;
const UDP_CACHE_LIMIT: usize = 32;

/// Buffer size configuration used to allocate fresh relay scratch buffers.
#[derive(Debug, Clone)]
pub struct Buffers {
    tcp: Arc<BufferPool>,
    udp: Arc<BufferPool>,
}

#[derive(Debug)]
struct BufferPool {
    size: usize,
    cache_limit: usize,
    cached: Mutex<Vec<Vec<u8>>>,
}

/// A relay buffer returned to its bounded pool on drop.
#[derive(Debug)]
pub struct BufferLease {
    buffer: Option<Vec<u8>>,
    pool: Arc<BufferPool>,
}

impl Buffers {
    /// Creates a buffer-size pair for TCP and UDP relay paths.
    pub fn new(tcp_size: usize, udp_size: usize) -> Self {
        Self {
            tcp: Arc::new(BufferPool::new(tcp_size, TCP_CACHE_LIMIT)),
            udp: Arc::new(BufferPool::new(udp_size, UDP_CACHE_LIMIT)),
        }
    }

    /// Borrows a TCP relay buffer from the bounded reuse pool.
    pub fn get_tcp_buffer(&self) -> BufferLease {
        BufferPool::acquire(&self.tcp)
    }

    /// Borrows a UDP relay buffer from the bounded reuse pool.
    pub fn get_udp_buffer(&self) -> BufferLease {
        BufferPool::acquire(&self.udp)
    }
}

impl BufferPool {
    fn new(size: usize, cache_limit: usize) -> Self {
        Self {
            size,
            cache_limit,
            cached: Mutex::new(Vec::with_capacity(cache_limit)),
        }
    }

    fn acquire(pool: &Arc<Self>) -> BufferLease {
        let mut buffer = pool
            .cached
            .lock()
            .expect("buffer pool poisoned")
            .pop()
            .unwrap_or_else(|| vec![0; pool.size]);
        buffer.resize(pool.size, 0);
        BufferLease {
            buffer: Some(buffer),
            pool: pool.clone(),
        }
    }
}

impl Deref for BufferLease {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().expect("buffer lease is live")
    }
}

impl DerefMut for BufferLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().expect("buffer lease is live")
    }
}

impl AsMut<[u8]> for BufferLease {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for BufferLease {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for BufferLease {
    fn drop(&mut self) {
        let Some(buffer) = self.buffer.take() else {
            return;
        };
        let mut cached = self.pool.cached.lock().expect("buffer pool poisoned");
        if cached.len() < self.pool.cache_limit {
            cached.push(buffer);
        }
    }
}

#[cfg(test)]
#[path = "../tests/transport/buffers.rs"]
mod tests;
