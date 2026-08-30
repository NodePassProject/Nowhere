// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated `vector://` URL parsing with first-value query semantics.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Result, anyhow, bail};
use url::Url;

use crate::common::socks::{
    SocksCredentials, first_raw_socks_value, format_host_port, parse_host_port, parse_socks_value,
};
use crate::common::{DEFAULT_DIALER_IP, query_first};

const VECTOR_QUERY_KEYS: &[&str] = &[
    "up", "down", "mux", "sni", "pin", "rate", "etar", "socks", "log",
];

/// Whether a client originates dedicated or Mux TLS carriers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MuxMode {
    Disabled,
    Enabled,
}

impl MuxMode {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("0") => Ok(Self::Disabled),
            Some("1") => Ok(Self::Enabled),
            Some(_) => bail!("mux must be 0 or 1"),
        }
    }

    pub(crate) const fn enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl fmt::Display for MuxMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.enabled() { "1" } else { "0" })
    }
}

/// Physical carrier selected for one logical flow direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierMode {
    Tcp,
    Udp,
}

impl CarrierMode {
    pub(crate) fn parse(value: Option<&str>, name: &str) -> Result<Self> {
        match value {
            None => Ok(Self::Udp),
            Some("tcp") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some(_) => bail!("vector::config: {name} must be tcp or udp"),
        }
    }
}

/// Transport-only configuration shared by Vector and Portal upstream clients.
#[derive(Clone, Debug)]
pub(crate) struct PortalClientConfig {
    pub(crate) remote_host: String,
    pub(crate) remote_port: u16,
    pub(crate) up: CarrierMode,
    pub(crate) down: CarrierMode,
    pub(crate) mux: MuxMode,
    pub(crate) sni: Option<String>,
    pub(crate) pin: Option<String>,
    pub(crate) dialer_ip: String,
}

impl PortalClientConfig {
    fn parse(url: &Url, query: &HashMap<String, String>, dialer_ip: &str) -> Result<Self> {
        let remote_host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| anyhow!("vector::config: missing Portal host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let remote_port = url
            .port()
            .filter(|port| *port != 0)
            .ok_or_else(|| anyhow!("vector::config: missing Portal port"))?;
        let up = CarrierMode::parse(query.get("up").map(String::as_str), "up")?;
        let down = CarrierMode::parse(query.get("down").map(String::as_str), "down")?;
        let mux = MuxMode::parse(query.get("mux").map(String::as_str))
            .map_err(|error| anyhow!("vector::config: {error}"))?;
        let sni = query
            .get("sni")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .map(|value| {
                if !value.is_ascii()
                    || value.len() > 253
                    || value.contains([':', '[', ']'])
                    || value.parse::<std::net::IpAddr>().is_ok()
                {
                    bail!("vector::config: sni must be an ASCII DNS name");
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        let pin = query
            .get("pin")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .cloned();
        Ok(Self {
            remote_host,
            remote_port,
            up,
            down,
            mux,
            sni,
            pin,
            dialer_ip: dialer_ip.to_owned(),
        })
    }

    pub(crate) fn from_upstream_authority(
        raw_authority: &str,
        query: &HashMap<String, String>,
        dialer_ip: &str,
    ) -> Result<(Self, crate::protocol::Credentials)> {
        let separator = raw_authority.rfind('@').ok_or_else(|| {
            anyhow!("portal::next: shared key and endpoint must be separated by @")
        })?;
        if raw_authority[..separator].contains('@') {
            bail!("portal::next: reserved shared-key characters must be percent-encoded");
        }
        let url = Url::parse(&format!("vector://{raw_authority}"))
            .map_err(|error| anyhow!("portal::next: invalid upstream Portal authority: {error}"))?;
        if url.password().is_some()
            || !url.path().is_empty()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("portal::next: expected only shared-key@host:port");
        }
        let credentials = crate::protocol::Credentials::new(&url)
            .map_err(|error| anyhow!("portal::next: {error}"))?;
        let config = Self::parse(&url, query, dialer_ip)
            .map_err(|error| anyhow!("portal::next: {error}"))?;
        Ok((config, credentials))
    }

    pub(crate) fn endpoint(&self) -> String {
        format_host_port(&self.remote_host, self.remote_port)
    }

    pub(crate) fn effective_route(&self) -> String {
        format!(
            "up={} down={} mux={} sni={} pin={}",
            self.up,
            self.down,
            self.mux,
            self.sni.as_deref().unwrap_or("none"),
            self.pin.as_deref().unwrap_or("none"),
        )
    }
}

impl fmt::Display for CarrierMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Validated local SOCKS5 listen endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksListenConfig {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) credentials: Option<SocksCredentials>,
}

impl SocksListenConfig {
    fn from_url(url: &Url) -> Result<Self> {
        let raw_value = first_raw_socks_value(url)
            .ok_or_else(|| anyhow!("vector::config: socks parameter is required"))?;
        if raw_value.is_empty() {
            bail!("vector::config: socks must not be empty");
        }
        let (endpoint, credentials) = parse_socks_value(raw_value)?;
        let (host, port) = parse_host_port(&endpoint, "socks listener", true)?;
        Ok(Self {
            host,
            port,
            credentials,
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    pub(super) fn authenticated(&self) -> bool {
        self.credentials.is_some()
    }
}

/// Fully validated Vector runtime configuration.
#[derive(Clone, Debug)]
pub(crate) struct VectorConfig {
    pub(super) remote_host: String,
    pub(super) remote_port: u16,
    pub(super) up: CarrierMode,
    pub(super) down: CarrierMode,
    pub(super) mux: MuxMode,
    pub(super) sni: Option<String>,
    pub(super) pin: Option<String>,
    pub(super) rate_mbps: i32,
    pub(super) etar_mbps: i32,
    pub(super) socks: SocksListenConfig,
}

impl VectorConfig {
    pub(super) fn from_url(url: &Url) -> Result<Self> {
        if url.scheme() != "vector" {
            bail!("vector::config: URL scheme must be vector");
        }
        if url.password().is_some() {
            bail!("vector::config: URL password component is not supported");
        }
        if url.username().is_empty() {
            bail!("vector::config: missing shared key");
        }
        if url.fragment().is_some() {
            bail!("vector::config: URL fragment is not supported");
        }
        if !url.path().is_empty() {
            bail!("vector::config: URL path is not supported");
        }

        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        let portal = PortalClientConfig::parse(url, &query, DEFAULT_DIALER_IP)?;
        let rate_mbps = parse_rate(query.get("rate").map(String::as_str), "rate")?;
        let etar_mbps = parse_rate(query.get("etar").map(String::as_str), "etar")?;
        let socks = SocksListenConfig::from_url(url)?;

        Ok(Self {
            remote_host: portal.remote_host,
            remote_port: portal.remote_port,
            up: portal.up,
            down: portal.down,
            mux: portal.mux,
            sni: portal.sni,
            pin: portal.pin,
            rate_mbps,
            etar_mbps,
            socks,
        })
    }

    pub(crate) fn portal_client_config(&self) -> PortalClientConfig {
        PortalClientConfig {
            remote_host: self.remote_host.clone(),
            remote_port: self.remote_port,
            up: self.up,
            down: self.down,
            mux: self.mux,
            sni: self.sni.clone(),
            pin: self.pin.clone(),
            dialer_ip: DEFAULT_DIALER_IP.to_owned(),
        }
    }

    pub(super) fn portal_endpoint(&self) -> String {
        format_host_port(&self.remote_host, self.remote_port)
    }

    pub(super) fn checkpoint_mode(&self) -> u8 {
        match (self.up, self.down) {
            (CarrierMode::Tcp, CarrierMode::Tcp) => 0,
            (CarrierMode::Tcp, CarrierMode::Udp) => 1,
            (CarrierMode::Udp, CarrierMode::Tcp) => 2,
            (CarrierMode::Udp, CarrierMode::Udp) => 3,
        }
    }

    pub(super) fn effective_url(&self) -> String {
        format!(
            "vector://{}?up={}&down={}&mux={}&sni={}&pin={}&rate={}&etar={}&socks={}",
            self.portal_endpoint(),
            self.up,
            self.down,
            self.mux,
            self.sni.as_deref().unwrap_or("none"),
            self.pin.as_deref().unwrap_or("none"),
            self.rate_mbps,
            self.etar_mbps,
            self.socks.endpoint(),
        )
    }
}

fn parse_rate(value: Option<&str>, name: &str) -> Result<i32> {
    match value {
        None => Ok(0),
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow!("vector::config: {name} must be a non-negative integer")),
    }
}

#[cfg(test)]
#[path = "../tests/vector/config.rs"]
mod tests;
