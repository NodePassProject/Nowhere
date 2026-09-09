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
use crate::common::{
    CarrierEndpoint, DEFAULT_DIALER_IP, ServiceEndpoint, query_first, validate_endpoint_url_input,
};
use crate::transport::MorphKeys;

const VECTOR_QUERY_KEYS: &[&str] = &[
    "up", "down", "mux", "sni", "pin", "rate", "etar", "morph", "socks", "log",
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
    Mix,
}

impl CarrierMode {
    pub(crate) fn parse(
        value: Option<&str>,
        name: &str,
        default: Self,
        context: &str,
    ) -> Result<Self> {
        match value {
            None => Ok(default),
            Some("tcp") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some("mix") => Ok(Self::Mix),
            Some(_) => bail!("{context}: {name} must be tcp, udp, or mix"),
        }
    }

    pub(crate) const fn is_mix(self) -> bool {
        matches!(self, Self::Mix)
    }
}

/// Transport-only configuration shared by Vector and Portal upstream clients.
#[derive(Clone, Debug)]
pub(crate) struct PortalClientConfig {
    pub(crate) remote: ServiceEndpoint,
    pub(crate) up: CarrierMode,
    pub(crate) down: CarrierMode,
    pub(crate) mux: MuxMode,
    pub(crate) morph: bool,
    pub(crate) morph_keys: Option<MorphKeys>,
    pub(crate) sni: Option<String>,
    pub(crate) pin: Option<String>,
    pub(crate) dialer_ip: String,
}

impl PortalClientConfig {
    fn parse(
        url: &Url,
        query: &HashMap<String, String>,
        dialer_ip: &str,
        context: &str,
    ) -> Result<Self> {
        let remote = ServiceEndpoint::parse(url, false, context)?;
        let default = match (remote.has_tcp(), remote.has_udp()) {
            (true, false) | (true, true) => CarrierMode::Tcp,
            (false, true) => CarrierMode::Udp,
            (false, false) => unreachable!(),
        };
        let up = CarrierMode::parse(query.get("up").map(String::as_str), "up", default, context)?;
        let down = CarrierMode::parse(
            query.get("down").map(String::as_str),
            "down",
            default,
            context,
        )?;
        validate_carrier_policy(&remote, up, "up", context)?;
        validate_carrier_policy(&remote, down, "down", context)?;
        let mux = MuxMode::parse(query.get("mux").map(String::as_str))
            .map_err(|error| anyhow!("{context}: {error}"))?;
        let mux = if up == CarrierMode::Udp && down == CarrierMode::Udp {
            MuxMode::Disabled
        } else {
            mux
        };
        let morph = match query.get("morph").map(String::as_str) {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => bail!("{context}: morph must be 0 or 1"),
        };
        let morph_keys = morph.then(|| MorphKeys::from_url(url)).transpose()?;
        let sni = query
            .get("sni")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .map(|value| {
                if !value.is_ascii()
                    || value.len() > 253
                    || value.contains([':', '[', ']'])
                    || value.parse::<std::net::IpAddr>().is_ok()
                {
                    bail!("{context}: sni must be an ASCII DNS name");
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        let pin = query
            .get("pin")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .cloned();
        Ok(Self {
            remote,
            up,
            down,
            mux,
            morph,
            morph_keys,
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
        validate_endpoint_url_input(&format!("vector://{raw_authority}"), "Portal next endpoint")?;
        let separator = raw_authority.rfind('@').ok_or_else(|| {
            anyhow!("Portal next endpoint: shared key and endpoint must be separated by '@'")
        })?;
        if raw_authority[..separator].contains('@') {
            bail!("Portal next endpoint: reserved shared-key characters must be percent-encoded");
        }
        let url = Url::parse(&format!("vector://{raw_authority}"))
            .map_err(|error| anyhow!("Portal next endpoint: invalid authority: {error}"))?;
        if url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            bail!(
                "Portal next endpoint: expected shared-key and one endpoint without a query or fragment"
            );
        }
        let credentials = crate::protocol::Credentials::new(&url)?;
        let config = Self::parse(&url, query, dialer_ip, "Portal next endpoint")?;
        Ok((config, credentials))
    }

    pub(crate) fn endpoint(&self) -> String {
        self.remote.canonical()
    }

    pub(crate) fn host(&self) -> &str {
        &self.remote.host
    }

    pub(crate) fn tcp_endpoint(&self) -> Option<CarrierEndpoint> {
        self.remote.tcp
    }

    pub(crate) fn udp_endpoint(&self) -> Option<CarrierEndpoint> {
        self.remote.udp
    }

    pub(crate) fn effective_route(&self) -> String {
        format!(
            "up={} down={} mux={} sni={} pin={} morph={}",
            self.up,
            self.down,
            self.mux,
            self.sni.as_deref().unwrap_or("none"),
            self.pin.as_deref().unwrap_or("none"),
            u8::from(self.morph),
        )
    }
}

impl fmt::Display for CarrierMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Mix => "mix",
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
            .ok_or_else(|| anyhow!("Vector configuration: socks parameter is required"))?;
        if raw_value.is_empty() {
            bail!("Vector configuration: socks must not be empty");
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
    pub(super) remote: ServiceEndpoint,
    pub(super) up: CarrierMode,
    pub(super) down: CarrierMode,
    pub(super) mux: MuxMode,
    pub(super) morph: bool,
    pub(super) morph_keys: Option<MorphKeys>,
    pub(super) sni: Option<String>,
    pub(super) pin: Option<String>,
    pub(super) rate_mbps: i32,
    pub(super) etar_mbps: i32,
    pub(super) socks: SocksListenConfig,
}

impl VectorConfig {
    pub(super) fn from_url(url: &Url) -> Result<Self> {
        if url.scheme() != "vector" {
            bail!("Vector configuration: URL scheme must be vector");
        }
        if url.password().is_some() {
            bail!("Vector configuration: URL password component is not supported");
        }
        if url.username().is_empty() {
            bail!("Vector configuration: missing shared key before '@'");
        }
        if url.fragment().is_some() {
            bail!("Vector configuration: URL fragment is not supported");
        }
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        let portal = PortalClientConfig::parse(url, &query, DEFAULT_DIALER_IP, "Vector endpoint")?;
        let rate_mbps = parse_rate(query.get("rate").map(String::as_str), "rate")?;
        let etar_mbps = parse_rate(query.get("etar").map(String::as_str), "etar")?;
        let socks = SocksListenConfig::from_url(url)?;

        Ok(Self {
            remote: portal.remote,
            up: portal.up,
            down: portal.down,
            mux: portal.mux,
            morph: portal.morph,
            morph_keys: portal.morph_keys,
            sni: portal.sni,
            pin: portal.pin,
            rate_mbps,
            etar_mbps,
            socks,
        })
    }

    pub(crate) fn portal_client_config(&self) -> PortalClientConfig {
        PortalClientConfig {
            remote: self.remote.clone(),
            up: self.up,
            down: self.down,
            mux: self.mux,
            morph: self.morph,
            morph_keys: self.morph_keys.clone(),
            sni: self.sni.clone(),
            pin: self.pin.clone(),
            dialer_ip: DEFAULT_DIALER_IP.to_owned(),
        }
    }

    pub(super) fn portal_endpoint(&self) -> String {
        self.remote.canonical()
    }

    pub(super) fn checkpoint_mode(&self) -> u8 {
        match (self.up, self.down) {
            (CarrierMode::Tcp, CarrierMode::Tcp) => 0,
            (CarrierMode::Tcp, CarrierMode::Udp) => 1,
            (CarrierMode::Udp, CarrierMode::Tcp) => 2,
            (CarrierMode::Udp, CarrierMode::Udp) => 3,
            (CarrierMode::Mix, CarrierMode::Tcp) => 4,
            (CarrierMode::Mix, CarrierMode::Udp) => 5,
            (CarrierMode::Tcp, CarrierMode::Mix) => 6,
            (CarrierMode::Udp, CarrierMode::Mix) => 7,
            (CarrierMode::Mix, CarrierMode::Mix) => 8,
        }
    }

    pub(super) fn effective_url(&self) -> String {
        format!(
            "vector://{}?up={}&down={}&mux={}&sni={}&pin={}&rate={}&etar={}&morph={}&socks={}",
            self.portal_endpoint(),
            self.up,
            self.down,
            self.mux,
            self.sni.as_deref().unwrap_or("none"),
            self.pin.as_deref().unwrap_or("none"),
            self.rate_mbps,
            self.etar_mbps,
            u8::from(self.morph),
            self.socks.endpoint(),
        )
    }
}

fn validate_carrier_policy(
    endpoint: &ServiceEndpoint,
    mode: CarrierMode,
    name: &str,
    context: &str,
) -> Result<()> {
    let available = match mode {
        CarrierMode::Tcp => endpoint.has_tcp(),
        CarrierMode::Udp => endpoint.has_udp(),
        CarrierMode::Mix => endpoint.has_tcp() && endpoint.has_udp(),
    };
    if !available {
        bail!("{context}: {name} selects a carrier not declared by the endpoint");
    }
    Ok(())
}

fn parse_rate(value: Option<&str>, name: &str) -> Result<i32> {
    match value {
        None => Ok(0),
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow!("Vector configuration: {name} must be a non-negative integer")),
    }
}

#[cfg(test)]
#[path = "../tests/vector/config.rs"]
mod tests;
