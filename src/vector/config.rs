// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated `vector://` URL parsing with first-value query semantics.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use url::Url;

use crate::common::{
    CarrierEndpoint, DialPolicy, ServiceEndpoint, SocksCredentials, first_raw_query_value,
    format_host_port, parse_host_port, parse_socks_value, query_first,
};
use crate::transport::MorphKeys;

const VECTOR_QUERY_KEYS: &[&str] = &["in", "sni", "pin", "rate", "etar", "morph"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierMode {
    Tcp,
    Udp,
}

impl CarrierMode {
    pub(crate) const fn carrier(self) -> crate::protocol::Carrier {
        match self {
            Self::Tcp => crate::protocol::Carrier::TlsTcp,
            Self::Udp => crate::protocol::Carrier::Quic,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PortalClientConfig {
    pub(crate) handshake_timeout: Duration,
    pub(crate) remote: ServiceEndpoint,
    pub(crate) net: CarrierMode,
    pub(crate) morph: bool,
    pub(crate) morph_keys: Option<MorphKeys>,
    pub(crate) sni: Option<String>,
    pub(crate) pin: Option<String>,
    pub(crate) dial_policy: DialPolicy,
}

impl PortalClientConfig {
    pub(crate) fn parse(url: &Url, query: &HashMap<String, String>) -> Result<Self> {
        let context = match url.scheme() {
            "vector" => "vector endpoint",
            "egress" => "egress endpoint",
            "nowhere" => "share link endpoint",
            _ => bail!("unsupported client URL scheme"),
        };
        if url.password().is_some() || url.fragment().is_some() {
            bail!("invalid URL password or fragment");
        }
        let remote = ServiceEndpoint::parse(url, false, context)?;
        let net = match url.scheme() {
            "vector" => {
                if !url.path().is_empty() && remote.has_tcp() && remote.has_udp() {
                    bail!("{context}: path must declare exactly one carrier");
                }
                if remote.has_tcp() {
                    CarrierMode::Tcp
                } else {
                    CarrierMode::Udp
                }
            }
            "egress" => {
                if url.path().is_empty() {
                    CarrierMode::Udp
                } else if remote.has_tcp() != remote.has_udp() {
                    if remote.has_tcp() {
                        CarrierMode::Tcp
                    } else {
                        CarrierMode::Udp
                    }
                } else {
                    bail!("{context}: path must declare exactly one carrier");
                }
            }
            "nowhere" => match query.get("net").map(String::as_str) {
                None | Some("tcp") => CarrierMode::Tcp,
                Some("udp") => CarrierMode::Udp,
                Some(_) => bail!("share link net must be tcp or udp"),
            },
            _ => bail!("unsupported client URL scheme"),
        };
        let morph = match query.get("morph").map(String::as_str) {
            Some("0") => false,
            None | Some("1") => true,
            Some(_) => bail!("{context}: morph must be 0 or 1"),
        };
        if net == CarrierMode::Tcp && morph {
            crate::transport::validate_tcp_prelude_env()?;
        }
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
        if pin.as_ref().is_some_and(|pin| {
            pin.len() != 64
                || !pin
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) {
            bail!("pin must be 64 lowercase hex characters");
        }
        Ok(Self {
            handshake_timeout: crate::common::read_handshake_timeout(
                &mut crate::common::env_value,
                url,
            )?,
            remote,
            net,
            morph,
            morph_keys,
            sni,
            pin,
            dial_policy: DialPolicy::default(),
        })
    }

    pub(crate) fn from_probe_url(url: &Url) -> Result<(Self, crate::protocol::Credentials)> {
        if url.scheme() != "vector" {
            bail!("probe requires vector://");
        }
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        validate_options(&query)?;
        if first_raw_query_value(url, "in").is_some() {
            SocksListenConfig::from_url(url)?;
        }
        let credentials = crate::protocol::Credentials::new(url)?;
        Ok((Self::parse(url, &query)?, credentials))
    }

    pub(crate) fn from_fingerprint_url(url: &Url) -> Result<Self> {
        if url.scheme() != "nowhere" {
            bail!("fingerprint requires a nowhere:// share link");
        }
        crate::protocol::Credentials::validated_shared_key(url, "Fingerprint configuration")?;
        if !url.path().is_empty() {
            bail!("share links require HOST:PORT without carrier paths");
        }
        let mut clean = url.clone();
        clean.set_fragment(None);
        let query = query_first(&clean, &["net", "morph", "sni"])?;
        if !query.contains_key("morph") {
            bail!("fingerprint requires morph=0 or morph=1");
        }
        Self::parse(&clean, &query)
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksListenConfig {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) credentials: Option<SocksCredentials>,
}

impl SocksListenConfig {
    fn from_url(url: &Url) -> Result<Self> {
        let raw = first_raw_query_value(url, "in")
            .ok_or_else(|| anyhow!("Vector configuration: in parameter is required"))?;
        let (endpoint, credentials) = parse_socks_value(raw)?;
        let (host, port) = parse_host_port(&endpoint, "SOCKS ingress", true)?;
        Ok(Self {
            host,
            port,
            credentials,
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VectorConfig {
    pub(crate) portal: PortalClientConfig,
    pub(super) rate_mbps: i32,
    pub(super) etar_mbps: i32,
    pub(super) socks: SocksListenConfig,
}

impl std::ops::Deref for VectorConfig {
    type Target = PortalClientConfig;
    fn deref(&self) -> &Self::Target {
        &self.portal
    }
}

impl VectorConfig {
    pub(super) fn from_url(url: &Url) -> Result<Self> {
        let (portal, _) = PortalClientConfig::from_probe_url(url)?;
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        Ok(Self {
            portal,
            rate_mbps: parse_rate(query.get("rate").map(String::as_str), "rate")?,
            etar_mbps: parse_rate(query.get("etar").map(String::as_str), "etar")?,
            socks: SocksListenConfig::from_url(url)?,
        })
    }

    pub(crate) fn portal_client_config(&self) -> PortalClientConfig {
        self.portal.clone()
    }

    pub(super) fn effective_url(&self) -> String {
        format!(
            "vector://{}?in={}&sni={}&pin={}&morph={}&rate={}&etar={}",
            self.endpoint(),
            self.socks.endpoint(),
            self.sni.as_deref().unwrap_or(self.host()),
            self.pin.as_deref().unwrap_or("none"),
            u8::from(self.morph),
            self.rate_mbps,
            self.etar_mbps,
        )
    }
}

fn validate_options(query: &HashMap<String, String>) -> Result<()> {
    parse_rate(query.get("rate").map(String::as_str), "rate")?;
    parse_rate(query.get("etar").map(String::as_str), "etar")?;
    Ok(())
}

fn parse_rate(value: Option<&str>, name: &str) -> Result<i32> {
    match value {
        None => Ok(0),
        Some(s) => s
            .parse()
            .ok()
            .filter(|v| *v >= 0)
            .ok_or_else(|| anyhow!("{name} must be a non-negative integer")),
    }
}

#[cfg(test)]
#[path = "../tests/vector/config.rs"]
mod tests;
