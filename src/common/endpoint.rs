// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Portal service endpoint URL grammar.

use std::fmt;
use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressFamily {
    Any,
    V4,
    V6,
}

impl AddressFamily {
    pub(crate) const fn accepts(self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => ip.is_ipv4(),
            Self::V6 => ip.is_ipv6(),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Any => "",
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierEndpoint {
    pub(crate) port: u16,
    pub(crate) family: AddressFamily,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceEndpoint {
    pub(crate) host: String,
    pub(crate) tcp: Option<CarrierEndpoint>,
    pub(crate) udp: Option<CarrierEndpoint>,
}

impl ServiceEndpoint {
    pub(crate) fn parse(url: &Url, allow_wildcard: bool, context: &str) -> Result<Self> {
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| anyhow!("{context}: missing host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        if host == "*" && !allow_wildcard {
            bail!("{context}: wildcard host is only valid for Portal listeners");
        }

        let (tcp, udp) = if url.path().is_empty() {
            let port = required_port(url.port(), context)?;
            let endpoint = CarrierEndpoint {
                port,
                family: AddressFamily::Any,
            };
            (Some(endpoint), Some(endpoint))
        } else {
            if url.port().is_some() {
                bail!(
                    "{context}: choose either HOST:PORT or HOST/CARRIER:PORT; authority port and carrier path cannot be combined"
                );
            }
            parse_carrier_path(url.path(), context)?
        };

        let endpoint = Self { host, tcp, udp };
        endpoint.validate_literal_families(context)?;
        Ok(endpoint)
    }

    fn validate_literal_families(&self, context: &str) -> Result<()> {
        let Ok(ip) = self.host.parse::<IpAddr>() else {
            return Ok(());
        };
        for endpoint in [self.tcp, self.udp].into_iter().flatten() {
            if !endpoint.family.accepts(ip) {
                bail!("{context}: address family does not match host {ip}");
            }
        }
        Ok(())
    }

    pub(crate) const fn has_tcp(&self) -> bool {
        self.tcp.is_some()
    }

    pub(crate) const fn has_udp(&self) -> bool {
        self.udp.is_some()
    }

    pub(crate) fn carrier_addr(&self, endpoint: CarrierEndpoint) -> String {
        format_host_port(&self.host, endpoint.port)
    }

    pub(crate) fn canonical(&self) -> String {
        if let (Some(tcp), Some(udp)) = (self.tcp, self.udp)
            && tcp.family == AddressFamily::Any
            && udp.family == AddressFamily::Any
            && tcp.port == udp.port
        {
            return format_host_port(&self.host, tcp.port);
        }
        let mut value = format_host(&self.host);
        if let Some(tcp) = self.tcp {
            value.push_str(&format!("/tcp{}:{}", tcp.family.suffix(), tcp.port));
        }
        if let Some(udp) = self.udp {
            value.push_str(&format!("/udp{}:{}", udp.family.suffix(), udp.port));
        }
        value
    }
}

/// Validates the endpoint path before `url::Url` can normalize dot segments.
///
/// Other URL structure remains the responsibility of the standard parser.
pub fn validate_endpoint_url_input(raw: &str, context: &str) -> Result<()> {
    let Some((scheme, remainder)) = raw.split_once("://") else {
        return Ok(());
    };
    if !scheme.eq_ignore_ascii_case("portal") && !scheme.eq_ignore_ascii_case("vector") {
        return Ok(());
    }
    let endpoint = remainder
        .split_once(['?', '#'])
        .map_or(remainder, |(endpoint, _)| endpoint);
    let Some(path_start) = endpoint.find('/') else {
        return Ok(());
    };
    parse_carrier_path(&endpoint[path_start..], context).map(|_| ())
}

fn parse_carrier_path(
    path: &str,
    context: &str,
) -> Result<(Option<CarrierEndpoint>, Option<CarrierEndpoint>)> {
    let raw = path
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("{context}: carrier path must start with '/'"))?;
    if raw.is_empty() || raw.ends_with('/') || raw.split('/').any(str::is_empty) {
        bail!("{context}: carrier path must not contain empty segments or a trailing slash");
    }
    let mut tcp = None;
    let mut udp = None;
    for segment in raw.split('/') {
        if is_dot_segment(segment) {
            bail!("{context}: carrier path must not contain '.' or '..' segments");
        }
        let (carrier, raw_port) = segment.split_once(':').ok_or_else(|| {
            anyhow!("{context}: carrier segment {segment:?} must use CARRIER:PORT")
        })?;
        if raw_port.is_empty() || !raw_port.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("{context}: carrier port in {segment:?} must contain decimal digits only");
        }
        let port = raw_port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| anyhow!("{context}: carrier port must be in 1..=65535"))?;
        let (name, slot, family) = match carrier {
            "tcp" => ("TCP", &mut tcp, AddressFamily::Any),
            "tcp4" => ("TCP", &mut tcp, AddressFamily::V4),
            "tcp6" => ("TCP", &mut tcp, AddressFamily::V6),
            "udp" => ("UDP", &mut udp, AddressFamily::Any),
            "udp4" => ("UDP", &mut udp, AddressFamily::V4),
            "udp6" => ("UDP", &mut udp, AddressFamily::V6),
            _ => bail!(
                "{context}: unknown carrier {carrier:?}; expected tcp, tcp4, tcp6, udp, udp4, or udp6"
            ),
        };
        if slot.is_some() {
            bail!("{context}: {name} carrier is declared more than once");
        }
        *slot = Some(CarrierEndpoint { port, family });
    }
    Ok((tcp, udp))
}

fn is_dot_segment(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        "." | ".." | "%2e" | ".%2e" | "%2e." | "%2e%2e"
    )
}

impl fmt::Display for ServiceEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical())
    }
}

fn required_port(port: Option<u16>, context: &str) -> Result<u16> {
    port.filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("{context}: compact endpoint requires a port in 1..=65535"))
}

pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        Ok(IpAddr::V4(ip)) => format!("{ip}:{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

fn format_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => host.to_owned(),
    }
}

#[cfg(test)]
#[path = "../tests/common/endpoint.rs"]
mod tests;
