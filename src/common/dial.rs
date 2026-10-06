// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Outbound address-family policy and source address selection.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DialPolicy {
    Legacy(Option<IpAddr>),
    DualStack {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    },
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self::Legacy(None)
    }
}

impl DialPolicy {
    pub(crate) fn from_query(query: &HashMap<String, String>) -> Result<Self> {
        let dial = query.get("dial");
        let has_families = query.contains_key("dial4") || query.contains_key("dial6");
        if dial.is_some() && has_families {
            bail!("dial and dial4/dial6 are mutually exclusive");
        }
        if has_families {
            let v4 = match query.get("dial4").map(String::as_str) {
                None | Some("auto") => None,
                Some(value) => Some(
                    value
                        .parse::<Ipv4Addr>()
                        .map_err(|_| anyhow::anyhow!("dial4 must be auto or an IPv4 literal"))?,
                ),
            };
            let v6 = match query.get("dial6").map(String::as_str) {
                None | Some("auto") => None,
                Some(value) => {
                    let ip = value
                        .parse::<Ipv6Addr>()
                        .map_err(|_| anyhow::anyhow!("dial6 must be auto or an IPv6 literal"))?;
                    if ip.to_ipv4_mapped().is_some() {
                        bail!("dial6 must not be an IPv4-mapped IPv6 address");
                    }
                    Some(ip)
                }
            };
            Ok(Self::DualStack { v4, v6 })
        } else {
            match dial.map(String::as_str) {
                None | Some("auto") => Ok(Self::default()),
                Some(value) => {
                    Ok(Self::Legacy(Some(value.parse::<IpAddr>().map_err(
                        |_| anyhow::anyhow!("dial must be auto or an IP literal"),
                    )?)))
                }
            }
        }
    }

    pub(crate) fn accepts(&self, target: IpAddr) -> bool {
        match self {
            Self::Legacy(Some(source)) => source.is_ipv4() == target.is_ipv4(),
            _ => true,
        }
    }

    pub(crate) fn local_ip(&self, target: IpAddr) -> Result<Option<IpAddr>> {
        if !self.accepts(target) {
            bail!("target address family conflicts with dial");
        }
        Ok(match self {
            Self::Legacy(source) => *source,
            Self::DualStack { v4, .. } if target.is_ipv4() => v4.map(IpAddr::V4),
            Self::DualStack { v6, .. } => v6.map(IpAddr::V6),
        })
    }
}

impl fmt::Display for DialPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(source) => write!(
                formatter,
                "dial={}",
                source.map_or_else(|| "auto".to_owned(), |ip| ip.to_string())
            ),
            Self::DualStack { v4, v6 } => write!(
                formatter,
                "dial4={} dial6={}",
                v4.map_or_else(|| "auto".to_owned(), |ip| ip.to_string()),
                v6.map_or_else(|| "auto".to_owned(), |ip| ip.to_string())
            ),
        }
    }
}

#[cfg(test)]
#[path = "../tests/common/dial.rs"]
mod tests;
