// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated parsing and redacted display for the `socks` URL parameter.

use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use percent_encoding::percent_decode_str;
use url::Url;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SocksCredentials {
    username: String,
    password: String,
}

impl fmt::Debug for SocksCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocksCredentials(<redacted>)")
    }
}

impl SocksCredentials {
    pub(crate) fn as_pair(&self) -> (&str, &str) {
        (&self.username, &self.password)
    }
}

/// Validated SOCKS5 endpoint and optional RFC 1929 credentials.
#[derive(Clone)]
pub(crate) struct SocksConfig {
    host: String,
    port: u16,
    credentials: Option<SocksCredentials>,
}

impl fmt::Debug for SocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksConfig")
            .field("endpoint", &self.endpoint())
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

impl SocksConfig {
    /// Parses the first raw `socks` query value without decoding delimiters first.
    pub(crate) fn from_url(parsed_url: &Url) -> Result<Option<Self>> {
        let Some(raw_value) = first_raw_socks_value(parsed_url) else {
            return Ok(None);
        };
        let (endpoint, credentials) = parse_socks_value(raw_value)?;
        if credentials.is_none() && (endpoint.is_empty() || endpoint == "none") {
            return Ok(None);
        }
        let (host, port) = parse_host_port(&endpoint, "socks endpoint", false)?;
        Ok(Some(Self {
            host,
            port,
            credentials,
        }))
    }

    /// Returns the credential-free endpoint used in operator output.
    pub(crate) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    pub(super) fn credentials(&self) -> Option<(&str, &str)> {
        self.credentials
            .as_ref()
            .map(|value| (value.username.as_str(), value.password.as_str()))
    }
}

pub(crate) fn first_raw_socks_value(parsed_url: &Url) -> Option<&str> {
    let query = parsed_url.query()?;
    for pair in query.split('&') {
        let (raw_key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_component(raw_key, "query key").is_ok_and(|key| key == "socks") {
            return Some(value);
        }
    }
    None
}

pub(crate) fn parse_socks_value(raw_value: &str) -> Result<(String, Option<SocksCredentials>)> {
    let Some((raw_credentials, raw_endpoint)) = raw_value.split_once('@') else {
        return Ok((decode_component(raw_value, "socks endpoint")?, None));
    };
    if raw_endpoint.contains('@') {
        bail!("invalid socks credentials: expected USERNAME:PASSWORD@HOST:PORT");
    }
    let (raw_username, raw_password) = raw_credentials.split_once(':').ok_or_else(|| {
        anyhow!("invalid socks credentials: expected USERNAME:PASSWORD@HOST:PORT")
    })?;
    if raw_password.contains(':') {
        bail!("reserved characters in socks credentials must be percent-encoded");
    }
    validate_raw_credential(raw_username)?;
    validate_raw_credential(raw_password)?;
    let username = decode_component(raw_username, "socks username")?;
    let password = decode_component(raw_password, "socks password")?;
    validate_credential("username", &username)?;
    validate_credential("password", &password)?;
    Ok((
        decode_component(raw_endpoint, "socks endpoint")?,
        Some(SocksCredentials { username, password }),
    ))
}

pub(crate) fn parse_host_port(
    value: &str,
    name: &str,
    allow_empty_host: bool,
) -> Result<(String, u16)> {
    let (host, raw_port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid {name}: missing closing ']'"))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("invalid {name}: expected ':' followed by a port"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            bail!("invalid {name}: brackets may only contain an IPv6 address");
        }
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid {name}: expected HOST:PORT"))?;
        if host.contains(':') {
            bail!("invalid {name}: IPv6 addresses must be enclosed in brackets");
        }
        (host, port)
    };
    if host.is_empty() && !allow_empty_host {
        bail!("invalid {name}: host must not be empty");
    }
    let port = raw_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("invalid {name}: port must be in 1..=65535"))?;
    Ok((host.to_string(), port))
}

pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn validate_credential(name: &str, value: &str) -> Result<()> {
    if !(1..=u8::MAX as usize).contains(&value.len()) {
        bail!("socks {name} length must be in 1..=255 bytes");
    }
    Ok(())
}

fn validate_raw_credential(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| b":/?#[]@!$&'()*+,;=".contains(&byte))
    {
        bail!("reserved characters in socks credentials must be percent-encoded");
    }
    Ok(())
}

fn decode_component(raw: &str, name: &str) -> Result<String> {
    validate_percent_encoding(raw, name)?;
    percent_decode_str(raw)
        .decode_utf8()
        .with_context(|| format!("invalid UTF-8 in {name}"))
        .map(|value| value.into_owned())
}

fn validate_percent_encoding(raw: &str, name: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!("invalid percent encoding in {name}");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}
