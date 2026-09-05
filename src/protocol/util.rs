// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Small validation and URL-decoding helpers shared by fixed codecs.

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use url::Url;

/// Largest domain name accepted by the binary target codec.
pub const DOMAIN_LEN_MAX: usize = 253;

pub(super) fn decode_url_username(parsed_url: &Url) -> Result<Vec<u8>> {
    let username = parsed_url.username();
    let bytes = username.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!("malformed percent escape in shared key");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let decoded = percent_decode_str(username)
        .decode_utf8()
        .context("shared key is not valid UTF-8")?;
    Ok(decoded.as_bytes().to_vec())
}

pub(super) fn validate_port(port: u16, context: &str) -> Result<()> {
    if port == 0 {
        bail!("{context}: zero port");
    }
    Ok(())
}

pub(super) fn validate_domain_bytes(domain: &[u8], context: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > DOMAIN_LEN_MAX {
        bail!("{context}: invalid domain length: {}", domain.len());
    }
    if !domain.is_ascii() {
        bail!("{context}: domain is not ASCII/IDNA wire form");
    }
    for label in domain.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > 63 {
            bail!("{context}: invalid DNS label length");
        }
        if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
            bail!("{context}: DNS label begins or ends with hyphen");
        }
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            bail!("{context}: invalid DNS label bytes");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/protocol/util.rs"]
mod tests;
