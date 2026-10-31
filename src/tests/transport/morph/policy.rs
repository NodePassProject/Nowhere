// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP Prelude policy distributions and entropy failures.

use super::*;

#[test]
fn udp_policies_preserve_exact_ranges_and_fixed_fade_boundaries() {
    for value in 0..=u8::MAX {
        for policy in [
            PreludePolicy::Fade,
            PreludePolicy::Full8,
            PreludePolicy::Low7,
        ] {
            let mut calls = 0;
            let prelude: [u8; UDP_PRELUDE_LEN] = policy
                .generate_with(|bytes| {
                    calls += 1;
                    bytes.fill(if calls == 1 { value } else { 94 });
                    Ok(())
                })
                .unwrap();
            match policy {
                PreludePolicy::Fade => {
                    let ascii = 0x20 + if value < 190 { value % 95 } else { 94 };
                    assert_eq!(&prelude[..2], &[ascii; 2]);
                    assert_eq!(&prelude[2..10], &[value & 0x7f; 8]);
                    assert_eq!(&prelude[10..], &[value; 2]);
                    assert_eq!(calls, if value < 190 { 1 } else { 3 });
                }
                PreludePolicy::Full8 => assert_eq!(prelude, [value; UDP_PRELUDE_LEN]),
                PreludePolicy::Low7 => assert_eq!(prelude, [value & 0x7f; UDP_PRELUDE_LEN]),
            }
        }
    }
}

#[test]
fn udp_policy_propagates_initial_and_ascii_resampling_entropy_failures() {
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        let result: io::Result<[u8; UDP_PRELUDE_LEN]> =
            policy.generate_with(|_| Err(io::Error::other("entropy")));
        assert_eq!(result.unwrap_err().to_string(), "entropy");
    }
    let mut calls = 0;
    let result: io::Result<[u8; UDP_PRELUDE_LEN]> = PreludePolicy::Fade.generate_with(|bytes| {
        calls += 1;
        if calls == 1 {
            bytes.fill(255);
            Ok(())
        } else {
            Err(io::Error::other("resample"))
        }
    });
    assert_eq!(result.unwrap_err().to_string(), "resample");
}

#[test]
fn bounded_sampling_is_uniform_over_all_accepted_bytes_and_retries_rejections() {
    for (upper, accepted, multiplicity) in [(5u8, 255u16, 51), (17, 255, 15), (95, 190, 2)] {
        let mut counts = vec![0; usize::from(upper)];
        for input in 0..=u8::MAX {
            let mut retries = 0;
            let output = sample_below(input, upper, &mut |bytes| {
                retries += 1;
                bytes.fill(0);
                Ok(())
            })
            .unwrap();
            if u16::from(input) < accepted {
                assert_eq!(retries, 0);
                counts[usize::from(output)] += 1;
            } else {
                assert_eq!(retries, 1);
                assert_eq!(output, 0);
            }
        }
        assert_eq!(counts, vec![multiplicity; usize::from(upper)]);
    }
    let mut replacements = [255, 190, 94].into_iter();
    assert_eq!(
        sample_below(255, 95, &mut |bytes| {
            bytes[0] = replacements.next().unwrap();
            Ok(())
        })
        .unwrap(),
        94
    );
    assert!(replacements.next().is_none());
}
