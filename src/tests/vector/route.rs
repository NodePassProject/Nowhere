use super::*;

use crate::protocol::Carrier::{Quic as Q, TlsTcp as T};

fn route(up: CarrierMode, down: CarrierMode, choose_quic: bool) -> ResolvedRoute {
    resolve_with_choice(up, down, choose_quic)
}

#[test]
fn resolves_all_configured_pairs() {
    use CarrierMode::{Mix, Tcp, Udp};

    let cases = [
        (
            Tcp,
            Tcp,
            ResolvedRoute {
                uplink: T,
                downlink: T,
            },
            ResolvedRoute {
                uplink: T,
                downlink: T,
            },
        ),
        (
            Tcp,
            Udp,
            ResolvedRoute {
                uplink: T,
                downlink: Q,
            },
            ResolvedRoute {
                uplink: T,
                downlink: Q,
            },
        ),
        (
            Udp,
            Tcp,
            ResolvedRoute {
                uplink: Q,
                downlink: T,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: T,
            },
        ),
        (
            Udp,
            Udp,
            ResolvedRoute {
                uplink: Q,
                downlink: Q,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: Q,
            },
        ),
        (
            Mix,
            Tcp,
            ResolvedRoute {
                uplink: T,
                downlink: T,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: T,
            },
        ),
        (
            Mix,
            Udp,
            ResolvedRoute {
                uplink: T,
                downlink: Q,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: Q,
            },
        ),
        (
            Tcp,
            Mix,
            ResolvedRoute {
                uplink: T,
                downlink: T,
            },
            ResolvedRoute {
                uplink: T,
                downlink: Q,
            },
        ),
        (
            Udp,
            Mix,
            ResolvedRoute {
                uplink: Q,
                downlink: T,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: Q,
            },
        ),
        (
            Mix,
            Mix,
            ResolvedRoute {
                uplink: T,
                downlink: T,
            },
            ResolvedRoute {
                uplink: Q,
                downlink: Q,
            },
        ),
    ];

    for (up, down, tcp, quic) in cases {
        assert_eq!(route(up, down, false), tcp, "up={up} down={down}");
        assert_eq!(route(up, down, true), quic, "up={up} down={down}");
    }
}

#[test]
fn route_plan_is_stable_and_uses_the_other_allowed_route_as_fallback() {
    use CarrierMode::{Mix, Tcp};

    let seed = seed_from_session([0x5a; crate::protocol::SESSION_ID_LEN]);
    let first = plan_route(Mix, Tcp, seed, 7);
    let repeated = plan_route(Mix, Tcp, seed, 7);
    assert_eq!(first, repeated);
    assert_ne!(first.primary, first.fallback.unwrap());

    let fixed = plan_route(Tcp, Tcp, seed, 7);
    assert_eq!(
        fixed.primary,
        ResolvedRoute {
            uplink: T,
            downlink: T
        }
    );
    assert_eq!(fixed.fallback, None);
}

#[test]
fn mix_mix_never_resolves_to_a_split_route() {
    for flow_id in 1..=1024 {
        let plan = plan_route(CarrierMode::Mix, CarrierMode::Mix, 0x1234, flow_id);
        assert!(!plan.primary.split());
        assert!(!plan.fallback.unwrap().split());
        assert_ne!(plan.primary, plan.fallback.unwrap());
    }
}
