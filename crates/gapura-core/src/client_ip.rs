//! Which address a request really came from, when something sits in front of us.

use std::net::IpAddr;
use std::str::FromStr;

/// A network we accept `X-Forwarded-For` from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u32,
}

impl FromStr for Cidr {
    type Err = String;

    /// `10.0.0.0/8`, or a bare address standing for a network of one.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (text, prefix) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = text
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address"))?;
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match prefix {
            None => width,
            Some(b) => b
                .parse()
                .ok()
                .filter(|b| *b <= width)
                .ok_or_else(|| format!("{b:?} is not a prefix length for {addr}"))?,
        };
        Ok(Cidr { addr, bits })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                same_prefix(u32::from(net).into(), u32::from(ip).into(), self.bits, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                same_prefix(u128::from(net), u128::from(ip), self.bits, 128)
            }
            // A v4 address is never inside a v6 network, nor the other way round.
            _ => false,
        }
    }
}

fn same_prefix(a: u128, b: u128, bits: u32, width: u32) -> bool {
    bits == 0 || (a >> (width - bits)) == (b >> (width - bits))
}

/// The address to log as the client.
///
/// `X-Forwarded-For` is written by whoever felt like it, so it is only read when the connection
/// itself came from a network we trust, and then only as far as the trust reaches: walking the
/// chain from the right, the first address no trusted proxy vouches for is the client. Anything a
/// caller wrote itself sits further left than that and is never reached. With no trusted network
/// configured the header is ignored entirely, which is the behaviour to keep by default.
///
/// `named` is the value of a configured single-IP header such as `CF-Connecting-IP` or
/// `X-Real-IP`, read by the caller from the request. It is consulted only when no XFF chain is
/// present at all -- the shape of a CDN whose tunnel names the client nowhere else -- and the
/// same rule guards it: the peer must be trusted for the header to be believed, since any caller
/// can write these headers too. When a chain exists it keeps its precedence, including the
/// all-trusted chain that resolves to its own first address. An unparseable value is ignored,
/// the way an unparseable XFF hop is skipped.
pub fn client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &[Cidr],
    named: Option<&str>,
) -> IpAddr {
    let trusts = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !trusts(peer) {
        return peer;
    }
    let Some(chain) = forwarded_for else {
        return named_header_ip(named).unwrap_or(peer);
    };
    // Right to left, so `leftmost` ends up holding the far end of the chain.
    let mut leftmost = None;
    for hop in chain.rsplit(',') {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            continue;
        };
        if !trusts(ip) {
            return ip;
        }
        leftmost = Some(ip);
    }
    // Every hop was trusted, so the chain names no client this deployment can believe.
    leftmost.unwrap_or_else(|| named_header_ip(named).unwrap_or(peer))
}

fn named_header_ip(named: Option<&str>) -> Option<IpAddr> {
    named?.trim().parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn nets(v: &[&str]) -> Vec<Cidr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn without_a_trusted_network_the_peer_is_the_client() {
        // The safe default: no configuration means the header is never believed.
        let got = client_ip(ip("10.0.0.7"), Some("1.2.3.4"), &[], None);
        assert_eq!(got, ip("10.0.0.7"));
    }

    #[test]
    fn a_peer_we_do_not_trust_cannot_name_the_client() {
        // Anyone may send this header. Only a proxy we trust is allowed to be believed.
        let got = client_ip(
            ip("203.0.113.9"),
            Some("1.2.3.4"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn the_client_is_the_last_address_the_chain_does_not_vouch_for() {
        let got = client_ip(
            ip("10.0.0.253"),
            Some("198.51.100.5, 10.0.0.110"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("198.51.100.5"));
    }

    #[test]
    fn an_address_a_client_put_there_itself_is_never_reached() {
        // The client sent "1.2.3.4"; the proxy then appended where it really came from.
        let got = client_ip(
            ip("10.0.0.253"),
            Some("1.2.3.4, 198.51.100.5"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("198.51.100.5"));
    }

    #[test]
    fn a_chain_that_is_trusted_end_to_end_resolves_to_its_first_address() {
        let got = client_ip(
            ip("10.0.0.253"),
            Some("10.0.0.4, 10.0.0.110"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("10.0.0.4"));
    }

    #[test]
    fn a_named_header_is_believed_when_the_peer_is_trusted_and_no_xff_exists() {
        // The CDN-tunnel shape: X-Forwarded-For absent, CF-Connecting-IP carries the visitor.
        let got = client_ip(
            ip("10.0.0.253"),
            None,
            &nets(&["10.0.0.0/8"]),
            Some("198.51.100.7"),
        );
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn a_named_header_never_overrides_a_chain_that_names_a_client() {
        let got = client_ip(
            ip("10.0.0.253"),
            Some("198.51.100.5, 10.0.0.110"),
            &nets(&["10.0.0.0/8"]),
            Some("203.0.113.1"),
        );
        assert_eq!(got, ip("198.51.100.5"));
    }

    #[test]
    fn a_named_header_from_a_peer_we_do_not_trust_is_ignored() {
        // Same rule as the chain: anyone may write the header, only a trusted peer is believed.
        let got = client_ip(
            ip("203.0.113.9"),
            None,
            &nets(&["10.0.0.0/8"]),
            Some("198.51.100.7"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn an_unparseable_named_header_is_ignored() {
        let got = client_ip(
            ip("10.0.0.253"),
            None,
            &nets(&["10.0.0.0/8"]),
            Some("not-an-ip"),
        );
        assert_eq!(got, ip("10.0.0.253"));
    }

    #[test]
    fn a_trusted_peer_that_forwarded_nothing_is_itself_the_client() {
        let got = client_ip(ip("10.0.0.253"), None, &nets(&["10.0.0.0/8"]), None);
        assert_eq!(got, ip("10.0.0.253"));
    }

    #[test]
    fn a_bare_address_is_a_network_of_one() {
        let one: Cidr = "10.0.0.1".parse().unwrap();
        assert!(one.contains(ip("10.0.0.1")));
        assert!(!one.contains(ip("10.0.0.2")));
    }

    #[test]
    fn a_prefix_covers_the_addresses_under_it() {
        let net: Cidr = "10.1.0.0/16".parse().unwrap();
        assert!(net.contains(ip("10.1.255.9")));
        assert!(!net.contains(ip("10.2.0.1")));
    }

    #[test]
    fn v6_and_v4_never_match_each_other() {
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8::1")));
        assert!(!v6.contains(ip("10.0.0.1")));
        let v4: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(!v4.contains(ip("2001:db8::1")));
    }

    #[test]
    fn a_prefix_wider_than_the_address_is_refused() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nonsense".parse::<Cidr>().is_err());
    }
}
