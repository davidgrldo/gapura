//! Which address a request really came from, when something sits in front of us.

use std::net::IpAddr;
use std::str::FromStr;

/// A network of addresses: one we accept `X-Forwarded-For` from (`--trusted-proxy`), or an entry
/// in an ip_restriction policy's allow or deny list.
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

/// `addr/bits`, the form `from_str` reads, a bare address included: what a policy's networks
/// look like on the wire, in the disk cache and in the console.
impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl serde::Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// From the text `from_str` reads, so a network that does not parse fails the whole
/// configuration rather than being left out of a list: a deny list missing an entry admits it.
impl<'de> serde::Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl Cidr {
    /// Whether `ip` is in this network, in either of the forms an IPv4 address takes (#216): an
    /// IPv4-mapped IPv6 address (`::ffff:10.0.0.5`, how a dual-stack `[::]` listener sees an
    /// IPv4 peer) is the IPv4 address it stands for, so a v4 network holds it, and an IPv4 address
    /// is in a v6 network that holds its mapped form. So trust does not depend on which socket
    /// the proxy arrived on, or on whether the address was canonicalised first.
    ///
    /// An IPv6 network reaches an IPv4 address only when it lies inside the mapped range
    /// `::ffff:0:0/96`, which is a prefix of at least 96 bits on a mapped address
    /// (`::ffff:0:0/96`, `::ffff:10.0.0.0/104`). A shorter prefix such as `::/0` or
    /// `2001:db8::/32` means "these IPv6 addresses": reading `::/0` as every IPv4 address too would
    /// let an `allow` of `::/0` admit every IPv4 client, and a `deny` of it turn away all of them.
    /// The same rule applies to `--trusted-proxy`, where it trusts less than the mapped reading
    /// did, never more.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V6(net), IpAddr::V4(v4)) => {
                self.bits >= 96
                    && net.to_ipv4_mapped().is_some()
                    && self.contains_exactly(IpAddr::V6(v4.to_ipv6_mapped()))
            }
            (_, ip) => self.contains_exactly(ip),
        }
    }

    fn contains_exactly(&self, ip: IpAddr) -> bool {
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
///
/// Every address, the peer and each hop alike, is canonicalised first (#216): an IPv4 client
/// seen through a dual-stack `[::]` socket, or written mapped by a proxy, is `::ffff:a.b.c.d`,
/// and is both trusted and reported as the IPv4 address it is.
pub fn client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &[Cidr],
    named: Option<&str>,
) -> IpAddr {
    let trusts = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    let peer = peer.to_canonical();
    if !trusts(peer) {
        return peer;
    }
    let Some(chain) = forwarded_for else {
        return named_header_ip(named).unwrap_or(peer);
    };
    // Right to left, so `leftmost` ends up holding the far end of the chain.
    let mut leftmost = None;
    for hop in chain.rsplit(',') {
        let Ok(ip) = hop.trim().parse::<IpAddr>().map(|ip| ip.to_canonical()) else {
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
    named?
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
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
    fn a_mapped_v4_peer_is_trusted_by_a_v4_network() {
        // #216: on a dual-stack `[::]` listener an IPv4 load balancer at 10.0.0.5 arrives as
        // `::ffff:10.0.0.5`. Untrusted, every client became the load balancer.
        let got = client_ip(
            ip("::ffff:10.0.0.5"),
            Some("198.51.100.5"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("198.51.100.5"));
        // Mapped hops are walked as the v4 addresses they are, and reported that way.
        let got = client_ip(
            ip("::ffff:10.0.0.5"),
            Some("::ffff:198.51.100.5, ::ffff:10.0.0.110"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("198.51.100.5"));
        // An untrusted mapped peer is still the client, reported as v4.
        let got = client_ip(
            ip("::ffff:203.0.113.9"),
            Some("1.2.3.4"),
            &nets(&["10.0.0.0/8"]),
            None,
        );
        assert_eq!(got, ip("203.0.113.9"));
        let got = client_ip(
            ip("::ffff:10.0.0.5"),
            None,
            &nets(&["10.0.0.0/8"]),
            Some("::ffff:198.51.100.7"),
        );
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn a_mapped_address_is_in_the_v4_network_it_stands_for() {
        let v4: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(v4.contains(ip("::ffff:10.1.2.3")));
        assert!(!v4.contains(ip("::ffff:11.1.2.3")));
        // A v6 network naming the mapped range keeps matching it, in either form, so
        // canonicalising the peer first never takes trust away.
        let mapped: Cidr = "::ffff:0:0/96".parse().unwrap();
        assert!(mapped.contains(ip("::ffff:10.1.2.3")));
        assert!(mapped.contains(ip("10.1.2.3")));
        let got = client_ip(ip("::ffff:10.0.0.5"), Some("198.51.100.5"), &[mapped], None);
        assert_eq!(got, ip("198.51.100.5"));
    }

    #[test]
    fn an_ipv6_network_shorter_than_the_mapped_range_holds_no_ipv4_address() {
        for net in ["::/0", "2001:db8::/32"] {
            let net: Cidr = net.parse().unwrap();
            assert!(net.contains(ip("2001:db8::1")), "{net}");
            assert!(!net.contains(ip("192.0.2.1")), "{net}");
            assert!(!net.contains(ip("::ffff:192.0.2.1")), "{net}");
        }
    }

    #[test]
    fn an_ipv6_network_inside_the_mapped_range_holds_the_ipv4_addresses_it_names() {
        // Past the 96 mapped bits each further bit is a bit of the IPv4 address, so /104 is the
        // IPv4 /8 and /112 the IPv4 /16.
        let net: Cidr = "::ffff:10.0.0.0/104".parse().unwrap();
        assert!(net.contains(ip("10.0.0.5")));
        assert!(net.contains(ip("::ffff:10.0.0.5")));
        assert!(net.contains(ip("10.1.0.0")));
        assert!(!net.contains(ip("11.0.0.0")));
        assert!(!net.contains(ip("::ffff:11.0.0.0")));
        let narrower: Cidr = "::ffff:10.0.0.0/112".parse().unwrap();
        assert!(narrower.contains(ip("10.0.0.5")));
        assert!(narrower.contains(ip("::ffff:10.0.0.5")));
        assert!(!narrower.contains(ip("10.1.0.0")));
        assert!(!narrower.contains(ip("::ffff:10.1.0.0")));
    }

    #[test]
    fn an_ipv4_network_holds_the_mapped_form_of_its_addresses() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains(ip("::ffff:10.0.0.5")));
        assert!(!net.contains(ip("::ffff:11.0.0.5")));
    }

    #[test]
    fn a_prefix_wider_than_the_address_is_refused() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nonsense".parse::<Cidr>().is_err());
    }

    /// A policy carries its networks on the wire and in the disk cache as the text an operator
    /// wrote, a bare address as the network of one it stands for.
    #[test]
    fn a_network_is_written_and_read_as_text() {
        let written =
            serde_json::to_value(nets(&["10.0.0.0/8", "2001:db8::1", "::ffff:10.0.0.5/128"]))
                .unwrap();
        assert_eq!(
            written,
            serde_json::json!(["10.0.0.0/8", "2001:db8::1/128", "::ffff:10.0.0.5/128"])
        );
        let back: Vec<Cidr> = serde_json::from_value(written).unwrap();
        assert_eq!(
            back,
            nets(&["10.0.0.0/8", "2001:db8::1", "::ffff:10.0.0.5/128"])
        );
        for bad in ["10.0.0.0/33", "nope", "10.0.0.0/"] {
            assert!(
                serde_json::from_value::<Cidr>(serde_json::json!(bad)).is_err(),
                "{bad}"
            );
        }
    }
}
