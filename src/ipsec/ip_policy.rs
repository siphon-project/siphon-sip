//! The `ip xfrm policy` command lines of the `ip` backend, built apart from
//! running them so a test can read exactly what the kernel would be told.

use std::net::IpAddr;

use super::{host_prefix, IpsecError, IpsecManager, SaProtocol};

/// `ip xfrm policy add|update` for one policy. A `spi` of 0 leaves the
/// template's SPI out, which iproute2 sends as 0: any SA of the selector
/// satisfies it.
///
/// `proto X` precedes `sport`/`dport`: iproute2's UPSPEC grammar (man
/// ip-xfrm) takes the ports as sub-arguments of the protocol.
pub(super) fn policy_arguments(
    verb: &str,
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: &str,
    spi: u32,
    protocol: SaProtocol,
    hard_lifetime_secs: Option<u64>,
) -> Vec<String> {
    let mut arguments: Vec<String> = ["xfrm".to_string(), "policy".to_string(), verb.to_string()]
        .into_iter()
        .chain(selector_arguments(
            source,
            source_port,
            destination,
            destination_port,
            direction,
            protocol,
        ))
        .collect();
    arguments.extend(
        [
            "tmpl",
            "src",
            &source.to_string(),
            "dst",
            &destination.to_string(),
            "proto",
            "esp",
        ]
        .map(str::to_string),
    );
    if spi != 0 {
        arguments.extend(["spi".to_string(), format!("0x{spi:x}")]);
    }
    arguments.extend(["mode".to_string(), "transport".to_string()]);
    // Optional hard lifetime, so a policy reaps on the same deadline as its
    // states: `limit time-hard <secs>` sets lft.hard_add_expires_seconds.
    if let Some(secs) = hard_lifetime_secs {
        arguments.extend([
            "limit".to_string(),
            "time-hard".to_string(),
            secs.to_string(),
        ]);
    }
    arguments
}

/// `ip xfrm policy delete` for the policy with this selector and direction.
pub(super) fn policy_delete_arguments(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: &str,
    protocol: SaProtocol,
) -> Vec<String> {
    [
        "xfrm".to_string(),
        "policy".to_string(),
        "delete".to_string(),
    ]
    .into_iter()
    .chain(selector_arguments(
        source,
        source_port,
        destination,
        destination_port,
        direction,
        protocol,
    ))
    .collect()
}

fn selector_arguments(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: &str,
    protocol: SaProtocol,
) -> [String; 12] {
    [
        "src".to_string(),
        format!("{}/{}", source, host_prefix(source)),
        "dst".to_string(),
        format!("{}/{}", destination, host_prefix(destination)),
        "proto".to_string(),
        protocol.as_str().to_string(),
        "sport".to_string(),
        source_port.to_string(),
        "dport".to_string(),
        destination_port.to_string(),
        "dir".to_string(),
        direction.to_string(),
    ]
}

impl IpsecManager {
    /// Run `ip` with `arguments`.
    pub(super) async fn run_ip_arguments(arguments: &[String]) -> Result<(), IpsecError> {
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        Self::run_ip_command(&borrowed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an IP literal")
    }

    #[test]
    fn a_pinned_template_names_its_spi_and_an_open_one_names_none() {
        let pinned = policy_arguments(
            "add",
            &ip("198.51.100.10"),
            5064,
            &ip("192.0.2.77"),
            6101,
            "in",
            0x1_2345,
            SaProtocol::Any,
            Some(240),
        );
        assert_eq!(
            pinned.join(" "),
            "xfrm policy add src 198.51.100.10/32 dst 192.0.2.77/32 proto any sport 5064 \
             dport 6101 dir in tmpl src 198.51.100.10 dst 192.0.2.77 proto esp spi 0x12345 \
             mode transport limit time-hard 240"
        );
        let open = policy_arguments(
            "update",
            &ip("198.51.100.10"),
            5064,
            &ip("192.0.2.77"),
            6101,
            "in",
            0,
            SaProtocol::Any,
            None,
        );
        assert_eq!(
            open.join(" "),
            "xfrm policy update src 198.51.100.10/32 dst 192.0.2.77/32 proto any sport 5064 \
             dport 6101 dir in tmpl src 198.51.100.10 dst 192.0.2.77 proto esp mode transport"
        );
    }

    #[test]
    fn a_delete_names_the_selector_and_direction_only() {
        let arguments = policy_delete_arguments(
            &ip("2001:db8::7"),
            6101,
            &ip("2001:db8::10"),
            5064,
            "out",
            SaProtocol::Udp,
        );
        assert_eq!(
            arguments.join(" "),
            "xfrm policy delete src 2001:db8::7/128 dst 2001:db8::10/128 proto udp sport 6101 \
             dport 5064 dir out"
        );
    }
}
