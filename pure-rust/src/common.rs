//! Common utilities and constants used across different encryption modes.
//!
//! This module provides shared functionality for IP address handling and AES operations.
//! It includes the AES S-box, inverse S-box, round constants, and IP address conversion utilities.

use std::net::IpAddr;

/// Converts an IP address to its 16-byte representation.
///
/// For IPv4 addresses, this function creates an IPv4-mapped IPv6 address by:
/// - Setting the first 10 bytes to 0x00
/// - Setting bytes 10-11 to 0xFF
/// - Copying the 4 IPv4 address bytes to positions 12-15
///
/// For IPv6 addresses, it simply returns the 16-byte representation directly.
///
/// # Arguments
///
/// * `ip` - The IP address to convert
///
/// # Returns
///
/// A 16-byte array containing the address representation
pub fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ipv4) => {
            let mut bytes = [0u8; 16];
            bytes[10..12].copy_from_slice(&[0xFF; 2]); // Set IPv4-mapped prefix more efficiently
            bytes[12..16].copy_from_slice(&ipv4.octets());
            bytes
        }
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}

/// Converts a 16-byte representation back to an IP address.
///
/// This function detects whether the input represents an IPv4-mapped address or a native IPv6 address:
/// - If bytes 0-9 are 0x00 and bytes 10-11 are 0xFF, it's treated as an IPv4 address
/// - Otherwise, it's treated as an IPv6 address
///
/// # Arguments
///
/// * `bytes` - The 16-byte array to convert
///
/// # Returns
///
/// The corresponding IP address
pub fn bytes_to_ip(bytes: [u8; 16]) -> IpAddr {
    if bytes[..10].iter().all(|&b| b == 0) && bytes[10..12] == [0xFF; 2] {
        let mut ipv4_bytes = [0u8; 4];
        ipv4_bytes.copy_from_slice(&bytes[12..16]);
        IpAddr::V4(ipv4_bytes.into())
    } else {
        IpAddr::V6(bytes.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_conversion() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let bytes = ip_to_bytes(ipv4);
        assert_eq!(bytes_to_ip(bytes), ipv4);
    }

    #[test]
    fn test_ipv6_conversion() {
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let bytes = ip_to_bytes(ipv6);
        assert_eq!(bytes_to_ip(bytes), ipv6);
    }
}
