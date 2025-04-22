//! IP address encryption and obfuscation methods.
//!
//! This crate provides three encryption modes for IP addresses, allowing both deterministic
//! and non-deterministic encryption.
//!
//! # Features
//!
//! - `ipcrypt-deterministic`: A deterministic mode in which identical inputs always produce the same output—another IP address.
//! - `ipcrypt-nd`: A non-deterministic mode that uses an 8-byte tweak
//! - `ipcrypt-ndx`: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak
//!
//! # Examples
//!
//! ```rust
//! use ipcrypt_rs::{Ipcrypt, IpcryptNd, IpcryptNdx};
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! // Deterministic encryption
//! let key = [42u8; 16];
//! let ip = IpAddr::from_str("192.168.1.1").unwrap();
//! let cipher = Ipcrypt::new(key);
//! let encrypted = cipher.encrypt_ipaddr(ip);
//! let decrypted = cipher.decrypt_ipaddr(encrypted);
//! assert_eq!(ip, decrypted);
//!
//! // Non-deterministic encryption with automatic tweak generation
//! let cipher_nd = IpcryptNd::new(key);
//! let encrypted_bytes = cipher_nd.encrypt_ipaddr(ip, None);
//! let decrypted = cipher_nd.decrypt_ipaddr(&encrypted_bytes);
//! assert_eq!(ip, decrypted);
//! ```
//!
//! # Security Considerations
//!
//! - The deterministic mode is compact and facilitates integration, but allows correlation of encrypted addresses
//! - For general use cases, prefer the non-deterministic modes (`IpcryptNd` or `IpcryptNdx`)
//! - The extended mode (`IpcryptNdx`) provides the strongest security with a larger key and tweak size

pub(crate) mod aes;
pub(crate) mod common;
pub(crate) mod deterministic;
pub(crate) mod nd;
pub(crate) mod ndx;

pub use common::{bytes_to_ip, ip_to_bytes};
pub use deterministic::Ipcrypt;
pub use nd::IpcryptNd;
pub use ndx::IpcryptNdx;

pub mod reexports {
    pub use aes;
    pub use ct_codecs;
    pub use rand;
}
