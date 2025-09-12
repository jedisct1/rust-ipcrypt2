//! IP address encryption and obfuscation methods.
//!
//! This crate provides four encryption modes for IP addresses, allowing both deterministic
//! and non-deterministic encryption, as well as prefix-preserving encryption.
//!
//! # Features
//!
//! - `ipcrypt-deterministic`: A deterministic mode in which identical inputs always produce the same output—another IP address.
//! - `ipcrypt-pfx`: A prefix-preserving deterministic mode that maintains network structure in encrypted addresses
//! - `ipcrypt-nd`: A non-deterministic mode that uses an 8-byte tweak
//! - `ipcrypt-ndx`: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak
//!
//! # Examples
//!
//! ```rust
//! use ipcrypt_rs::{Ipcrypt, IpcryptPfx, IpcryptNd, IpcryptNdx};
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! // Deterministic encryption
//! # #[cfg(feature = "random")]
//! let key = Ipcrypt::generate_key();
//! # #[cfg(not(feature = "random"))]
//! # let key = [0u8; 16];
//! let ip = IpAddr::from_str("192.168.1.1").unwrap();
//! let cipher = Ipcrypt::new(key);
//! let encrypted = cipher.encrypt_ipaddr(ip);
//! let decrypted = cipher.decrypt_ipaddr(encrypted);
//! assert_eq!(ip, decrypted);
//!
//! // Prefix-preserving encryption
//! # #[cfg(feature = "random")]
//! let pfx_key = IpcryptPfx::generate_key();
//! # #[cfg(not(feature = "random"))]
//! # let pfx_key = {
//! #     let mut key = [0u8; 32];
//! #     key[0] = 1; // Make the two halves different
//! #     key
//! # };
//! let cipher_pfx = IpcryptPfx::new(pfx_key);
//! let encrypted_pfx = cipher_pfx.encrypt_ipaddr(ip);
//! let decrypted_pfx = cipher_pfx.decrypt_ipaddr(encrypted_pfx);
//! assert_eq!(ip, decrypted_pfx);
//!
//! // Non-deterministic encryption with a provided tweak
//! let cipher_nd = IpcryptNd::new(key);
//! let tweak = [2u8; 8];
//! let encrypted_bytes = cipher_nd.encrypt_ipaddr(ip, Some(tweak));
//! let decrypted = cipher_nd.decrypt_ipaddr(&encrypted_bytes);
//! assert_eq!(ip, decrypted);
//! ```
//!
//! # Security Considerations
//!
//! - The deterministic mode is compact and facilitates integration, but allows correlation of encrypted addresses
//! - The prefix-preserving mode (`IpcryptPfx`) maintains network structure for analytics while encrypting actual network identities
//! - For general use cases, prefer the non-deterministic modes (`IpcryptNd` or `IpcryptNdx`)
//! - The extended mode (`IpcryptNdx`) provides the strongest security with a larger key and tweak size

pub(crate) mod aes;
pub(crate) mod common;
pub(crate) mod deterministic;
pub(crate) mod nd;
pub(crate) mod ndx;
pub(crate) mod pfx;

pub use common::{bytes_to_ip, ip_to_bytes};
pub use deterministic::Ipcrypt;
pub use nd::IpcryptNd;
pub use ndx::IpcryptNdx;
pub use pfx::IpcryptPfx;

pub mod reexports {
    pub use aes;
    #[cfg(feature = "random")]
    pub use rand;
}
