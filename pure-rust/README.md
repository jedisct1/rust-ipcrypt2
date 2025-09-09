# IPCrypt - pure Rust implementation

A pure Rust implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

[![Crates.io](https://img.shields.io/crates/v/ipcrypt-rs.svg)](https://crates.io/crates/ipcrypt-rs)
[![Documentation](https://docs.rs/ipcrypt-rs/badge.svg)](https://docs.rs/ipcrypt-rs)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

## Features

- **Pure Rust Implementation**: Written entirely in Rust with no C bindings or external dependencies
- **Format-Preserving Encryption**: Deterministic mode preserves IP address format
- **Prefix-Preserving Encryption**: PFX mode maintains network structure while encrypting addresses
- **Non-Deterministic Modes**: Two modes for enhanced privacy with different tweak sizes
- **IPv4 and IPv6 Support**: Works with both address types seamlessly
- **Minimal Dependencies**: Only uses the `aes` and `rand` crates
- **Safe Implementation**: No unsafe code

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ipcrypt-rs = "0.9.2"
```

## Overview

IPCrypt provides four different methods for IP address encryption:

1. **Deterministic Encryption** (`Ipcrypt`): Uses AES-128 in a deterministic mode, where the same input always produces the same output for a given key. This mode preserves the IP address format.

2. **Prefix-Preserving Encryption** (`IpcryptPfx`): A deterministic mode that maintains network prefix structure while encrypting addresses. Addresses in the same subnet will remain in the same subnet after encryption, enabling network analytics while preserving privacy.

3. **Non-Deterministic Encryption** (`IpcryptNd`): Uses KIASU-BC with an 8-byte tweak to provide non-deterministic encryption. The output includes both the tweak and ciphertext.

4. **Extended Non-Deterministic Encryption** (`IpcryptNdx`): Uses AES-XTS with a 32-byte key (two AES-128 keys) and 16-byte tweak for enhanced security.

## Usage

### Deterministic Encryption

```rust
use ipcrypt_rs::Ipcrypt;
use std::net::IpAddr;
use std::str::FromStr;

// Create a new instance with a random key
let cipher = Ipcrypt::new_random();

// Or with a specific key
let key = [0u8; Ipcrypt::KEY_BYTES];
let cipher = Ipcrypt::new(key);

// Encrypt an IP address
let ip = IpAddr::from_str("192.168.1.1").unwrap();
let encrypted = cipher.encrypt_ipaddr(ip);

// Decrypt the IP address
let decrypted = cipher.decrypt_ipaddr(encrypted);
assert_eq!(ip, decrypted);
```

### Prefix-Preserving Encryption

```rust
use ipcrypt_rs::IpcryptPfx;
use std::net::IpAddr;
use std::str::FromStr;

// Create a new instance with a random key
let cipher = IpcryptPfx::new_random();

// Or with a specific key (32 bytes)
let key = [0u8; IpcryptPfx::KEY_BYTES];
let cipher = IpcryptPfx::new(key);

// Encrypt an IP address
let ip = IpAddr::from_str("192.168.1.1").unwrap();
let encrypted = cipher.encrypt_ipaddr(ip);

// Decrypt the IP address
let decrypted = cipher.decrypt_ipaddr(encrypted);
assert_eq!(ip, decrypted);

// Note: Addresses in the same subnet will remain in the same subnet
let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
let ip2 = IpAddr::from_str("192.168.1.2").unwrap();
let enc1 = cipher.encrypt_ipaddr(ip1);
let enc2 = cipher.encrypt_ipaddr(ip2);
// Both encrypted addresses will be in the same /24 network
```

### Non-Deterministic Encryption

```rust
use ipcrypt_rs::IpcryptNd;
use std::net::IpAddr;
use std::str::FromStr;

// Create a new instance with a random key
let cipher = IpcryptNd::new_random();

// Encrypt with automatic tweak generation
let ip = IpAddr::from_str("192.168.1.1").unwrap();
let encrypted = cipher.encrypt_ipaddr(ip, None);

// Or with a specific tweak
let tweak = [0u8; IpcryptNd::TWEAK_BYTES];
let encrypted = cipher.encrypt_ipaddr(ip, Some(tweak));

// Decrypt (tweak is automatically extracted from the encrypted data)
let decrypted = cipher.decrypt_ipaddr(&encrypted);
assert_eq!(ip, decrypted);
```

### Extended Non-Deterministic Encryption

```rust
use ipcrypt_rs::IpcryptNdx;
use std::net::IpAddr;
use std::str::FromStr;

// Create a new instance with a random key
let cipher = IpcryptNdx::new_random();

// Or with a specific key (32 bytes)
let key = [0u8; IpcryptNdx::KEY_BYTES];
let cipher = IpcryptNdx::new(key);

// Encrypt with automatic tweak generation
let ip = IpAddr::from_str("192.168.1.1").unwrap();
let encrypted = cipher.encrypt_ipaddr(ip, None);

// Or with a specific tweak (16 bytes)
let tweak = [0u8; IpcryptNdx::TWEAK_BYTES];
let encrypted = cipher.encrypt_ipaddr(ip, Some(tweak));

// Decrypt (tweak is automatically extracted from the encrypted data)
let decrypted = cipher.decrypt_ipaddr(&encrypted);
assert_eq!(ip, decrypted);
```

## API Reference

### Deterministic Mode (`Ipcrypt`)

- `KEY_BYTES`: The number of bytes required for the encryption key (16)
- `new(key: [u8; KEY_BYTES]) -> Self`: Creates a new instance with the given key
- `new_random() -> Self`: Creates a new instance with a random key
- `encrypt_ipaddr(ip: IpAddr) -> IpAddr`: Encrypts an IP address
- `decrypt_ipaddr(encrypted: IpAddr) -> IpAddr`: Decrypts an encrypted IP address

### Prefix-Preserving Mode (`IpcryptPfx`)

- `KEY_BYTES`: The number of bytes required for the encryption key (32)
- `new(key: [u8; KEY_BYTES]) -> Self`: Creates a new instance with the given key
- `new_random() -> Self`: Creates a new instance with a random key
- `generate_key() -> [u8; KEY_BYTES]`: Generates a random key
- `encrypt_ipaddr(ip: IpAddr) -> IpAddr`: Encrypts an IP address while preserving prefix
- `decrypt_ipaddr(encrypted: IpAddr) -> IpAddr`: Decrypts an encrypted IP address

### Non-Deterministic Mode (`IpcryptNd`)

- `KEY_BYTES`: The number of bytes required for the encryption key (16)
- `TWEAK_BYTES`: The number of bytes required for the tweak (8)
- `NDIP_BYTES`: The number of bytes in the output (24 = tweak + ciphertext)
- `new(key: [u8; KEY_BYTES]) -> Self`: Creates a new instance with the given key
- `new_random() -> Self`: Creates a new instance with a random key
- `generate_tweak() -> [u8; TWEAK_BYTES]`: Generates a random tweak
- `encrypt_ipaddr(ip: IpAddr, tweak: Option<[u8; TWEAK_BYTES]>) -> [u8; NDIP_BYTES]`: Encrypts an IP address
- `decrypt_ipaddr(encrypted: &[u8; NDIP_BYTES]) -> IpAddr`: Decrypts an encrypted IP address

### Extended Non-Deterministic Mode (`IpcryptNdx`)

- `KEY_BYTES`: The number of bytes required for the encryption key (32)
- `TWEAK_BYTES`: The number of bytes required for the tweak (16)
- `NDIP_BYTES`: The number of bytes in the output (32 = tweak + ciphertext)
- `new(key: [u8; KEY_BYTES]) -> Self`: Creates a new instance with the given key
- `new_random() -> Self`: Creates a new instance with a random key
- `generate_tweak() -> [u8; TWEAK_BYTES]`: Generates a random tweak
- `encrypt_ipaddr(ip: IpAddr, tweak: Option<[u8; TWEAK_BYTES]>) -> [u8; NDIP_BYTES]`: Encrypts an IP address
- `decrypt_ipaddr(encrypted: &[u8; NDIP_BYTES]) -> IpAddr`: Decrypts an encrypted IP address
