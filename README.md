# ipcrypt2

**ipcrypt2** is a Rust library to enable encryption and decryption of IP addresses (both IPv4 and IPv6).

## Features

- **Deterministic (Format-Preserving) Encryption/Decryption:**
  Encrypt and decrypt IP addresses in a way that preserves their format. The output remains a valid IP address.

- **Non-Deterministic Encryption/Decryption (KIASU-BC):**
  For increased privacy, non-deterministic encryption produces a compact 24-byte array (or its hex string representation) instead of an IP address. This mode uses 8-byte random tweaks, so the same input will yield different outputs on each encryption.

- **NDX Mode: Non-Deterministic Encryption with Extended Tweaks (AES-XTX):**
  Similar to the non-deterministic mode but uses 16-byte tweaks for higher usage limits before collisions occur. Produces 32-byte encrypted values (or 64-character hex strings). This mode runs at half the speed of the regular non-deterministic mode.

- **IP Conversion Utilities:**
  Seamlessly convert between `std::net::IpAddr`, 16-byte binary representations, and IP strings. IPv4 addresses are automatically converted to IPv4‑mapped IPv6 format when needed.

- **WebAssembly Support:**
  The library is fully compatible with WebAssembly.

## Installation

To use **ipcrypt2** in your project, add it to your `Cargo.toml`:

```toml
[dependencies]
ipcrypt2 = "0.1"  # Replace with the latest version
```

## Usage

The [ipcrypt2 API documentation](https://docs.rs/ipcrypt2) is available on `docs.rs`.

Below is an example demonstrating all three encryption modes:

```rust
use std::net::{IpAddr, Ipv4Addr};
use ipcrypt2::{Ipcrypt, IpcryptNdx};

// Create secret keys with the required lengths.
let key = Ipcrypt::generate_key();
let ndx_key = IpcryptNdx::generate_key();

// Initialize the ipcrypt2 contexts.
let ipcrypt = Ipcrypt::new(key);
let ipcrypt_ndx = IpcryptNdx::new(ndx_key);

// --- Deterministic (Format-Preserving) Mode ---
// Encrypting an IP address preserves its format.
let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
let encrypted_ip = ipcrypt.encrypt_ipaddr(ip)
    .expect("IP encryption failed");
println!("Deterministically Encrypted IP: {}", encrypted_ip);

let decrypted_ip = ipcrypt.decrypt_ipaddr(encrypted_ip)
    .expect("IP decryption failed");
println!("Decrypted IP: {}", decrypted_ip);

// --- Non-Deterministic Mode (KIASU-BC) ---
// Non-deterministic encryption produces a compact 24-byte array (or hex string).
let ip_str = "10.0.0.1";
let nd_encrypted = ipcrypt.nd_encrypt_ip_str(ip_str)
    .expect("Non-deterministic encryption failed");
println!("Non-Deterministically Encrypted IP String: {}", nd_encrypted);

let nd_decrypted = ipcrypt.nd_decrypt_ip_str(&nd_encrypted)
    .expect("Non-deterministic decryption failed");
println!("Non-Deterministically Decrypted IP String: {}", nd_decrypted);

// --- NDX Mode (AES-XTX) ---
// NDX mode uses 16-byte tweaks and produces 32-byte encrypted values.
let ndx_encrypted = ipcrypt_ndx.nd_encrypt_ip_str(ip_str)
    .expect("NDX encryption failed");
println!("NDX Encrypted IP String: {}", ndx_encrypted);

let ndx_decrypted = ipcrypt_ndx.nd_decrypt_ip_str(&ndx_encrypted)
    .expect("NDX decryption failed");
println!("NDX Decrypted IP String: {}", ndx_decrypted);
```

## API Overview

The primary interfaces are provided by the `Ipcrypt` and `IpcryptNdx` structs, which expose several functionalities:

### Initialization

- **`Ipcrypt::new(key: [u8; KEY_BYTES])`**
  Creates a new instance with a secret key. The key must be exactly 16 bytes long.

- **`IpcryptNdx::new(key: [u8; KEY_BYTES])`**
  Creates a new NDX instance with a secret key. The key must be exactly 32 bytes long.

### Deterministic Methods (Format-Preserving)

- **`encrypt_ip16(&self, ip: &mut [u8; 16])` / `decrypt_ip16(&self, ip: &mut [u8; 16])`**
  Encrypts and decrypts a 16-byte IP address in-place.

- **`encrypt_ip_str(&self, ip: &str)` / `decrypt_ip_str(&self, encrypted: &str)`**
  Encrypts and decrypts IP address strings, supporting both IPv4 and IPv6 formats.

- **`encrypt_ipaddr(&self, ip: IpAddr)` / `decrypt_ipaddr(&self, encrypted: IpAddr)`**
  Encrypts and decrypts `std::net::IpAddr` types. The encrypted output is still a valid IP address, with IPv4 addresses represented in IPv4‑mapped IPv6 format.

### Non-Deterministic Methods (KIASU-BC)

- **`nd_encrypt_ip16(&self, ip: &[u8; 16])` / `nd_decrypt_ip16(&self, ndip: &[u8; NDIP_BYTES])`**
  Encrypts and decrypts 16-byte IP addresses non-deterministically, outputting a 24-byte encrypted array.

- **`nd_encrypt_ip_str(&self, ip: &str)` / `nd_decrypt_ip_str(&self, encrypted: &str)`**
  Encrypts and decrypts IP address strings in non-deterministic mode. The encrypted value is returned as a hex-encoded string.

- **`nd_encrypt_ipaddr_str(&self, ip: IpAddr)` / `nd_decrypt_ipaddr_str(&self, encrypted: &str)`**
  Encrypts an `IpAddr` to a non-deterministic hex string and converts it back upon decryption.

### NDX Mode Methods (AES-XTX)

- **`nd_encrypt_ip16(&self, ip: &[u8; 16])` / `nd_decrypt_ip16(&self, ndip: &[u8; NDIP_BYTES])`**
  Encrypts and decrypts 16-byte IP addresses non-deterministically, outputting a 32-byte encrypted array.

- **`nd_encrypt_ip_str(&self, ip: &str)` / `nd_decrypt_ip_str(&self, encrypted: &str)`**
  Encrypts and decrypts IP address strings in NDX mode. The encrypted value is returned as a hex-encoded string.

- **`nd_encrypt_ipaddr_str(&self, ip: IpAddr)` / `nd_decrypt_ipaddr_str(&self, encrypted: &str)`**
  Encrypts an `IpAddr` to an NDX hex string and converts it back upon decryption.

### Conversion Utilities

- **`ipaddr_to_ip16(ip: IpAddr)` and `ip16_to_ipaddr(ip16: [u8; 16])`**
  Convert between `IpAddr` and its 16-byte representation. IPv4 addresses are represented as IPv4‑mapped IPv6 addresses.

- **`str_to_ip16(ip: &str)` and `ip16_to_str(ip16: &[u8; 16])`**
  Convert between IP address strings and their corresponding 16-byte binary forms.

For detailed API documentation, refer to the inline comments in the source code.

## Contributing

Contributions are welcome! If you encounter any issues or have feature requests, please open an issue or submit a pull request.

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for more details.
