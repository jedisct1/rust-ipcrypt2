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

Below is an example demonstrating the basic usage:

```rust
use ipcrypt2::Ipcrypt;

// Create an instance with a random key
let ipcrypt = Ipcrypt::new_random();

// Encrypt and decrypt an IP address
let ip = "192.168.1.1";
let encrypted = ipcrypt.encrypt(ip).unwrap();
let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
assert_eq!(ip, decrypted);

// Non-deterministic encryption
let nd_encrypted = ipcrypt.encrypt_nd(ip).unwrap();
let nd_decrypted = ipcrypt.decrypt_nd(&nd_encrypted).unwrap();
assert_eq!(ip, nd_decrypted);
```

For NDX mode (using 16-byte tweaks):

```rust
use ipcrypt2::IpcryptNdx;

// Create an instance with a random key
let ipcrypt = IpcryptNdx::new_random();

// Encrypt and decrypt an IP address
let ip = "192.168.1.1";
let encrypted = ipcrypt.encrypt(ip).unwrap();
let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
assert_eq!(ip, decrypted);
```

### Advanced Usage

For more control over the encryption process, you can use the lower-level methods:

```rust
use ipcrypt2::Ipcrypt;
use std::net::IpAddr;

// Create an instance with a specific key
let key = [0u8; 16];
let ipcrypt = Ipcrypt::new(key);

// Work with IP addresses directly
let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
let encrypted = ipcrypt.encrypt_ipaddr(ip).unwrap();
let decrypted = ipcrypt.decrypt_ipaddr(encrypted).unwrap();
assert_eq!(ip, decrypted);

// Work with raw bytes
let ip16 = Ipcrypt::to_bytes("192.168.1.1").unwrap();
let ip_str = Ipcrypt::from_bytes(&ip16).unwrap();
assert_eq!("192.168.1.1", ip_str);
```

## API Overview

The primary interfaces are provided by the `Ipcrypt` and `IpcryptNdx` structs, which expose several functionalities:

### Initialization

- **`Ipcrypt::new_random()`**
  Creates a new instance with a randomly generated key.

- **`Ipcrypt::new(key: [u8; KEY_BYTES])`**
  Creates a new instance with a specific key. The key must be exactly 16 bytes long.

- **`IpcryptNdx::new_random()`**
  Creates a new NDX instance with a randomly generated key.

- **`IpcryptNdx::new(key: [u8; KEY_BYTES])`**
  Creates a new NDX instance with a specific key. The key must be exactly 32 bytes long.

### Basic Methods

- **`encrypt(ip: &str)` / `decrypt(encrypted: &str)`**
  Encrypts and decrypts IP address strings, supporting both IPv4 and IPv6 formats.

- **`encrypt_nd(ip: &str)` / `decrypt_nd(encrypted: &str)`**
  Non-deterministically encrypts and decrypts IP address strings.

### Utility Methods

- **`to_bytes(ip: &str)` / `from_bytes(ip16: &[u8; 16])`**
  Convert between IP address strings and their 16-byte binary representations.

### Advanced Methods

For more control, you can use the following methods:

- **`encrypt_ip16(&self, ip: &mut [u8; 16])` / `decrypt_ip16(&self, ip: &mut [u8; 16])`**
  Encrypts and decrypts a 16-byte IP address in-place.

- **`encrypt_ipaddr(&self, ip: IpAddr)` / `decrypt_ipaddr(&self, encrypted: IpAddr)`**
  Encrypts and decrypts `std::net::IpAddr` types.

- **`nd_encrypt_ip16(&self, ip: &[u8; 16])` / `nd_decrypt_ip16(&self, ndip: &[u8; NDIP_BYTES])`**
  Non-deterministically encrypts and decrypts 16-byte IP addresses.

For detailed API documentation, refer to the inline comments in the source code.

## Contributing

Contributions are welcome! If you encounter any issues or have feature requests, please open an issue or submit a pull request.

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for more details.
