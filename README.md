# rust-ipcrypt2

This repository contains two Rust implementations of the "Methods for IP Address Encryption and Obfuscation" specification, which defines efficient and secure methods for IP address encryption and obfuscation.

## Overview

IP address encryption and obfuscation are crucial for various security and privacy applications, such as:

- Protecting sensitive network topology information
- Implementing privacy-preserving network monitoring
- Securing logging systems that handle IP addresses
- Supporting GDPR compliance in network data processing

This repository provides two distinct implementations:

### 1. ipcrypt2-rust

Located in the `ipcrypt2-rust` directory, this implementation provides Rust bindings to the reference ipcrypt2 library. It offers:

- Direct integration with the battle-tested reference implementation
- High performance through native code
- FFI (Foreign Function Interface) bindings for seamless Rust integration

### 2. pure-rust

Located in the `pure-rust` directory, this is a pure Rust implementation of the specification. It provides:

- Native Rust implementation with no external dependencies
- Easy integration into Rust-only projects
- Platform independence
- Clear, auditable Rust code

## Documentation

Each implementation has its own detailed documentation:

- [ipcrypt2-rust documentation](ipcrypt2-rust/README.md) - Rust bindings to the reference implementation
- [pure-rust documentation](pure-rust/README.md) - Pure Rust implementation

## References

- [Methods for IP Address Encryption and Obfuscation Specification](https://datatracker.ietf.org/doc/draft-dulaunoy-ipaddr-privacy/)
