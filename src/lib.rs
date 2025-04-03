#![doc = include_str!("../README.md")]

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int};

pub mod reexports {
    pub use getrandom;
}

/// Re-export constants from the FFI layer.
pub const IPCRYPT_KEYBYTES: usize = 16;
pub const IPCRYPT_TWEAKBYTES: usize = 8;
pub const IPCRYPT_MAX_IP_STR_BYTES: usize = 46;
pub const IPCRYPT_NDIP_BYTES: usize = 24;
pub const IPCRYPT_NDIP_STR_BYTES: usize = 48 + 1;

/// Raw FFI bindings generated from ipcrypt2.h.
#[repr(C)]
pub struct IPCrypt {
    opaque: [u8; 16 * 11],
}

extern "C" {
    fn ipcrypt_init(ipcrypt: *mut IPCrypt, key: *const u8);
    fn ipcrypt_deinit(ipcrypt: *mut IPCrypt);
    fn ipcrypt_encrypt_ip16(ipcrypt: *const IPCrypt, ip16: *mut u8);
    fn ipcrypt_decrypt_ip16(ipcrypt: *const IPCrypt, ip16: *mut u8);
    fn ipcrypt_encrypt_ip_str(
        ipcrypt: *const IPCrypt,
        encrypted_ip_str: *mut c_char,
        ip_str: *const c_char,
    ) -> usize;
    fn ipcrypt_decrypt_ip_str(
        ipcrypt: *const IPCrypt,
        ip_str: *mut c_char,
        encrypted_ip_str: *const c_char,
    ) -> usize;
    fn ipcrypt_nd_encrypt_ip16(
        ipcrypt: *const IPCrypt,
        ndip: *mut u8,
        ip16: *const u8,
        random: *const u8,
    );
    fn ipcrypt_nd_decrypt_ip16(ipcrypt: *const IPCrypt, ip16: *mut u8, ndip: *const u8);
    fn ipcrypt_nd_encrypt_ip_str(
        ipcrypt: *const IPCrypt,
        encrypted_ip_str: *mut c_char,
        ip_str: *const c_char,
        random: *const u8,
    ) -> usize;
    fn ipcrypt_nd_decrypt_ip_str(
        ipcrypt: *const IPCrypt,
        ip_str: *mut c_char,
        encrypted_ip_str: *const c_char,
    ) -> usize;
    fn ipcrypt_str_to_ip16(ip16: *mut u8, ip_str: *const c_char) -> c_int;
    fn ipcrypt_ip16_to_str(ip_str: *mut c_char, ip16: *const u8) -> usize;
}

/// An error type for the safe Ipcrypt interface.
#[derive(Debug)]
pub enum IpcryptError {
    NullByteInInput,
    Utf8Error,
    OperationFailed,
}

/// A safe wrapper around the raw IPCrypt context.
pub struct Ipcrypt {
    inner: IPCrypt,
}

impl Ipcrypt {
    /// Creates a random key for the Ipcrypt instance.
    pub fn random_key() -> [u8; IPCRYPT_KEYBYTES] {
        let mut key = [0u8; IPCRYPT_KEYBYTES];
        getrandom::fill(&mut key).expect("Failed to fill random bytes");
        key
    }

    /// Creates a new Ipcrypt instance with the given secret key.
    ///
    /// # Panics
    ///
    /// Panics if the key length is not equal to IPCRYPT_KEYBYTES.
    pub fn new(key: &[u8]) -> Self {
        assert!(
            key.len() == IPCRYPT_KEYBYTES,
            "Key must be {} bytes",
            IPCRYPT_KEYBYTES
        );
        let mut inner = std::mem::MaybeUninit::<IPCrypt>::uninit();
        unsafe {
            ipcrypt_init(inner.as_mut_ptr(), key.as_ptr());
            Self {
                inner: inner.assume_init(),
            }
        }
    }

    /// Encrypts a 16-byte IP address in place.
    pub fn encrypt_ip16(&self, ip: &mut [u8; 16]) {
        unsafe {
            ipcrypt_encrypt_ip16(&self.inner, ip.as_mut_ptr());
        }
    }

    /// Decrypts a 16-byte IP address in place.
    pub fn decrypt_ip16(&self, ip: &mut [u8; 16]) {
        unsafe {
            ipcrypt_decrypt_ip16(&self.inner, ip.as_mut_ptr());
        }
    }

    /// Encrypts an IP address string (IPv4 or IPv6).
    ///
    /// On success, returns the encrypted IP string.
    pub fn encrypt_ip_str(&self, ip: &str) -> Result<String, IpcryptError> {
        let c_ip = CString::new(ip).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; IPCRYPT_MAX_IP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_encrypt_ip_str(
                &self.inner,
                buffer.as_mut_ptr() as *mut c_char,
                c_ip.as_ptr(),
            )
        };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| IpcryptError::Utf8Error)
        }
    }

    /// Decrypts an encrypted IP address string.
    ///
    /// On success, returns the decrypted IP string.
    pub fn decrypt_ip_str(&self, encrypted: &str) -> Result<String, IpcryptError> {
        let c_encrypted = CString::new(encrypted).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; IPCRYPT_MAX_IP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_decrypt_ip_str(
                &self.inner,
                buffer.as_mut_ptr() as *mut c_char,
                c_encrypted.as_ptr(),
            )
        };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| IpcryptError::Utf8Error)
        }
    }

    /// Non-deterministically encrypts a 16-byte IP address.
    ///
    /// Returns a 24-byte encrypted value.
    pub fn nd_encrypt_ip16(&self, ip: &[u8; 16]) -> [u8; IPCRYPT_NDIP_BYTES] {
        let mut random = [0u8; IPCRYPT_TWEAKBYTES];
        getrandom::fill(&mut random).expect("Failed to fill random bytes");
        let mut ndip = [0u8; IPCRYPT_NDIP_BYTES];
        unsafe {
            ipcrypt_nd_encrypt_ip16(&self.inner, ndip.as_mut_ptr(), ip.as_ptr(), random.as_ptr());
        }
        ndip
    }

    /// Non-deterministically decrypts a 24-byte encrypted IP address.
    ///
    /// Returns the decrypted 16-byte IP address.
    pub fn nd_decrypt_ip16(&self, ndip: &[u8; IPCRYPT_NDIP_BYTES]) -> [u8; 16] {
        let mut ip = [0u8; 16];
        unsafe {
            ipcrypt_nd_decrypt_ip16(&self.inner, ip.as_mut_ptr(), ndip.as_ptr());
        }
        ip
    }

    /// Non-deterministically encrypts an IP address string (IPv4 or IPv6).
    ///
    /// Returns a hex-encoded string.
    pub fn nd_encrypt_ip_str(&self, ip: &str) -> Result<String, IpcryptError> {
        let c_ip = CString::new(ip).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut random = [0u8; IPCRYPT_TWEAKBYTES];
        getrandom::fill(&mut random).map_err(|_| IpcryptError::OperationFailed)?;
        let mut buffer = [0u8; IPCRYPT_NDIP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_nd_encrypt_ip_str(
                &self.inner,
                buffer.as_mut_ptr() as *mut c_char,
                c_ip.as_ptr(),
                random.as_ptr(),
            )
        };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| IpcryptError::Utf8Error)
        }
    }

    /// Non-deterministically decrypts a hex-encoded IP address string from non-deterministic mode.
    ///
    /// Returns the decrypted IP string on success.
    pub fn nd_decrypt_ip_str(&self, encrypted: &str) -> Result<String, IpcryptError> {
        let c_encrypted = CString::new(encrypted).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; IPCRYPT_MAX_IP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_nd_decrypt_ip_str(
                &self.inner,
                buffer.as_mut_ptr() as *mut c_char,
                c_encrypted.as_ptr(),
            )
        };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| IpcryptError::Utf8Error)
        }
    }

    /// Converts an IP address string (IPv4 or IPv6) to a 16-byte binary representation.
    ///
    /// Returns the binary representation as a 16-byte array on success.
    pub fn str_to_ip16(ip: &str) -> Result<[u8; 16], IpcryptError> {
        let c_ip = CString::new(ip).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut ip16 = [0u8; 16];
        let ret = unsafe { ipcrypt_str_to_ip16(ip16.as_mut_ptr(), c_ip.as_ptr()) };
        if ret != 0 {
            Err(IpcryptError::OperationFailed)
        } else {
            Ok(ip16)
        }
    }

    /// Converts a 16-byte binary IP address into a string.
    ///
    /// Returns the IP string on success.
    pub fn ip16_to_str(ip16: &[u8; 16]) -> Result<String, IpcryptError> {
        let mut buffer = [0u8; IPCRYPT_MAX_IP_STR_BYTES];
        let ret = unsafe { ipcrypt_ip16_to_str(buffer.as_mut_ptr() as *mut c_char, ip16.as_ptr()) };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| IpcryptError::Utf8Error)
        }
    }

    // --- Additional interfaces using std::net::IpAddr ---

    /// Converts a `std::net::IpAddr` into a 16-byte representation.
    ///
    /// IPv4 addresses are converted to the IPv4‑mapped IPv6 format.
    pub fn ipaddr_to_ip16(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    /// Converts a 16-byte representation to a `std::net::IpAddr`.
    ///
    /// If the 16-byte value is an IPv4-mapped IPv6 address, it returns an `IpAddr::V4`.
    pub fn ip16_to_ipaddr(ip16: [u8; 16]) -> Result<IpAddr, IpcryptError> {
        // Check for IPv4-mapped IPv6 address.
        if ip16[0..10] == [0u8; 10] && ip16[10] == 0xff && ip16[11] == 0xff {
            let octets = [ip16[12], ip16[13], ip16[14], ip16[15]];
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        } else {
            Ok(IpAddr::V6(Ipv6Addr::from(ip16)))
        }
    }

    /// Encrypts an `IpAddr` using the format-preserving encryption for IP strings.
    ///
    /// Returns the encrypted IP as an `IpAddr` (the encrypted string is parsed back into an `IpAddr`).
    pub fn encrypt_ipaddr(&self, ip: IpAddr) -> Result<IpAddr, IpcryptError> {
        let mut ip16 = Ipcrypt::ipaddr_to_ip16(ip);
        self.encrypt_ip16(&mut ip16);
        let encrypted_ip = Ipcrypt::ip16_to_ipaddr(ip16)?;
        Ok(encrypted_ip)
    }

    /// Decrypts an encrypted `IpAddr` (provided as an `IpAddr` type).
    ///
    /// Returns the original `IpAddr` on success.
    pub fn decrypt_ipaddr(&self, encrypted: IpAddr) -> Result<IpAddr, IpcryptError> {
        let mut ip16 = Ipcrypt::ipaddr_to_ip16(encrypted);
        self.decrypt_ip16(&mut ip16);
        let decrypted_ip = Ipcrypt::ip16_to_ipaddr(ip16)?;
        Ok(decrypted_ip)
    }

    /// Non-deterministically encrypts an `IpAddr` using the IP string interface.
    ///
    /// Returns the encrypted IP as an `IpAddr`.
    pub fn nd_encrypt_ipaddr(&self, ip: IpAddr) -> Result<[u8; IPCRYPT_NDIP_BYTES], IpcryptError> {
        let ip_str = Ipcrypt::ipaddr_to_ip16(ip);
        let encrypted = self.nd_encrypt_ip16(&ip_str);
        Ok(encrypted)
    }

    /// Non-deterministically decrypts an encrypted `IpAddr` (provided as an `IpAddr` type).
    ///
    /// Returns the original `IpAddr` on success.
    pub fn nd_decrypt_ipaddr(
        &self,
        encrypted: [u8; IPCRYPT_NDIP_BYTES],
    ) -> Result<IpAddr, IpcryptError> {
        let decrypted = self.nd_decrypt_ip16(&encrypted);
        let decrypted_ip = Ipcrypt::ip16_to_ipaddr(decrypted)?;
        Ok(decrypted_ip)
    }

    /// Non-deterministically encrypts an IP address (IPv4 or IPv6).
    ///
    /// Returns a hex-encoded string.
    pub fn nd_encrypt_ipaddr_str(&self, ip: IpAddr) -> Result<String, IpcryptError> {
        let ip_str = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        };
        self.nd_encrypt_ip_str(&ip_str)
    }

    /// Non-deterministically decrypts an encrypted IP address string.
    ///
    /// Returns the decrypted `IpAddr` on success.
    pub fn nd_decrypt_ipaddr_str(&self, encrypted: &str) -> Result<IpAddr, IpcryptError> {
        let decrypted_str = self.nd_decrypt_ip_str(encrypted)?;
        let ip = Ipcrypt::str_to_ip16(&decrypted_str)?;
        Ipcrypt::ip16_to_ipaddr(ip)
    }
}

impl Drop for Ipcrypt {
    fn drop(&mut self) {
        unsafe {
            ipcrypt_deinit(&mut self.inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip16_encrypt_decrypt() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);
        let mut ip = [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let original = ip;
        ipcrypt.encrypt_ip16(&mut ip);
        assert_ne!(ip, original);
        ipcrypt.decrypt_ip16(&mut ip);
        assert_eq!(ip, original);
    }

    #[test]
    fn test_ip_str_encrypt_decrypt() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);
        let ip = "192.168.1.1";
        let encrypted = ipcrypt.encrypt_ip_str(ip).expect("Encryption failed");
        let decrypted = ipcrypt
            .decrypt_ip_str(&encrypted)
            .expect("Decryption failed");
        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_nd_ip16_encrypt_decrypt() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);
        let ip: [u8; 16] = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nd_encrypted = ipcrypt.nd_encrypt_ip16(&ip);
        let decrypted = ipcrypt.nd_decrypt_ip16(&nd_encrypted);
        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_nd_ip_str_encrypt_decrypt() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);
        let ip = "10.0.0.1";
        let nd_encrypted = ipcrypt.nd_encrypt_ip_str(ip).expect("ND Encryption failed");
        let nd_decrypted = ipcrypt
            .nd_decrypt_ip_str(&nd_encrypted)
            .expect("ND Decryption failed");
        assert_eq!(ip, nd_decrypted);
    }

    #[test]
    fn test_str_to_ip16_and_back() {
        let ip_str = "192.168.1.1";
        let ip16 = Ipcrypt::str_to_ip16(ip_str).expect("Conversion to ip16 failed");
        let ip_str_converted = Ipcrypt::ip16_to_str(&ip16).expect("Conversion to string failed");
        assert_eq!(ip_str, ip_str_converted);
    }

    #[test]
    fn test_encrypt_decrypt_ipaddr() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);

        // Test IPv4
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let encrypted_v4 = ipcrypt.encrypt_ipaddr(ip_v4).expect("Encryption failed");
        let decrypted_v4 = ipcrypt
            .decrypt_ipaddr(encrypted_v4)
            .expect("Decryption failed");
        assert_eq!(ip_v4, decrypted_v4);

        // Test IPv6
        let ip_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let encrypted_v6 = ipcrypt.encrypt_ipaddr(ip_v6).expect("Encryption failed");
        let decrypted_v6 = ipcrypt
            .decrypt_ipaddr(encrypted_v6)
            .expect("Decryption failed");
        assert_eq!(ip_v6, decrypted_v6);
    }

    #[test]
    fn test_nd_encrypt_decrypt_ipaddr() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);

        // Test IPv4
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let encrypted_v4 = ipcrypt
            .nd_encrypt_ipaddr(ip_v4)
            .expect("ND Encryption failed");
        let decrypted_v4 = ipcrypt
            .nd_decrypt_ipaddr(encrypted_v4)
            .expect("ND Decryption failed");
        assert_eq!(ip_v4, decrypted_v4);

        // Test IPv6
        let ip_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let encrypted_v6 = ipcrypt
            .nd_encrypt_ipaddr(ip_v6)
            .expect("ND Encryption failed");
        let decrypted_v6 = ipcrypt
            .nd_decrypt_ipaddr(encrypted_v6)
            .expect("ND Decryption failed");
        assert_eq!(ip_v6, decrypted_v6);
    }

    #[test]
    fn test_nd_ipaddr_str_encrypt_decrypt() {
        let key = [0u8; IPCRYPT_KEYBYTES];
        let ipcrypt = Ipcrypt::new(&key);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nd_encrypted = ipcrypt
            .nd_encrypt_ipaddr_str(ip)
            .expect("ND Encryption failed");
        let nd_decrypted = ipcrypt
            .nd_decrypt_ipaddr_str(&nd_encrypted)
            .expect("ND Decryption failed");
        assert_eq!(ip, nd_decrypted);
    }
}
