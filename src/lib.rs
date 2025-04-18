#![doc = include_str!("../README.md")]

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int};

pub mod reexports {
    pub use rand;
}

#[repr(C)]
pub struct IPCrypt {
    opaque: [u8; 16 * 11],
}

#[repr(C)]
pub struct IPCryptNDX {
    opaque: [u8; 16 * 11 * 2],
}

extern "C" {
    fn ipcrypt_str_to_ip16(ip16: *mut u8, ip_str: *const c_char) -> c_int;
    fn ipcrypt_ip16_to_str(ip_str: *mut c_char, ip16: *const u8) -> usize;

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

    fn ipcrypt_ndx_init(ipcrypt: *mut IPCryptNDX, key: *const u8);
    fn ipcrypt_ndx_deinit(ipcrypt: *mut IPCryptNDX);
    fn ipcrypt_ndx_encrypt_ip16(
        ipcrypt: *const IPCryptNDX,
        ndip: *mut u8,
        ip16: *const u8,
        random: *const u8,
    );
    fn ipcrypt_ndx_decrypt_ip16(ipcrypt: *const IPCryptNDX, ip16: *mut u8, ndip: *const u8);
    fn ipcrypt_ndx_encrypt_ip_str(
        ipcrypt: *const IPCryptNDX,
        encrypted_ip_str: *mut c_char,
        ip_str: *const c_char,
        random: *const u8,
    ) -> usize;
    fn ipcrypt_ndx_decrypt_ip_str(
        ipcrypt: *const IPCryptNDX,
        ip_str: *mut c_char,
        encrypted_ip_str: *const c_char,
    ) -> usize;
}

/// An error type for the safe Ipcrypt interface.
#[derive(Debug)]
pub enum IpcryptError {
    /// Input contains a null byte
    NullByteInInput,
    /// Failed to convert bytes to UTF-8 string
    Utf8Error(std::str::Utf8Error),
    /// Operation failed (e.g., invalid IP format)
    OperationFailed,
}

impl fmt::Display for IpcryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcryptError::NullByteInInput => write!(f, "input contains a null byte"),
            IpcryptError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            IpcryptError::OperationFailed => write!(f, "operation failed"),
        }
    }
}

impl Error for IpcryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            IpcryptError::Utf8Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::str::Utf8Error> for IpcryptError {
    fn from(err: std::str::Utf8Error) -> Self {
        IpcryptError::Utf8Error(err)
    }
}

/// A structure representing the IPCrypt context.
///
/// This struct provides methods for encrypting and decrypting IP addresses
/// using both deterministic and non-deterministic modes.
///
/// # Examples
///
/// ```
/// use ipcrypt2::Ipcrypt;
///
/// let key = Ipcrypt::generate_key();
/// let ipcrypt = Ipcrypt::new(key);
///
/// // Encrypt an IP address
/// let ip = "192.168.1.1";
/// let encrypted = ipcrypt.encrypt_ip_str(ip).unwrap();
/// let decrypted = ipcrypt.decrypt_ip_str(&encrypted).unwrap();
/// assert_eq!(ip, decrypted);
/// ```
pub struct Ipcrypt {
    inner: IPCrypt,
}

impl Ipcrypt {
    /// The number of bytes required for the encryption key.
    pub const KEY_BYTES: usize = 16;

    /// The number of bytes in the tweak used for non-deterministic encryption.
    pub const TWEAK_BYTES: usize = 8;

    /// The number of bytes in the encrypted output for non-deterministic mode.
    pub const NDIP_BYTES: usize = 24;

    /// The maximum number of bytes in the encrypted IP string (including null terminator).
    pub const NDIP_STR_BYTES: usize = 48 + 1;

    /// Generates a new random key for encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let key = Ipcrypt::generate_key();
    /// let ipcrypt = Ipcrypt::new(key);
    /// ```
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new Ipcrypt instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 16-byte array containing the encryption key.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let key = [0u8; 16];
    /// let ipcrypt = Ipcrypt::new(key);
    /// ```
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        // Safety: IPCrypt is a C struct with a fixed size and no alignment requirements
        let mut inner = std::mem::MaybeUninit::<IPCrypt>::uninit();

        // Safety: We have a valid pointer to uninitialized memory and a valid key pointer
        unsafe {
            ipcrypt_init(inner.as_mut_ptr(), key.as_ptr());
            Self {
                inner: inner.assume_init(),
            }
        }
    }

    /// Encrypts a 16-byte IP address in place.
    pub fn encrypt_ip16(&self, ip: &mut [u8; 16]) {
        // Safety: We have a valid IPCrypt instance and a valid mutable pointer to 16 bytes
        unsafe {
            ipcrypt_encrypt_ip16(&self.inner, ip.as_mut_ptr());
        }
    }

    /// Decrypts a 16-byte IP address in place.
    pub fn decrypt_ip16(&self, ip: &mut [u8; 16]) {
        // Safety: We have a valid IPCrypt instance and a valid mutable pointer to 16 bytes
        unsafe {
            ipcrypt_decrypt_ip16(&self.inner, ip.as_mut_ptr());
        }
    }

    /// Encrypts an IP address string (IPv4 or IPv6).
    ///
    /// On success, returns the encrypted IP string.
    pub fn encrypt_ip_str(&self, ip: &str) -> Result<String, IpcryptError> {
        let c_ip = CString::new(ip).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; MAX_IP_STR_BYTES];

        // Safety: We have valid pointers to initialized memory and a valid C string
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

        // Safety: The buffer is null-terminated and contains valid UTF-8
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(Into::into)
        }
    }

    /// Decrypts an encrypted IP address string.
    ///
    /// On success, returns the decrypted IP string.
    pub fn decrypt_ip_str(&self, encrypted: &str) -> Result<String, IpcryptError> {
        let c_encrypted = CString::new(encrypted).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; MAX_IP_STR_BYTES];
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
                .map_err(Into::into)
        }
    }

    /// Non-deterministically encrypts a 16-byte IP address.
    ///
    /// Returns a 24-byte encrypted value.
    pub fn nd_encrypt_ip16(&self, ip: &[u8; 16]) -> [u8; Self::NDIP_BYTES] {
        let random: [u8; Self::TWEAK_BYTES] = rand::random();
        let mut ndip = [0u8; Self::NDIP_BYTES];
        unsafe {
            ipcrypt_nd_encrypt_ip16(&self.inner, ndip.as_mut_ptr(), ip.as_ptr(), random.as_ptr());
        }
        ndip
    }

    /// Non-deterministically decrypts a 24-byte encrypted IP address.
    ///
    /// Returns the decrypted 16-byte IP address.
    pub fn nd_decrypt_ip16(&self, ndip: &[u8; Self::NDIP_BYTES]) -> [u8; 16] {
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
        let random: [u8; Self::TWEAK_BYTES] = rand::random();
        let mut buffer = [0u8; Self::NDIP_STR_BYTES];
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
                .map_err(Into::into)
        }
    }

    /// Non-deterministically decrypts a hex-encoded IP address string from non-deterministic mode.
    ///
    /// Returns the decrypted IP string on success.
    pub fn nd_decrypt_ip_str(&self, encrypted: &str) -> Result<String, IpcryptError> {
        let c_encrypted = CString::new(encrypted).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; MAX_IP_STR_BYTES];
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
                .map_err(Into::into)
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
        let mut buffer = [0u8; MAX_IP_STR_BYTES];
        let ret = unsafe { ipcrypt_ip16_to_str(buffer.as_mut_ptr() as *mut c_char, ip16.as_ptr()) };
        if ret == 0 {
            return Err(IpcryptError::OperationFailed);
        }
        unsafe {
            CStr::from_ptr(buffer.as_ptr() as *const c_char)
                .to_str()
                .map(|s| s.to_owned())
                .map_err(Into::into)
        }
    }

    /// Encrypts an IP address and returns the result as a new IP address.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.encrypt_ipaddr(ip).unwrap();
    /// ```
    pub fn encrypt_ipaddr(&self, ip: IpAddr) -> Result<IpAddr, IpcryptError> {
        let mut ip16 = ipaddr_to_ip16(ip);
        self.encrypt_ip16(&mut ip16);
        ip16_to_ipaddr(ip16)
    }

    /// Decrypts an encrypted IP address and returns the result as a new IP address.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.encrypt_ipaddr(ip).unwrap();
    /// let decrypted = ipcrypt.decrypt_ipaddr(encrypted).unwrap();
    /// assert_eq!(ip, decrypted);
    /// ```
    pub fn decrypt_ipaddr(&self, encrypted: IpAddr) -> Result<IpAddr, IpcryptError> {
        let mut ip16 = ipaddr_to_ip16(encrypted);
        self.decrypt_ip16(&mut ip16);
        ip16_to_ipaddr(ip16)
    }

    /// Non-deterministically encrypts an IP address and returns the result as a byte array.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.nd_encrypt_ipaddr(ip).unwrap();
    /// ```
    pub fn nd_encrypt_ipaddr(&self, ip: IpAddr) -> Result<[u8; Self::NDIP_BYTES], IpcryptError> {
        let ip16 = ipaddr_to_ip16(ip);
        Ok(self.nd_encrypt_ip16(&ip16))
    }

    /// Non-deterministically decrypts an encrypted IP address and returns the result as a new IP address.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address bytes to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.nd_encrypt_ipaddr(ip).unwrap();
    /// let decrypted = ipcrypt.nd_decrypt_ipaddr(encrypted).unwrap();
    /// assert_eq!(ip, decrypted);
    /// ```
    pub fn nd_decrypt_ipaddr(
        &self,
        encrypted: [u8; Self::NDIP_BYTES],
    ) -> Result<IpAddr, IpcryptError> {
        let decrypted = self.nd_decrypt_ip16(&encrypted);
        ip16_to_ipaddr(decrypted)
    }

    /// Non-deterministically encrypts an IP address and returns the result as a hex string.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.nd_encrypt_ipaddr_str(ip).unwrap();
    /// ```
    pub fn nd_encrypt_ipaddr_str(&self, ip: IpAddr) -> Result<String, IpcryptError> {
        let ip_str = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        };
        self.nd_encrypt_ip_str(&ip_str)
    }

    /// Non-deterministically decrypts an encrypted IP address string and returns the result as a new IP address.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address string to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    /// use std::net::IpAddr;
    ///
    /// let ipcrypt = Ipcrypt::new([0u8; 16]);
    /// let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    /// let encrypted = ipcrypt.nd_encrypt_ipaddr_str(ip).unwrap();
    /// let decrypted = ipcrypt.nd_decrypt_ipaddr_str(&encrypted).unwrap();
    /// assert_eq!(ip, decrypted);
    /// ```
    pub fn nd_decrypt_ipaddr_str(&self, encrypted: &str) -> Result<IpAddr, IpcryptError> {
        let decrypted_str = self.nd_decrypt_ip_str(encrypted)?;
        let ip = Ipcrypt::str_to_ip16(&decrypted_str)?;
        ip16_to_ipaddr(ip)
    }

    /// Creates a new Ipcrypt instance with a randomly generated key.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ipcrypt = Ipcrypt::new_random();
    /// ```
    pub fn new_random() -> Self {
        Self::new(Self::generate_key())
    }

    /// Encrypts an IP address string and returns the result as a new string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address string to encrypt (IPv4 or IPv6)
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ipcrypt = Ipcrypt::new_random();
    /// let encrypted = ipcrypt.encrypt("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn encrypt(&self, ip: &str) -> Result<String, IpcryptError> {
        self.encrypt_ip_str(ip)
    }

    /// Decrypts an encrypted IP address string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address string to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ipcrypt = Ipcrypt::new_random();
    /// let encrypted = ipcrypt.encrypt("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn decrypt(&self, encrypted: &str) -> Result<String, IpcryptError> {
        self.decrypt_ip_str(encrypted)
    }

    /// Non-deterministically encrypts an IP address string and returns the result as a hex string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address string to encrypt (IPv4 or IPv6)
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ipcrypt = Ipcrypt::new_random();
    /// let encrypted = ipcrypt.encrypt_nd("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt_nd(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn encrypt_nd(&self, ip: &str) -> Result<String, IpcryptError> {
        self.nd_encrypt_ip_str(ip)
    }

    /// Non-deterministically decrypts an encrypted IP address string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address string to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ipcrypt = Ipcrypt::new_random();
    /// let encrypted = ipcrypt.encrypt_nd("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt_nd(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn decrypt_nd(&self, encrypted: &str) -> Result<String, IpcryptError> {
        self.nd_decrypt_ip_str(encrypted)
    }

    /// Converts an IP address string to its 16-byte representation.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address string to convert
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ip16 = Ipcrypt::to_bytes("192.168.1.1").unwrap();
    /// let ip_str = Ipcrypt::from_bytes(&ip16).unwrap();
    /// assert_eq!("192.168.1.1", ip_str);
    /// ```
    pub fn to_bytes(ip: &str) -> Result<[u8; 16], IpcryptError> {
        Self::str_to_ip16(ip)
    }

    /// Converts a 16-byte IP address representation to a string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip16` - The 16-byte IP address to convert
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::Ipcrypt;
    ///
    /// let ip16 = Ipcrypt::to_bytes("192.168.1.1").unwrap();
    /// let ip_str = Ipcrypt::from_bytes(&ip16).unwrap();
    /// assert_eq!("192.168.1.1", ip_str);
    /// ```
    pub fn from_bytes(ip16: &[u8; 16]) -> Result<String, IpcryptError> {
        Self::ip16_to_str(ip16)
    }
}

impl Drop for Ipcrypt {
    fn drop(&mut self) {
        unsafe {
            ipcrypt_deinit(&mut self.inner);
        }
    }
}

/// A structure representing the IPCrypt context for NDX mode.
///
/// It can be only used for non-deterministic encryption with 16-byte tweaks.
///
/// Non-deterministic encryption in ND mode runs slower than encryption with 8-byte tweaks.
/// Ciphertexts are also longer, and the key is 32 byte long. However, the 16-byte tweak has higher
/// usage limits before collisions occur.
pub struct IpcryptNdx {
    inner: IPCryptNDX,
}

impl IpcryptNdx {
    /// The maximum number of bytes in the encrypted IP string (including null terminator) in NDX mode.
    pub const KEY_BYTES: usize = 32;

    /// The number of bytes in the tweak used for encryption/decryption in NDX mode.
    pub const TWEAK_BYTES: usize = 16;

    /// The maximum number of bytes in the encrypted IP string (including null terminator) in NDX mode.
    pub const NDIP_BYTES: usize = 32;

    /// The maximum number of bytes in the encrypted IP string (including null terminator) in NDX mode.
    pub const NDIP_STR_BYTES: usize = 64 + 1;

    /// Creates a random key for the Ipcrypt instance.
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new Ipcrypt instance with the given secret key.
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        let mut inner = std::mem::MaybeUninit::<IPCryptNDX>::uninit();
        unsafe {
            ipcrypt_ndx_init(inner.as_mut_ptr(), key.as_ptr());
            Self {
                inner: inner.assume_init(),
            }
        }
    }

    /// Non-deterministically encrypts a 16-byte IP address.
    ///
    /// Returns a 24-byte encrypted value.
    pub fn nd_encrypt_ip16(&self, ip: &[u8; 16]) -> [u8; Self::NDIP_BYTES] {
        let random: [u8; Self::TWEAK_BYTES] = rand::random();
        let mut ndip = [0u8; Self::NDIP_BYTES];
        unsafe {
            ipcrypt_ndx_encrypt_ip16(&self.inner, ndip.as_mut_ptr(), ip.as_ptr(), random.as_ptr());
        }
        ndip
    }

    /// Non-deterministically decrypts a 24-byte encrypted IP address.
    ///
    /// Returns the decrypted 16-byte IP address.
    pub fn nd_decrypt_ip16(&self, ndip: &[u8; Self::NDIP_BYTES]) -> [u8; 16] {
        let mut ip = [0u8; 16];
        unsafe {
            ipcrypt_ndx_decrypt_ip16(&self.inner, ip.as_mut_ptr(), ndip.as_ptr());
        }
        ip
    }

    /// Non-deterministically encrypts an IP address string (IPv4 or IPv6).
    ///
    /// Returns a hex-encoded string.
    pub fn nd_encrypt_ip_str(&self, ip: &str) -> Result<String, IpcryptError> {
        let c_ip = CString::new(ip).map_err(|_| IpcryptError::NullByteInInput)?;
        let random: [u8; Self::TWEAK_BYTES] = rand::random();
        let mut buffer = [0u8; Self::NDIP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_ndx_encrypt_ip_str(
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
                .map_err(Into::into)
        }
    }

    /// Non-deterministically decrypts a hex-encoded IP address string from non-deterministic mode.
    ///
    /// Returns the decrypted IP string on success.
    pub fn nd_decrypt_ip_str(&self, encrypted: &str) -> Result<String, IpcryptError> {
        let c_encrypted = CString::new(encrypted).map_err(|_| IpcryptError::NullByteInInput)?;
        let mut buffer = [0u8; MAX_IP_STR_BYTES];
        let ret = unsafe {
            ipcrypt_ndx_decrypt_ip_str(
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
                .map_err(Into::into)
        }
    }

    // --- Additional interfaces using std::net::IpAddr ---

    /// Non-deterministically encrypts an `IpAddr` using the IP string interface.
    ///
    /// Returns the encrypted IP as an `IpAddr`.
    pub fn nd_encrypt_ipaddr(&self, ip: IpAddr) -> Result<[u8; Self::NDIP_BYTES], IpcryptError> {
        let ip_str = ipaddr_to_ip16(ip);
        let encrypted = self.nd_encrypt_ip16(&ip_str);
        Ok(encrypted)
    }

    /// Non-deterministically decrypts an encrypted `IpAddr` (provided as an `IpAddr` type).
    ///
    /// Returns the original `IpAddr` on success.
    pub fn nd_decrypt_ipaddr(
        &self,
        encrypted: [u8; Self::NDIP_BYTES],
    ) -> Result<IpAddr, IpcryptError> {
        let decrypted = self.nd_decrypt_ip16(&encrypted);
        let decrypted_ip = ip16_to_ipaddr(decrypted)?;
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
        ip16_to_ipaddr(ip)
    }

    /// Creates a new IpcryptNdx instance with a randomly generated key.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::IpcryptNdx;
    ///
    /// let ipcrypt = IpcryptNdx::new_random();
    /// ```
    pub fn new_random() -> Self {
        Self::new(Self::generate_key())
    }

    /// Non-deterministically encrypts an IP address string and returns the result as a hex string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address string to encrypt (IPv4 or IPv6)
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::IpcryptNdx;
    ///
    /// let ipcrypt = IpcryptNdx::new_random();
    /// let encrypted = ipcrypt.encrypt("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn encrypt(&self, ip: &str) -> Result<String, IpcryptError> {
        self.nd_encrypt_ip_str(ip)
    }

    /// Non-deterministically decrypts an encrypted IP address string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address string to decrypt
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::IpcryptNdx;
    ///
    /// let ipcrypt = IpcryptNdx::new_random();
    /// let encrypted = ipcrypt.encrypt("192.168.1.1").unwrap();
    /// let decrypted = ipcrypt.decrypt(&encrypted).unwrap();
    /// assert_eq!("192.168.1.1", decrypted);
    /// ```
    pub fn decrypt(&self, encrypted: &str) -> Result<String, IpcryptError> {
        self.nd_decrypt_ip_str(encrypted)
    }

    /// Converts an IP address string to its 16-byte representation.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address string to convert
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::IpcryptNdx;
    ///
    /// let ip16 = IpcryptNdx::to_bytes("192.168.1.1").unwrap();
    /// let ip_str = IpcryptNdx::from_bytes(&ip16).unwrap();
    /// assert_eq!("192.168.1.1", ip_str);
    /// ```
    pub fn to_bytes(ip: &str) -> Result<[u8; 16], IpcryptError> {
        Ipcrypt::str_to_ip16(ip)
    }

    /// Converts a 16-byte IP address representation to a string.
    /// This is a convenience method that handles both IPv4 and IPv6 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip16` - The 16-byte IP address to convert
    ///
    /// # Examples
    ///
    /// ```
    /// use ipcrypt2::IpcryptNdx;
    ///
    /// let ip16 = IpcryptNdx::to_bytes("192.168.1.1").unwrap();
    /// let ip_str = IpcryptNdx::from_bytes(&ip16).unwrap();
    /// assert_eq!("192.168.1.1", ip_str);
    /// ```
    pub fn from_bytes(ip16: &[u8; 16]) -> Result<String, IpcryptError> {
        Ipcrypt::ip16_to_str(ip16)
    }
}

impl Drop for IpcryptNdx {
    fn drop(&mut self) {
        unsafe {
            ipcrypt_ndx_deinit(&mut self.inner);
        }
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

/// The maximum number of bytes in the encrypted IP string.
pub const MAX_IP_STR_BYTES: usize = 46;

/// Converts a 16-byte binary IP address into a string.
///
/// Returns the IP string on success.
pub fn ip16_to_str(ip16: &[u8; 16]) -> Result<String, IpcryptError> {
    let mut buffer = [0u8; MAX_IP_STR_BYTES];
    let ret = unsafe { ipcrypt_ip16_to_str(buffer.as_mut_ptr() as *mut c_char, ip16.as_ptr()) };
    if ret == 0 {
        return Err(IpcryptError::OperationFailed);
    }
    unsafe {
        CStr::from_ptr(buffer.as_ptr() as *const c_char)
            .to_str()
            .map(|s| s.to_owned())
            .map_err(Into::into)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip16_encrypt_decrypt() {
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);
        let mut ip = [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let original = ip;
        ipcrypt.encrypt_ip16(&mut ip);
        assert_ne!(ip, original);
        ipcrypt.decrypt_ip16(&mut ip);
        assert_eq!(ip, original);
    }

    #[test]
    fn test_ip_str_encrypt_decrypt() {
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);
        let ip = "192.168.1.1";
        let encrypted = ipcrypt.encrypt_ip_str(ip).expect("Encryption failed");
        let decrypted = ipcrypt
            .decrypt_ip_str(&encrypted)
            .expect("Decryption failed");
        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_nd_ip16_encrypt_decrypt() {
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);
        let ip: [u8; 16] = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nd_encrypted = ipcrypt.nd_encrypt_ip16(&ip);
        let decrypted = ipcrypt.nd_decrypt_ip16(&nd_encrypted);
        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_nd_ip_str_encrypt_decrypt() {
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);
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
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);

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
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);

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
        let key = [0u8; Ipcrypt::KEY_BYTES];
        let ipcrypt = Ipcrypt::new(key);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nd_encrypted = ipcrypt
            .nd_encrypt_ipaddr_str(ip)
            .expect("ND Encryption failed");
        let nd_decrypted = ipcrypt
            .nd_decrypt_ipaddr_str(&nd_encrypted)
            .expect("ND Decryption failed");
        assert_eq!(ip, nd_decrypted);
    }

    #[test]
    fn test_nxd_encrypt_decrypt_ipaddr() {
        let key = [0u8; IpcryptNdx::KEY_BYTES];
        let ipcrypt = IpcryptNdx::new(key);

        // Test IPv4
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let encrypted_v4 = ipcrypt
            .nd_encrypt_ipaddr(ip_v4)
            .expect("NDX Encryption failed");
        let decrypted_v4 = ipcrypt
            .nd_decrypt_ipaddr(encrypted_v4)
            .expect("NDX Decryption failed");
        assert_eq!(ip_v4, decrypted_v4);

        // Test IPv6
        let ip_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let encrypted_v6 = ipcrypt
            .nd_encrypt_ipaddr(ip_v6)
            .expect("NDX Encryption failed");
        let decrypted_v6 = ipcrypt
            .nd_decrypt_ipaddr(encrypted_v6)
            .expect("NDX Decryption failed");
        assert_eq!(ip_v6, decrypted_v6);
    }

    #[test]
    fn test_ndx_ipaddr_str_encrypt_decrypt() {
        let key = [0u8; IpcryptNdx::KEY_BYTES];
        let ipcrypt = IpcryptNdx::new(key);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nd_encrypted = ipcrypt
            .nd_encrypt_ipaddr_str(ip)
            .expect("NDX Encryption failed");
        let nd_decrypted = ipcrypt
            .nd_decrypt_ipaddr_str(&nd_encrypted)
            .expect("NDX Decryption failed");
        assert_eq!(ip, nd_decrypted);
    }
}
