use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Block;
use std::net::IpAddr;

use crate::common::{bytes_to_ip, ip_to_bytes};

/// A structure representing the IPCrypt context for deterministic mode.
pub struct Ipcrypt {
    cipher: Aes128,
}

impl Ipcrypt {
    /// The number of bytes required for the encryption key.
    pub const KEY_BYTES: usize = 16;

    /// Generates a new random key for encryption.
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new Ipcrypt instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 16-byte array containing the encryption key.
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        let cipher = Aes128::new_from_slice(&key).expect("key length is guaranteed to be correct");
        Self { cipher }
    }

    /// Creates a new Ipcrypt instance with a random key.
    pub fn new_random() -> Self {
        Self::new(Self::generate_key())
    }

    /// Encrypts a 16-byte IP address in place.
    pub fn encrypt_ip16(&self, ip: &mut [u8; 16]) {
        let mut block = Block::from(*ip);
        self.cipher.encrypt_block(&mut block);
        *ip = block.into();
    }

    /// Decrypts a 16-byte IP address in place.
    pub fn decrypt_ip16(&self, ip: &mut [u8; 16]) {
        let mut block = Block::from(*ip);
        self.cipher.decrypt_block(&mut block);
        *ip = block.into();
    }

    /// Encrypts an IP address.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    ///
    /// # Returns
    /// The encrypted IP address
    pub fn encrypt_ipaddr(&self, ip: IpAddr) -> IpAddr {
        let mut bytes = ip_to_bytes(ip);
        self.encrypt_ip16(&mut bytes);
        bytes_to_ip(bytes)
    }

    /// Decrypts an IP address.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address
    ///
    /// # Returns
    /// The decrypted IP address
    pub fn decrypt_ipaddr(&self, encrypted: IpAddr) -> IpAddr {
        let mut bytes = ip_to_bytes(encrypted);
        self.decrypt_ip16(&mut bytes);
        bytes_to_ip(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder as _, Hex};
    use std::str::FromStr;

    #[test]
    fn test_deterministic_vectors() {
        let test_vectors = vec![
            (
                // Test vector 1
                "0123456789abcdeffedcba9876543210",
                "0.0.0.0",
                "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb",
            ),
            (
                // Test vector 2
                "1032547698badcfeefcdab8967452301",
                "255.255.255.255",
                "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8",
            ),
            (
                // Test vector 3
                "2b7e151628aed2a6abf7158809cf4f3c",
                "192.0.2.1",
                "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777",
            ),
        ];

        for (key_hex, input_ip, expected_output) in test_vectors {
            // Parse key using constant-time hex decoder
            let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
            let mut key = [0u8; Ipcrypt::KEY_BYTES];
            key.copy_from_slice(&key_vec);

            // Create Ipcrypt instance
            let ipcrypt = Ipcrypt::new(key);

            // Parse input IP
            let ip = IpAddr::from_str(input_ip).unwrap();

            // Encrypt
            let encrypted = ipcrypt.encrypt_ipaddr(ip);
            assert_eq!(encrypted.to_string(), expected_output);

            // Decrypt
            let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
            assert_eq!(decrypted, ip);
        }
    }

    #[test]
    fn test_random_key() {
        let ipcrypt = Ipcrypt::new_random();
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        let encrypted = ipcrypt.encrypt_ipaddr(ip);
        let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
        assert_eq!(ip, decrypted);
    }
}
