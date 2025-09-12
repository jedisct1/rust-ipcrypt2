use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use std::net::IpAddr;

use crate::common::{bytes_to_ip, ip_to_bytes};

/// A structure representing the IPCrypt context for non-deterministic XTS mode encryption.
///
/// This struct provides methods for encrypting and decrypting IP addresses using AES-XTS mode
/// with a 16-byte tweak. The key is 32 bytes (two AES-128 keys).
pub struct IpcryptNdx {
    cipher1: Aes128, // For data encryption
    cipher2: Aes128, // For tweak encryption
}

impl IpcryptNdx {
    /// The number of bytes required for the encryption key (two AES-128 keys).
    pub const KEY_BYTES: usize = 32;
    /// The number of bytes required for the tweak.
    pub const TWEAK_BYTES: usize = 16;
    /// The number of bytes of the encrypted IP address.
    pub const NDIP_BYTES: usize = 32;

    /// Generates a new random key for encryption.
    #[cfg(feature = "random")]
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new IpcryptNdx instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte array containing two AES-128 keys.
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        let (key1, key2) = key.split_at(Self::KEY_BYTES / 2);
        let cipher1 = Aes128::new_from_slice(key1).expect("key1 length is correct");
        let cipher2 = Aes128::new_from_slice(key2).expect("key2 length is correct");
        Self { cipher1, cipher2 }
    }

    /// Creates a new IpcryptNdx instance with a random key.
    #[cfg(feature = "random")]
    pub fn new_random() -> Self {
        Self::new(Self::generate_key())
    }

    /// Generates a random tweak.
    #[cfg(feature = "random")]
    pub fn generate_tweak() -> [u8; Self::TWEAK_BYTES] {
        rand::random()
    }

    /// Encrypts a 16-byte IP address using XTS mode.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address bytes to encrypt
    /// * `tweak` - The tweak to use for encryption
    fn encrypt_ip16(&self, ip: &mut [u8; 16], tweak: &[u8; Self::TWEAK_BYTES]) {
        // First encrypt the tweak with the second key
        let mut encrypted_tweak = Block::from(*tweak);
        self.cipher2.encrypt_block(&mut encrypted_tweak);

        // XOR the input with the encrypted tweak
        let mut block = Block::from(*ip);
        for (b, t) in block.iter_mut().zip(encrypted_tweak.iter()) {
            *b ^= t;
        }

        // Encrypt with the first key
        self.cipher1.encrypt_block(&mut block);

        // XOR with the encrypted tweak again
        for (b, t) in block.iter_mut().zip(encrypted_tweak.iter()) {
            *b ^= t;
        }

        *ip = block.into();
    }

    /// Decrypts a 16-byte IP address using XTS mode.
    ///
    /// # Arguments
    ///
    /// * `ip` - The encrypted IP address bytes to decrypt
    /// * `tweak` - The tweak used for encryption
    fn decrypt_ip16(&self, ip: &mut [u8; 16], tweak: &[u8; Self::TWEAK_BYTES]) {
        // First encrypt the tweak with the second key
        let mut encrypted_tweak = Block::from(*tweak);
        self.cipher2.encrypt_block(&mut encrypted_tweak);

        // XOR the input with the encrypted tweak
        let mut block = Block::from(*ip);
        for (b, t) in block.iter_mut().zip(encrypted_tweak.iter()) {
            *b ^= t;
        }

        // Decrypt with the first key
        self.cipher1.decrypt_block(&mut block);

        // XOR with the encrypted tweak again
        for (b, t) in block.iter_mut().zip(encrypted_tweak.iter()) {
            *b ^= t;
        }

        *ip = block.into();
    }

    /// Encrypts an IP address using XTS mode.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    /// * `tweak` - Optional tweak to use. If None, a random tweak will be generated.
    ///
    /// # Returns
    /// The encrypted IP address, as a byte array of length 32.
    pub fn encrypt_ipaddr(
        &self,
        ip: IpAddr,
        tweak: Option<[u8; Self::TWEAK_BYTES]>,
    ) -> [u8; Self::NDIP_BYTES] {
        let mut out: [u8; Self::NDIP_BYTES] = [0; Self::NDIP_BYTES];
        #[cfg(feature = "random")]
        let tweak = tweak.unwrap_or_else(Self::generate_tweak);
        #[cfg(not(feature = "random"))]
        let tweak = tweak.expect("tweak must be provided when random feature is disabled");
        let mut bytes = ip_to_bytes(ip);
        self.encrypt_ip16(&mut bytes, &tweak);
        out[0..16].copy_from_slice(&tweak);
        out[16..].copy_from_slice(&bytes);
        out
    }

    /// Decrypts an IP address using XTS mode.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address as a byte array of length 32.
    /// * `tweak` - The tweak used for encryption
    ///
    /// # Returns
    /// The decrypted IP address
    pub fn decrypt_ipaddr(&self, encrypted: &[u8; Self::NDIP_BYTES]) -> IpAddr {
        let mut tweak = [0u8; Self::TWEAK_BYTES];
        tweak.copy_from_slice(&encrypted[0..16]);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&encrypted[16..]);
        self.decrypt_ip16(&mut bytes, &tweak);
        bytes_to_ip(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder as _, Encoder as _, Hex};
    use std::str::FromStr;

    #[test]
    fn test_ndx_vectors() {
        let test_vectors = vec![
            (
                // Test vector 1
                "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
                "0.0.0.0",
                "21bd1834bc088cd2b4ecbe30b70898d7",
                "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5",
            ),
            (
                // Test vector 2
                "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
                "192.0.2.1",
                "08e0c289bff23b7cb4ecbe30b70898d7",
                "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a",
            ),
            (
                // Test vector 3
                "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
                "2001:db8::1",
                "21bd1834bc088cd2b4ecbe30b70898d7",
                "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4",
            ),
        ];

        for (key_hex, input_ip, tweak_hex, expected_output) in test_vectors {
            // Parse key using constant-time hex decoder
            let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
            let mut key = [0u8; IpcryptNdx::KEY_BYTES];
            key.copy_from_slice(&key_vec);

            // Parse tweak
            let tweak_vec = Hex::decode_to_vec(tweak_hex.as_bytes(), None).unwrap();
            let mut tweak = [0u8; IpcryptNdx::TWEAK_BYTES];
            tweak.copy_from_slice(&tweak_vec);

            // Create IpcryptNdx instance
            let ipcrypt = IpcryptNdx::new(key);

            // Parse input IP
            let ip = IpAddr::from_str(input_ip).unwrap();

            // Encrypt with provided tweak
            let encrypted = ipcrypt.encrypt_ipaddr(ip, Some(tweak));

            // Convert to hex string for comparison
            let encrypted_hex = Hex::encode_to_string(encrypted).unwrap();
            assert_eq!(encrypted_hex, expected_output);

            // Test decryption
            let decrypted = ipcrypt.decrypt_ipaddr(&encrypted);
            assert_eq!(decrypted, ip);
        }
    }
}
