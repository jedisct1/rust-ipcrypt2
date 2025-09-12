use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Block;
use std::net::IpAddr;

use crate::common::{bytes_to_ip, ip_to_bytes};

/// A structure representing the IPCrypt context for prefix-preserving mode.
pub struct IpcryptPfx {
    cipher1: Aes128,
    cipher2: Aes128,
}

impl IpcryptPfx {
    /// The number of bytes required for the encryption key.
    pub const KEY_BYTES: usize = 32;

    /// Generates a new random key for encryption.
    #[cfg(feature = "random")]
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new IpcryptPfx instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte array containing the encryption key.
    ///
    /// # Panics
    ///
    /// Panics if the two halves of the key are identical, as this would
    /// compromise the security of the encryption.
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        // Split the key into two 16-byte halves
        let (k1, k2) = key.split_at(16);

        // Ensure the two halves are different
        assert_ne!(k1, k2, "The two halves of the key must be different");

        let cipher1 = Aes128::new_from_slice(k1).expect("key length is guaranteed to be correct");
        let cipher2 = Aes128::new_from_slice(k2).expect("key length is guaranteed to be correct");

        Self { cipher1, cipher2 }
    }

    /// Creates a new IpcryptPfx instance with a random key.
    #[cfg(feature = "random")]
    pub fn new_random() -> Self {
        loop {
            let key = Self::generate_key();
            let (k1, k2) = key.split_at(16);
            if k1 != k2 {
                return Self::new(key);
            }
        }
    }

    /// Encrypts an IP address using prefix-preserving encryption.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted IP address
    pub fn encrypt_ipaddr(&self, ip: IpAddr) -> IpAddr {
        let bytes = ip_to_bytes(ip);
        let encrypted = self.encrypt_bytes(&bytes, ip);
        bytes_to_ip(encrypted)
    }

    /// Decrypts an IP address using prefix-preserving encryption.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted IP address
    ///
    /// # Returns
    ///
    /// The decrypted IP address
    pub fn decrypt_ipaddr(&self, encrypted: IpAddr) -> IpAddr {
        let encrypted_bytes = ip_to_bytes(encrypted);
        let decrypted = self.decrypt_bytes(&encrypted_bytes, encrypted);
        bytes_to_ip(decrypted)
    }

    /// Internal method to encrypt bytes
    fn encrypt_bytes(&self, bytes: &[u8; 16], ip: IpAddr) -> [u8; 16] {
        let mut encrypted = [0u8; 16];

        // Determine starting point
        let prefix_start = if ip.is_ipv4() { 96 } else { 0 };

        // If IPv4, copy the IPv4-mapped prefix
        if ip.is_ipv4() {
            encrypted[..12].copy_from_slice(&bytes[..12]);
        }

        // Initialize padded_prefix for the starting prefix length
        let mut padded_prefix = if prefix_start == 0 {
            Self::pad_prefix_0()
        } else {
            Self::pad_prefix_96()
        };

        // Process each bit position
        for prefix_len_bits in prefix_start..128 {
            // Compute pseudorandom function with dual AES encryption
            let mut block1 = Block::from(padded_prefix);
            let mut block2 = Block::from(padded_prefix);

            self.cipher1.encrypt_block(&mut block1);
            self.cipher2.encrypt_block(&mut block2);

            // XOR the two encryptions
            let e1: [u8; 16] = block1.into();
            let e2: [u8; 16] = block2.into();
            let mut e = [0u8; 16];
            for i in 0..16 {
                e[i] = e1[i] ^ e2[i];
            }

            // Extract the least significant bit
            let cipher_bit = e[15] & 1;

            // Get the current bit position
            let bit_pos = 127 - prefix_len_bits;
            let original_bit = Self::get_bit(bytes, bit_pos);

            // Set the bit in the encrypted result
            Self::set_bit(&mut encrypted, bit_pos, cipher_bit ^ original_bit);

            // Prepare padded_prefix for next iteration
            padded_prefix = Self::shift_left_one_bit(&padded_prefix);
            Self::set_bit(&mut padded_prefix, 0, original_bit);
        }

        encrypted
    }

    /// Internal method to decrypt bytes
    fn decrypt_bytes(&self, encrypted_bytes: &[u8; 16], encrypted_ip: IpAddr) -> [u8; 16] {
        let mut decrypted = [0u8; 16];

        // For decryption, determine if this was originally IPv4
        let prefix_start = if encrypted_ip.is_ipv4() { 96 } else { 0 };

        // If this was originally IPv4, set up the IPv4-mapped IPv6 prefix
        if prefix_start == 96 {
            decrypted[10..12].copy_from_slice(&[0xFF; 2]);
        }

        // Initialize padded_prefix for the starting prefix length
        let mut padded_prefix = if prefix_start == 0 {
            Self::pad_prefix_0()
        } else {
            Self::pad_prefix_96()
        };

        // Process each bit position
        for prefix_len_bits in prefix_start..128 {
            // Compute pseudorandom function with dual AES encryption
            let mut block1 = Block::from(padded_prefix);
            let mut block2 = Block::from(padded_prefix);

            self.cipher1.encrypt_block(&mut block1);
            self.cipher2.encrypt_block(&mut block2);

            // XOR the two encryptions
            let e1: [u8; 16] = block1.into();
            let e2: [u8; 16] = block2.into();
            let mut e = [0u8; 16];
            for i in 0..16 {
                e[i] = e1[i] ^ e2[i];
            }

            // Extract the least significant bit
            let cipher_bit = e[15] & 1;

            // Get the current bit position
            let bit_pos = 127 - prefix_len_bits;
            let encrypted_bit = Self::get_bit(encrypted_bytes, bit_pos);
            let original_bit = cipher_bit ^ encrypted_bit;

            // Set the bit in the decrypted result
            Self::set_bit(&mut decrypted, bit_pos, original_bit);

            // Prepare padded_prefix for next iteration
            padded_prefix = Self::shift_left_one_bit(&padded_prefix);
            Self::set_bit(&mut padded_prefix, 0, original_bit);
        }

        decrypted
    }

    /// Extract bit at position from 16-byte array.
    /// position: 0 = LSB of byte 15, 127 = MSB of byte 0
    fn get_bit(data: &[u8; 16], position: usize) -> u8 {
        let byte_index = 15 - (position / 8);
        let bit_index = position % 8;
        (data[byte_index] >> bit_index) & 1
    }

    /// Set bit at position in 16-byte array.
    /// position: 0 = LSB of byte 15, 127 = MSB of byte 0
    fn set_bit(data: &mut [u8; 16], position: usize, value: u8) {
        let byte_index = 15 - (position / 8);
        let bit_index = position % 8;
        if value != 0 {
            data[byte_index] |= 1 << bit_index;
        } else {
            data[byte_index] &= !(1 << bit_index);
        }
    }

    /// Shift a 16-byte array one bit to the left.
    /// The most significant bit is lost, and a zero bit is shifted in from the right.
    fn shift_left_one_bit(data: &[u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        let mut carry = 0;

        // Process from least significant byte (byte 15) to most significant (byte 0)
        for i in (0..16).rev() {
            // Current byte shifted left by 1, with carry from previous byte
            result[i] = (data[i] << 1) | carry;
            // Extract the bit that will be carried to the next byte
            carry = (data[i] >> 7) & 1;
        }

        result
    }

    /// Pad prefix for prefix_len_bits=0 (IPv6).
    /// Sets separator bit at position 0 (LSB of byte 15).
    fn pad_prefix_0() -> [u8; 16] {
        let mut padded = [0u8; 16];
        padded[15] = 0x01; // Set bit at position 0 (LSB of byte 15)
        padded
    }

    /// Pad prefix for prefix_len_bits=96 (IPv4).
    /// For IPv4, the data always has format: 00...00 ffff xxxx (IPv4-mapped)
    /// Result: 00000001 00...00 0000ffff (separator at pos 96, then 96 bits)
    fn pad_prefix_96() -> [u8; 16] {
        let mut padded = [0u8; 16];
        padded[3] = 0x01; // Set bit at position 96 (bit 0 of byte 3)
        padded[14] = 0xFF;
        padded[15] = 0xFF;
        padded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder as _, Hex};
    use std::str::FromStr;

    #[test]
    fn test_pfx_basic_vectors() {
        let test_vectors = vec![
            // Test vector 1 (IPv4)
            (
                "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
                "0.0.0.0",
                "151.82.155.134",
            ),
            // Test vector 2 (IPv4)
            (
                "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
                "255.255.255.255",
                "94.185.169.89",
            ),
            // Test vector 3 (IPv4)
            (
                "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
                "192.0.2.1",
                "100.115.72.131",
            ),
            // Test vector 4 (IPv6)
            (
                "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
                "2001:db8::1",
                "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88",
            ),
        ];

        for (key_hex, input_ip, expected_output) in test_vectors {
            // Parse key using constant-time hex decoder
            let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
            let mut key = [0u8; IpcryptPfx::KEY_BYTES];
            key.copy_from_slice(&key_vec);

            // Create IpcryptPfx instance
            let ipcrypt = IpcryptPfx::new(key);

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
    fn test_pfx_prefix_preserving_ipv4_24() {
        let key_hex = "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a";
        let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
        let mut key = [0u8; IpcryptPfx::KEY_BYTES];
        key.copy_from_slice(&key_vec);
        let ipcrypt = IpcryptPfx::new(key);

        // Test IPv4 addresses from same /24 network
        let test_cases = vec![
            ("10.0.0.47", "19.214.210.244"),
            ("10.0.0.129", "19.214.210.80"),
            ("10.0.0.234", "19.214.210.30"),
        ];

        for (input_ip, expected_output) in test_cases {
            let ip = IpAddr::from_str(input_ip).unwrap();
            let encrypted = ipcrypt.encrypt_ipaddr(ip);
            assert_eq!(encrypted.to_string(), expected_output);

            let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
            assert_eq!(decrypted, ip);
        }

        // Verify prefix preservation: first 24 bits should be the same
        let ip1 = IpAddr::from_str("10.0.0.47").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.129").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.234").unwrap();

        let enc1 = ipcrypt.encrypt_ipaddr(ip1);
        let enc2 = ipcrypt.encrypt_ipaddr(ip2);
        let enc3 = ipcrypt.encrypt_ipaddr(ip3);

        // All encrypted addresses should be IPv4
        assert!(enc1.is_ipv4());
        assert!(enc2.is_ipv4());
        assert!(enc3.is_ipv4());

        // Extract first 24 bits of each encrypted address
        let enc1_bytes = match enc1 {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("Expected IPv4"),
        };
        let enc2_bytes = match enc2 {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("Expected IPv4"),
        };
        let enc3_bytes = match enc3 {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("Expected IPv4"),
        };

        // First 3 bytes should be identical
        assert_eq!(enc1_bytes[0], enc2_bytes[0]);
        assert_eq!(enc1_bytes[0], enc3_bytes[0]);
        assert_eq!(enc1_bytes[1], enc2_bytes[1]);
        assert_eq!(enc1_bytes[1], enc3_bytes[1]);
        assert_eq!(enc1_bytes[2], enc2_bytes[2]);
        assert_eq!(enc1_bytes[2], enc3_bytes[2]);
    }

    #[test]
    fn test_pfx_prefix_preserving_ipv4_16() {
        let key_hex = "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a";
        let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
        let mut key = [0u8; IpcryptPfx::KEY_BYTES];
        key.copy_from_slice(&key_vec);
        let ipcrypt = IpcryptPfx::new(key);

        // Test IPv4 addresses from same /16 but different /24 networks
        let test_cases = vec![
            ("172.16.5.193", "210.78.229.136"),
            ("172.16.97.42", "210.78.179.241"),
            ("172.16.248.177", "210.78.121.215"),
        ];

        for (input_ip, expected_output) in test_cases {
            let ip = IpAddr::from_str(input_ip).unwrap();
            let encrypted = ipcrypt.encrypt_ipaddr(ip);
            assert_eq!(encrypted.to_string(), expected_output);

            let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
            assert_eq!(decrypted, ip);
        }
    }

    #[test]
    fn test_pfx_prefix_preserving_ipv6_64() {
        let key_hex = "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a";
        let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
        let mut key = [0u8; IpcryptPfx::KEY_BYTES];
        key.copy_from_slice(&key_vec);
        let ipcrypt = IpcryptPfx::new(key);

        // Test IPv6 addresses from same /64 network
        let test_cases = vec![
            (
                "2001:db8::a5c9:4e2f:bb91:5a7d",
                "7cec:702c:1243:f70:1956:125:b9bd:1aba",
            ),
            (
                "2001:db8::7234:d8f1:3c6e:9a52",
                "7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d",
            ),
            (
                "2001:db8::f1e0:937b:26d4:8c1a",
                "7cec:702c:1243:f70:443c:c8e:6a62:b64d",
            ),
        ];

        for (input_ip, expected_output) in test_cases {
            let ip = IpAddr::from_str(input_ip).unwrap();
            let encrypted = ipcrypt.encrypt_ipaddr(ip);
            assert_eq!(encrypted.to_string(), expected_output);

            let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
            assert_eq!(decrypted, ip);
        }
    }

    #[test]
    fn test_pfx_prefix_preserving_ipv6_32() {
        let key_hex = "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a";
        let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
        let mut key = [0u8; IpcryptPfx::KEY_BYTES];
        key.copy_from_slice(&key_vec);
        let ipcrypt = IpcryptPfx::new(key);

        // Test IPv6 addresses from same /32 but different /48 networks
        let test_cases = vec![
            (
                "2001:db8:3a5c::e7d1:4b9f:2c8a:f673",
                "7cec:702c:3503:bef:e616:96bd:be33:a9b9",
            ),
            (
                "2001:db8:9f27::b4e2:7a3d:5f91:c8e6",
                "7cec:702c:a504:b74e:194a:3d90:b047:2d1a",
            ),
            (
                "2001:db8:d8b4::193c:a5e7:8b2f:46d1",
                "7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb",
            ),
        ];

        for (input_ip, expected_output) in test_cases {
            let ip = IpAddr::from_str(input_ip).unwrap();
            let encrypted = ipcrypt.encrypt_ipaddr(ip);
            assert_eq!(encrypted.to_string(), expected_output);

            let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
            assert_eq!(decrypted, ip);
        }
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_random_key() {
        let ipcrypt = IpcryptPfx::new_random();
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        let encrypted = ipcrypt.encrypt_ipaddr(ip);
        let decrypted = ipcrypt.decrypt_ipaddr(encrypted);
        assert_eq!(ip, decrypted);
    }

    #[test]
    #[should_panic(expected = "The two halves of the key must be different")]
    fn test_identical_key_halves() {
        let mut key = [0u8; 32];
        // Make both halves identical
        key[0..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        key[16..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        IpcryptPfx::new(key);
    }

    #[test]
    fn test_bit_operations() {
        let mut data = [0u8; 16];

        // Test setting and getting bits
        for pos in 0..128 {
            IpcryptPfx::set_bit(&mut data, pos, 1);
            assert_eq!(IpcryptPfx::get_bit(&data, pos), 1);
            IpcryptPfx::set_bit(&mut data, pos, 0);
            assert_eq!(IpcryptPfx::get_bit(&data, pos), 0);
        }
    }

    #[test]
    fn test_shift_left() {
        let data = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = IpcryptPfx::shift_left_one_bit(&data);

        // After shift left, the MSB should be lost and a 0 shifted in at LSB
        assert_eq!(result[0], 0x00); // MSB was 1, now lost
        assert_eq!(result[15], 0x02); // LSB was 1, shifted left
    }

    #[test]
    fn test_pad_prefix() {
        let padded0 = IpcryptPfx::pad_prefix_0();
        assert_eq!(padded0[15], 0x01);
        assert_eq!(padded0[0..15], [0u8; 15]);

        let padded96 = IpcryptPfx::pad_prefix_96();
        assert_eq!(padded96[3], 0x01);
        assert_eq!(padded96[14], 0xFF);
        assert_eq!(padded96[15], 0xFF);
        assert_eq!(padded96[0..3], [0u8; 3]);
        assert_eq!(padded96[4..14], [0u8; 10]);
    }
}
