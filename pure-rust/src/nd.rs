use aes::hazmat;
use aes::Block;
use std::net::IpAddr;

use crate::aes::*;
use crate::common::{bytes_to_ip, ip_to_bytes};

/// A structure representing the IPCrypt context for non-deterministic mode.
///
/// This struct provides methods for encrypting and decrypting IP addresses using KIASU-BC mode
/// with an 8-byte tweak. The key is 16 bytes (one AES-128 key).
pub struct IpcryptNd {
    round_keys: Vec<Block>,
}

impl Drop for IpcryptNd {
    fn drop(&mut self) {
        self.round_keys.clear();
    }
}

impl IpcryptNd {
    /// The number of bytes required for the encryption key.
    pub const KEY_BYTES: usize = 16;
    /// The number of bytes required for the tweak.
    pub const TWEAK_BYTES: usize = 8;
    /// The number of bytes in the non-deterministic mode output (8-byte tweak + 16-byte ciphertext).
    pub const NDIP_BYTES: usize = Self::TWEAK_BYTES + 16;

    /// Generates a new random key for encryption.
    pub fn generate_key() -> [u8; Self::KEY_BYTES] {
        rand::random()
    }

    /// Creates a new IpcryptNd instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 16-byte array containing the encryption key.
    pub fn new(key: [u8; Self::KEY_BYTES]) -> Self {
        let round_keys = Self::expand_key(&key);
        Self { round_keys }
    }

    /// Creates a new IpcryptNd instance with a random key.
    pub fn new_random() -> Self {
        Self::new(Self::generate_key())
    }

    /// Generates a random tweak.
    pub fn generate_tweak() -> [u8; Self::TWEAK_BYTES] {
        rand::random()
    }

    /// Pads an 8-byte tweak to 16 bytes according to KIASU-BC specification.
    /// The tweak is padded by placing each 2-byte pair at the start of a 4-byte group.
    fn pad_tweak(tweak: &[u8; Self::TWEAK_BYTES]) -> Block {
        let mut padded = Block::default();
        for i in (0..8).step_by(2) {
            padded[i * 2] = tweak[i];
            padded[i * 2 + 1] = tweak[i + 1];
        }
        padded
    }

    /// Encrypts a 16-byte IP address using KIASU-BC mode.
    ///
    /// This is an internal function that performs the core KIASU-BC encryption.
    /// For public use, prefer `encrypt_ipaddr`.
    fn encrypt_ip16(&self, ip: &mut [u8; 16], tweak: &[u8; Self::TWEAK_BYTES]) {
        let padded_tweak = Self::pad_tweak(tweak);
        let mut block = Block::from(*ip);

        // Initial round
        for i in 0..16 {
            block[i] ^= self.round_keys[0][i] ^ padded_tweak[i];
        }

        // Main rounds
        for round in 1..10 {
            // Create tweaked round key by XORing round key with tweak
            let mut tweaked_key = self.round_keys[round];
            for i in 0..16 {
                tweaked_key[i] ^= padded_tweak[i];
            }
            hazmat::cipher_round(&mut block, &tweaked_key);
        }

        // Final round
        // SubBytes
        for i in 0..16 {
            block[i] = SBOX[block[i] as usize];
        }

        // ShiftRows
        shift_rows(&mut block);

        // AddRoundKey with tweak
        for i in 0..16 {
            block[i] ^= self.round_keys[10][i] ^ padded_tweak[i];
        }

        *ip = block.into();
    }

    /// Decrypts a 16-byte IP address using KIASU-BC mode.
    ///
    /// This is an internal function that performs the core KIASU-BC decryption.
    /// For public use, prefer `decrypt_ipaddr`.
    fn decrypt_ip16(&self, ip: &mut [u8; 16], tweak: &[u8; Self::TWEAK_BYTES]) {
        let padded_tweak = Self::pad_tweak(tweak);
        let mut block = Block::from(*ip);

        // Initial round
        for i in 0..16 {
            block[i] ^= self.round_keys[10][i] ^ padded_tweak[i];
        }

        // Inverse ShiftRows
        inv_shift_rows(&mut block);

        // Inverse SubBytes
        for i in 0..16 {
            block[i] = INV_SBOX[block[i] as usize];
        }

        // Main rounds
        for round in (1..10).rev() {
            // AddRoundKey with tweak
            for i in 0..16 {
                block[i] ^= self.round_keys[round][i] ^ padded_tweak[i];
            }

            // Inverse MixColumns
            inv_mix_columns(&mut block);

            // Inverse ShiftRows
            inv_shift_rows(&mut block);

            // Inverse SubBytes
            for i in 0..16 {
                block[i] = INV_SBOX[block[i] as usize];
            }
        }

        // Final round
        for i in 0..16 {
            block[i] ^= self.round_keys[0][i] ^ padded_tweak[i];
        }

        *ip = block.into();
    }

    /// Encrypts an IP address using non-deterministic mode with KIASU-BC.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to encrypt
    /// * `tweak` - Optional tweak to use. If None, a random tweak will be generated.
    ///
    /// # Returns
    /// A 24-byte array containing the concatenation of the 8-byte tweak and the 16-byte encrypted IP address.
    pub fn encrypt_ipaddr(
        &self,
        ip: IpAddr,
        tweak: Option<[u8; Self::TWEAK_BYTES]>,
    ) -> [u8; Self::NDIP_BYTES] {
        let mut out = [0u8; Self::NDIP_BYTES];
        let tweak = tweak.unwrap_or_else(Self::generate_tweak);
        let mut bytes = ip_to_bytes(ip);
        self.encrypt_ip16(&mut bytes, &tweak);
        out[0..Self::TWEAK_BYTES].copy_from_slice(&tweak);
        out[Self::TWEAK_BYTES..].copy_from_slice(&bytes);
        out
    }

    /// Decrypts an IP address that was encrypted using non-deterministic mode with KIASU-BC.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - A 24-byte array containing the concatenation of the 8-byte tweak and 16-byte ciphertext
    ///
    /// # Returns
    /// The decrypted IP address
    pub fn decrypt_ipaddr(&self, encrypted: &[u8; Self::NDIP_BYTES]) -> IpAddr {
        let mut tweak = [0u8; Self::TWEAK_BYTES];
        tweak.copy_from_slice(&encrypted[0..Self::TWEAK_BYTES]);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&encrypted[Self::TWEAK_BYTES..]);
        self.decrypt_ip16(&mut bytes, &tweak);
        bytes_to_ip(bytes)
    }

    /// Expands a 16-byte key into 11 round keys using the AES key schedule.
    ///
    /// This is an internal function used during initialization to generate the round keys
    /// needed for encryption and decryption operations.
    fn expand_key(key: &[u8; Self::KEY_BYTES]) -> Vec<Block> {
        let mut round_keys = Vec::with_capacity(11);

        // First round key is the original key
        let current_key = Block::from(*key);
        round_keys.push(current_key);

        // Generate remaining round keys
        for i in 1..11 {
            let prev_key = round_keys[i - 1];
            let mut next_key = Block::default();

            // First word
            // RotWord and SubWord
            let t0 = prev_key[13];
            let t1 = prev_key[14];
            let t2 = prev_key[15];
            let t3 = prev_key[12];
            let s0 = SBOX[t0 as usize];
            let s1 = SBOX[t1 as usize];
            let s2 = SBOX[t2 as usize];
            let s3 = SBOX[t3 as usize];

            // XOR with Rcon and previous key
            next_key[0] = prev_key[0] ^ s0 ^ RCON[i - 1];
            next_key[1] = prev_key[1] ^ s1;
            next_key[2] = prev_key[2] ^ s2;
            next_key[3] = prev_key[3] ^ s3;

            // Remaining words
            next_key[4] = next_key[0] ^ prev_key[4];
            next_key[5] = next_key[1] ^ prev_key[5];
            next_key[6] = next_key[2] ^ prev_key[6];
            next_key[7] = next_key[3] ^ prev_key[7];

            next_key[8] = next_key[4] ^ prev_key[8];
            next_key[9] = next_key[5] ^ prev_key[9];
            next_key[10] = next_key[6] ^ prev_key[10];
            next_key[11] = next_key[7] ^ prev_key[11];

            next_key[12] = next_key[8] ^ prev_key[12];
            next_key[13] = next_key[9] ^ prev_key[13];
            next_key[14] = next_key[10] ^ prev_key[14];
            next_key[15] = next_key[11] ^ prev_key[15];

            round_keys.push(next_key);
        }

        round_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder as _, Encoder as _, Hex};
    use std::str::FromStr;

    #[test]
    fn test_nd_vectors() {
        let test_vectors = vec![
            (
                // Test vector 1
                "0123456789abcdeffedcba9876543210",
                "0.0.0.0",
                "08e0c289bff23b7c",
                "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16",
            ),
            (
                // Test vector 2
                "1032547698badcfeefcdab8967452301",
                "192.0.2.1",
                "21bd1834bc088cd2",
                "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad",
            ),
            (
                // Test vector 3
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2001:db8::1",
                "b4ecbe30b70898d7",
                "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96",
            ),
        ];

        for (key_hex, input_ip, tweak_hex, expected_output) in test_vectors {
            // Parse key using constant-time hex decoder
            let key_vec = Hex::decode_to_vec(key_hex.as_bytes(), None).unwrap();
            let mut key = [0u8; IpcryptNd::KEY_BYTES];
            key.copy_from_slice(&key_vec);

            // Parse tweak
            let tweak_vec = Hex::decode_to_vec(tweak_hex.as_bytes(), None).unwrap();
            let mut tweak = [0u8; IpcryptNd::TWEAK_BYTES];
            tweak.copy_from_slice(&tweak_vec);

            // Create IpcryptNd instance
            let ipcrypt = IpcryptNd::new(key);

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
