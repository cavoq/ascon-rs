use crate::{
    permutation::{word, State},
    Error,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Key length in bytes.
pub const KEY_SIZE: usize = 16;
/// Nonce length in bytes.
pub const NONCE_SIZE: usize = 16;
/// Full authentication tag length in bytes.
pub const TAG_SIZE: usize = 16;

/// Ascon-AEAD128 with a 128-bit key and full 128-bit tags.
///
/// Never reuse a nonce with the same key. Associated data is authenticated but
/// not encrypted. The stored key and internal states are zeroized on drop.
///
/// The application must manage the requirements in NIST SP 800-232 section 4.3:
/// generate and protect keys, keep nonces unique, limit total encryption and
/// decryption input (including nonces) to 2^54 bytes per key, and allow at most
/// 2^96 failed decryptions per key with these 128-bit tags. Replace the key when
/// the data limit is reached, and preferably when the failure limit is reached.
/// This type does not generate randomness or track usage across instances.
pub struct Aead128 {
    key: Zeroizing<[u8; KEY_SIZE]>,
}

impl Aead128 {
    /// Copy a key into a cipher instance. The caller owns its original key copy.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self {
            key: Zeroizing::new(*key),
        }
    }

    fn initialize(&self, nonce: &[u8; NONCE_SIZE], ad: &[u8]) -> State {
        let mut s = State([
            0x00001000808c0001,
            word(&self.key[..8]),
            word(&self.key[8..]),
            word(&nonce[..8]),
            word(&nonce[8..]),
        ]);
        s.permute(12);
        s.0[3] ^= word(&self.key[..8]);
        s.0[4] ^= word(&self.key[8..]);
        if !ad.is_empty() {
            let mut pos = 0;
            for &byte in ad {
                s.xor_byte(pos, byte);
                pos += 1;
                if pos == 16 {
                    s.permute(8);
                    pos = 0;
                }
            }
            s.xor_byte(pos, 1);
            s.permute(8);
        }
        s.0[4] ^= 1 << 63;
        s
    }

    fn tag(&self, mut s: State) -> [u8; TAG_SIZE] {
        s.0[2] ^= word(&self.key[..8]);
        s.0[3] ^= word(&self.key[8..]);
        s.permute(12);
        s.0[3] ^= word(&self.key[..8]);
        s.0[4] ^= word(&self.key[8..]);
        core::array::from_fn(|i| s.byte(24 + i))
    }

    // The closure returns ciphertext for both encryption and decryption.
    fn process(s: &mut State, len: usize, mut byte: impl FnMut(usize, u8) -> u8) {
        let mut pos = 0;
        for i in 0..len {
            let ciphertext = byte(i, s.byte(pos));
            s.set_byte(pos, ciphertext);
            pos += 1;
            if pos == 16 {
                s.permute(8);
                pos = 0;
            }
        }
        s.xor_byte(pos, 1);
    }

    fn verify_state(
        &self,
        initial: &State,
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), Error> {
        let mut s = initial.clone();
        Self::process(&mut s, ciphertext.len(), |i, _| ciphertext[i]);
        let expected = Zeroizing::new(self.tag(s));
        if bool::from(expected.as_ref().ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }

    /// Verify a ciphertext and detached tag without producing plaintext.
    pub fn verify_tag(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), Error> {
        self.verify_state(&self.initialize(nonce, ad), ciphertext, tag)
    }

    /// Encrypt into an equally sized output buffer and return a detached tag.
    /// Returns [`Error::InvalidLength`] without modifying output on mismatch.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], Error> {
        if plaintext.len() != ciphertext.len() {
            return Err(Error::InvalidLength);
        }
        let mut s = self.initialize(nonce, ad);
        Self::process(&mut s, plaintext.len(), |i, mask| {
            ciphertext[i] = plaintext[i] ^ mask;
            ciphertext[i]
        });
        Ok(self.tag(s))
    }

    /// Encrypt a buffer in place and return a detached authentication tag.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; TAG_SIZE] {
        let mut s = self.initialize(nonce, ad);
        Self::process(&mut s, buffer.len(), |i, mask| {
            buffer[i] ^= mask;
            buffer[i]
        });
        self.tag(s)
    }

    /// Verify and decrypt into an equally sized buffer.
    /// On any error the output is unchanged. Authentication precedes all writes.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext.len() != plaintext.len() {
            return Err(Error::InvalidLength);
        }
        let mut s = self.initialize(nonce, ad);
        self.verify_state(&s, ciphertext, tag)?;
        Self::process(&mut s, ciphertext.len(), |i, mask| {
            plaintext[i] = ciphertext[i] ^ mask;
            ciphertext[i]
        });
        Ok(())
    }

    /// Verify and decrypt in place. On failure the ciphertext is unchanged.
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), Error> {
        let mut s = self.initialize(nonce, ad);
        self.verify_state(&s, buffer, tag)?;
        Self::process(&mut s, buffer.len(), |i, mask| {
            let c = buffer[i];
            buffer[i] ^= mask;
            c
        });
        Ok(())
    }
}
