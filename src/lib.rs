//! Byte-oriented Ascon algorithms from NIST SP 800-232 (August 2025).
//!
//! All operations use caller-owned buffers and work without allocation. Disable
//! default features for `no_std`. See [`Aead128`], [`Hash256`], [`Xof128`], and
//! [`Cxof128`]. Nonces must never repeat under the same encryption key.
//!
//! ```
//! use ascon::{Aead128, hash256};
//! let cipher = Aead128::new(&[7; 16]);
//! let nonce = [1; 16]; // Use a unique nonce for every encryption with this key.
//! let mut message = *b"hello";
//! let tag = cipher.encrypt_in_place(&nonce, b"metadata", &mut message);
//! cipher.decrypt_in_place(&nonce, b"metadata", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! assert_eq!(hash256(&message).len(), 32);
//! # Ok::<(), ascon::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aead;
mod hash;
mod permutation;

pub use aead::{Aead128, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
pub use hash::{cxof128, hash256, xof128, Cxof128, Hash256, Xof128, XofReader};

/// Errors from the public cryptographic API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Authentication failed; the output buffer has not been modified.
    AuthenticationFailed,
    /// Input and output lengths differ.
    InvalidLength,
    /// CXOF customization exceeds 256 bytes (2048 bits).
    CustomizationTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::InvalidLength => "input and output lengths differ",
            Self::CustomizationTooLong => "customization exceeds 256 bytes",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
