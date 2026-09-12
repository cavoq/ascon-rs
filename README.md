# ascon-rs

Allocation-free Rust implementation of **Ascon-AEAD128, Ascon-Hash256,
Ascon-XOF128, and Ascon-CXOF128** from
[NIST SP 800-232](https://doi.org/10.6028/NIST.SP.800-232).
Supports `no_std`, in-place authenticated encryption, streaming hashes/XOFs,
and a separate C ABI. Requires **Rust 1.85+**; the Rust core forbids unsafe code.

[API docs](https://docs.rs/ascon-rs) ·
[Repository](https://github.com/cavoq/ascon-rs) ·
[Examples](https://github.com/cavoq/ascon-rs/tree/master/examples)

Add the dependency:

```toml
[dependencies]
ascon = { package = "ascon-rs", version = "0.1" }
# For no_std, add: default-features = false
```

```rust
use ascon::{hash256, Aead128};

fn main() -> Result<(), ascon::Error> {
    // Demo only: use a secret key and a unique nonce for every encryption.
    let cipher = Aead128::new(&[0x42; 16]);
    let nonce = [1; 16];
    let mut message = *b"hello";

    let tag = cipher.encrypt_in_place(&nonce, b"metadata", &mut message);
    cipher.decrypt_in_place(&nonce, b"metadata", &mut message, &tag)?;
    assert_eq!(&message, b"hello");
    let digest = hash256(&message);
    assert_eq!(digest.len(), 32);
    Ok(())
}
```

| Algorithm | Rust API |
| --- | --- |
| AEAD128 | `Aead128` |
| Hash256 | `hash256`, `Hash256` |
| XOF128 | `xof128`, `Xof128` |
| CXOF128 | `cxof128`, `Cxof128` |

Inputs and outputs are byte-oriented, with full 16-byte AEAD tags and at most
256 customization bytes. Empty XOF output is a no-op extension. The standardized
little-endian algorithms are incompatible with pre-standard Ascon v1.2.

**Never reuse a nonce with the same key.** Applications manage key generation
and per-key usage limits. Decryption authenticates before modifying output;
stored keys and states are zeroized. See the
[standards review and security limits](https://github.com/cavoq/ascon-rs/blob/master/docs/nist-sp-800-232-review.md).
This implementation has not undergone an independent security audit or NIST validation.

For C/C++, clone the repository and run `cargo build -p ascon-ffi --release`.
The repository-only FFI crate produces static and shared libraries; see the
[C header](https://github.com/cavoq/ascon-rs/blob/master/include/ascon.h) and
[C example](https://github.com/cavoq/ascon-rs/blob/master/examples/basic.c).

Verification covers 4,228 reference vectors, 16 NIST examples, and 512 differential
cases. CI builds and tests on Linux, macOS, and Windows, including Rust 1.85 and
embedded `no_std` checks. Run `cargo test --workspace --locked` from a checkout.
[Release instructions](https://github.com/cavoq/ascon-rs/blob/master/docs/releasing.md)
describe publishing to crates.io from version tags after CI passes.

License: [GPL-3.0-only](https://github.com/cavoq/ascon-rs/blob/master/LICENSE).
