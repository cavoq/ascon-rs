//! C ABI for Ascon. See `include/ascon.h` for the public interface.
//!
//! # Safety
//! Every nonempty input must point to initialized readable memory; every
//! nonempty output must point to writable memory for its declared length.
//! Fixed-size keys, nonces, tags and digests require their full documented sizes.
//! Memory must remain valid and inputs must remain unmodified for the call.
//! Null is accepted only for zero-length buffers. Writable ranges must not
//! overlap any other argument's range. Explicit in-place functions are provided.
//! Address checks detect null, length overflow and overlap, but cannot establish
//! whether a non-null pointer refers to a live allocation.

#![deny(unsafe_op_in_unsafe_fn)]

use ascon::{Aead128, Error};

pub const ASCON_OK: i32 = 0;
pub const ASCON_AUTH_FAILED: i32 = -1;
pub const ASCON_NULL_POINTER: i32 = -2;
pub const ASCON_INVALID_LENGTH: i32 = -3;
pub const ASCON_CUSTOMIZATION_TOO_LONG: i32 = -4;
pub const ASCON_OVERLAPPING_BUFFERS: i32 = -5;

type Buffer = (*const u8, usize);

fn range((ptr, len): Buffer) -> Result<(usize, usize), i32> {
    if len == 0 {
        return Ok((0, 0));
    }
    if ptr.is_null() {
        return Err(ASCON_NULL_POINTER);
    }
    if len > isize::MAX as usize {
        return Err(ASCON_INVALID_LENGTH);
    }
    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(ASCON_INVALID_LENGTH)?;
    Ok((start, end))
}

fn overlap(a: Buffer, b: Buffer) -> Result<bool, i32> {
    let (a0, a1) = range(a)?;
    let (b0, b1) = range(b)?;
    Ok(a0 < b1 && b0 < a1)
}

fn validate(inputs: &[Buffer], outputs: &[Buffer]) -> Result<(), i32> {
    for &buffer in inputs.iter().chain(outputs) {
        range(buffer)?;
    }
    for (i, &output) in outputs.iter().enumerate() {
        for &other in inputs.iter().chain(&outputs[..i]) {
            if overlap(output, other)? {
                return Err(ASCON_OVERLAPPING_BUFFERS);
            }
        }
    }
    Ok(())
}

// Call only after validation, with the caller's allocation validity guarantees.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn output<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
}

// Initialize C output memory before forming a Rust reference to it. Call only
// after all fallible checks, so error returns leave even uninitialized outputs
// untouched. Source and destination must be disjoint, validated ranges.
unsafe fn copy_output(dst: *mut u8, src: &[u8]) {
    if !src.is_empty() {
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }
}

unsafe fn zero_output(ptr: *mut u8, len: usize) {
    if len != 0 {
        unsafe {
            core::ptr::write_bytes(ptr, 0, len);
        }
    }
}

fn status(result: Result<(), i32>) -> i32 {
    result.err().unwrap_or(ASCON_OK)
}

fn error(error: Error) -> i32 {
    match error {
        Error::AuthenticationFailed => ASCON_AUTH_FAILED,
        Error::InvalidLength => ASCON_INVALID_LENGTH,
        Error::CustomizationTooLong => ASCON_CUSTOMIZATION_TOO_LONG,
    }
}

/// Encrypt to a separate buffer, writing a detached 16-byte tag.
/// # Safety
/// The module's pointer and memory requirements apply. Output lengths must match.
#[no_mangle]
pub unsafe extern "C" fn ascon_aead128_encrypt(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    tag: *mut u8,
) -> i32 {
    status((|| {
        if plaintext_len != ciphertext_len {
            return Err(ASCON_INVALID_LENGTH);
        }
        validate(
            &[
                (key, 16),
                (nonce, 16),
                (ad, ad_len),
                (plaintext, plaintext_len),
            ],
            &[(ciphertext, ciphertext_len), (tag, 16)],
        )?;
        // SAFETY: ranges are checked and caller guarantees valid allocations.
        unsafe {
            let cipher = Aead128::new(input(key, 16).try_into().unwrap());
            copy_output(ciphertext, input(plaintext, plaintext_len));
            let result = cipher.encrypt_in_place(
                input(nonce, 16).try_into().unwrap(),
                input(ad, ad_len),
                output(ciphertext, ciphertext_len),
            );
            copy_output(tag, &result);
        }
        Ok(())
    })())
}

/// Verify a detached tag and decrypt; output is unchanged on any error.
/// # Safety
/// The module's pointer and memory requirements apply. Output lengths must match.
#[no_mangle]
pub unsafe extern "C" fn ascon_aead128_decrypt(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
    plaintext_len: usize,
) -> i32 {
    status((|| {
        if plaintext_len != ciphertext_len {
            return Err(ASCON_INVALID_LENGTH);
        }
        validate(
            &[
                (key, 16),
                (nonce, 16),
                (ad, ad_len),
                (ciphertext, ciphertext_len),
                (tag, 16),
            ],
            &[(plaintext, plaintext_len)],
        )?;
        // SAFETY: all borrowed ranges have been validated and are disjoint.
        unsafe {
            let cipher = Aead128::new(input(key, 16).try_into().unwrap());
            let nonce = input(nonce, 16).try_into().unwrap();
            let ad = input(ad, ad_len);
            let ciphertext = input(ciphertext, ciphertext_len);
            let tag = input(tag, 16).try_into().unwrap();
            cipher
                .verify_tag(nonce, ad, ciphertext, tag)
                .map_err(error)?;
            // C output may be uninitialized. Authenticate before initializing it.
            copy_output(plaintext, ciphertext);
            cipher
                .decrypt_in_place(nonce, ad, output(plaintext, plaintext_len), tag)
                .map_err(error)
        }
    })())
}

/// Encrypt a buffer in place, writing a detached tag.
/// # Safety
/// The module's pointer and memory requirements apply; buffer must be initialized.
#[no_mangle]
pub unsafe extern "C" fn ascon_aead128_encrypt_in_place(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    buffer: *mut u8,
    buffer_len: usize,
    tag: *mut u8,
) -> i32 {
    status((|| {
        validate(
            &[(key, 16), (nonce, 16), (ad, ad_len)],
            &[(buffer, buffer_len), (tag, 16)],
        )?;
        // SAFETY: caller provides an initialized buffer; ranges are disjoint.
        unsafe {
            let result = Aead128::new(input(key, 16).try_into().unwrap()).encrypt_in_place(
                input(nonce, 16).try_into().unwrap(),
                input(ad, ad_len),
                output(buffer, buffer_len),
            );
            copy_output(tag, &result);
        }
        Ok(())
    })())
}

/// Verify and decrypt in place; buffer is unchanged on any error.
/// # Safety
/// The module's pointer and memory requirements apply; buffer must be initialized.
#[no_mangle]
pub unsafe extern "C" fn ascon_aead128_decrypt_in_place(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    buffer: *mut u8,
    buffer_len: usize,
    tag: *const u8,
) -> i32 {
    status((|| {
        validate(
            &[(key, 16), (nonce, 16), (ad, ad_len), (tag, 16)],
            &[(buffer, buffer_len)],
        )?;
        // SAFETY: caller provides an initialized buffer; ranges are disjoint.
        unsafe {
            Aead128::new(input(key, 16).try_into().unwrap())
                .decrypt_in_place(
                    input(nonce, 16).try_into().unwrap(),
                    input(ad, ad_len),
                    output(buffer, buffer_len),
                    input(tag, 16).try_into().unwrap(),
                )
                .map_err(error)
        }
    })())
}

/// Write a 32-byte Ascon-Hash256 digest.
/// # Safety
/// The module's pointer and memory requirements apply.
#[no_mangle]
pub unsafe extern "C" fn ascon_hash256(
    message: *const u8,
    message_len: usize,
    digest: *mut u8,
) -> i32 {
    status((|| {
        validate(&[(message, message_len)], &[(digest, 32)])?;
        // SAFETY: valid disjoint input and output per validation and caller.
        unsafe {
            copy_output(digest, &ascon::hash256(input(message, message_len)));
        }
        Ok(())
    })())
}

/// Write Ascon-XOF128 output; zero-length output is permitted.
/// # Safety
/// The module's pointer and memory requirements apply.
#[no_mangle]
pub unsafe extern "C" fn ascon_xof128(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    status((|| {
        validate(&[(message, message_len)], &[(out, out_len)])?;
        // SAFETY: valid disjoint input and output per validation and caller.
        unsafe {
            zero_output(out, out_len);
            ascon::xof128(input(message, message_len), output(out, out_len));
        }
        Ok(())
    })())
}

/// Write Ascon-CXOF128 output with at most 256 customization bytes.
/// # Safety
/// The module's pointer and memory requirements apply.
#[no_mangle]
pub unsafe extern "C" fn ascon_cxof128(
    message: *const u8,
    message_len: usize,
    customization: *const u8,
    customization_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    status((|| {
        if customization_len > 256 {
            return Err(ASCON_CUSTOMIZATION_TOO_LONG);
        }
        validate(
            &[(message, message_len), (customization, customization_len)],
            &[(out, out_len)],
        )?;
        // SAFETY: valid disjoint input and output per validation and caller.
        unsafe {
            zero_output(out, out_len);
            ascon::cxof128(
                input(message, message_len),
                input(customization, customization_len),
                output(out, out_len),
            )
            .map_err(error)
        }
    })())
}
