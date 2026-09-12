#ifndef ASCON_RS_H
#define ASCON_RS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32
#define ASCON_MAX_CUSTOMIZATION_SIZE 256

#define ASCON_OK 0
#define ASCON_AUTH_FAILED (-1)
#define ASCON_NULL_POINTER (-2)
#define ASCON_INVALID_LENGTH (-3)
#define ASCON_CUSTOMIZATION_TOO_LONG (-4)
#define ASCON_OVERLAPPING_BUFFERS (-5)

/* NIST SP 800-232 (August 2025), byte-oriented interface.
 * All lengths are in bytes. Keys, nonces and tags are exactly 16 bytes.
 * NEVER reuse a nonce with the same key. Tags are detached and never truncated.
 * Caller owns all buffers; the library retains no pointers and allocates no
 * buffers. Nonempty inputs must be readable, and outputs writable, for their
 * entire documented lengths. Fixed-size buffers must have the indicated size.
 * NULL is allowed only when the corresponding length is zero.
 * Writable ranges must not overlap any other argument (including key/nonce).
 * Use the explicit in-place functions to encrypt/decrypt a single buffer.
 * Inputs must remain unchanged by other threads for the duration of a call.
 * All functions return a status above. On any error all outputs are unchanged.
 * Successful decryption writes plaintext only after authentication succeeds.
 * XOF output length zero is permitted as a no-op extension to the standard.
 */

int32_t ascon_aead128_encrypt(
    const uint8_t key[ASCON_KEY_SIZE], const uint8_t nonce[ASCON_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t ciphertext_len, uint8_t tag[ASCON_TAG_SIZE]);

int32_t ascon_aead128_decrypt(
    const uint8_t key[ASCON_KEY_SIZE], const uint8_t nonce[ASCON_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t tag[ASCON_TAG_SIZE],
    uint8_t *plaintext, size_t plaintext_len);

/* buffer must be initialized for buffer_len bytes. */
int32_t ascon_aead128_encrypt_in_place(
    const uint8_t key[ASCON_KEY_SIZE], const uint8_t nonce[ASCON_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *buffer, size_t buffer_len, uint8_t tag[ASCON_TAG_SIZE]);

int32_t ascon_aead128_decrypt_in_place(
    const uint8_t key[ASCON_KEY_SIZE], const uint8_t nonce[ASCON_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *buffer, size_t buffer_len, const uint8_t tag[ASCON_TAG_SIZE]);

int32_t ascon_hash256(const uint8_t *message, size_t message_len,
                     uint8_t digest[ASCON_HASH_SIZE]);
int32_t ascon_xof128(const uint8_t *message, size_t message_len,
                    uint8_t *output, size_t output_len);
int32_t ascon_cxof128(const uint8_t *message, size_t message_len,
                     const uint8_t *customization, size_t customization_len,
                     uint8_t *output, size_t output_len);

#ifdef __cplusplus
}
#endif
#endif
