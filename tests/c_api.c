#include "ascon.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static void test_separate_aead_known_answer(void) {
    /* tests/vectors/aead.txt, Count = 579: full blocks plus a partial block. */
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t nonce[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t plaintext[17] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
    };
    const uint8_t ad[17] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
    };
    const uint8_t expected_ciphertext[17] = {
        0xbf, 0x77, 0xc7, 0x1b, 0x3d, 0xe9, 0xf1, 0xc5,
        0xb3, 0x72, 0xef, 0x27, 0x3a, 0x08, 0xe8, 0x9b, 0xe9
    };
    const uint8_t expected_tag[16] = {
        0xd5, 0x07, 0xd7, 0xb3, 0xc2, 0xae, 0xe9, 0x79,
        0x11, 0xe7, 0x91, 0xf7, 0x97, 0x0d, 0x66, 0x35
    };
    /* C callers may pass initially uninitialized output buffers. */
    uint8_t ciphertext[17], tag[16], decrypted[17];
    assert(ascon_aead128_encrypt(key, nonce, ad, sizeof ad,
                                plaintext, sizeof plaintext,
                                ciphertext, sizeof ciphertext, tag) == ASCON_OK);
    assert(memcmp(ciphertext, expected_ciphertext, sizeof ciphertext) == 0);
    assert(memcmp(tag, expected_tag, sizeof tag) == 0);
    assert(ascon_aead128_decrypt(key, nonce, ad, sizeof ad,
                                expected_ciphertext, sizeof expected_ciphertext,
                                expected_tag, decrypted, sizeof decrypted) == ASCON_OK);
    assert(memcmp(decrypted, plaintext, sizeof decrypted) == 0);
}

static void test_xof_known_answers(void) {
    const uint8_t message[17] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const uint8_t customization[17] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    /* tests/vectors/xof.txt, Count = 18. */
    const uint8_t expected_xof[64] = {
        0x23, 0x3a, 0xf6, 0x4f, 0x97, 0xca, 0x9b, 0xd9,
        0x7b, 0xae, 0x06, 0x27, 0x05, 0x71, 0xe5, 0x72,
        0x15, 0xc5, 0xcb, 0x5b, 0xa4, 0x03, 0x85, 0x36,
        0xc5, 0xc1, 0x28, 0xda, 0x1d, 0x3a, 0x37, 0x9a,
        0xe1, 0x3d, 0xa3, 0xe5, 0x45, 0x46, 0xa1, 0x49,
        0x90, 0x14, 0xca, 0x03, 0xf2, 0xee, 0xe1, 0x0b,
        0x7a, 0xa9, 0x30, 0xfa, 0xa5, 0x8a, 0x39, 0x94,
        0xfd, 0x4b, 0xcc, 0x71, 0xf6, 0xcb, 0x19, 0x27
    };
    /* tests/vectors/cxof.txt, Count = 579. */
    const uint8_t expected_cxof[64] = {
        0x2d, 0x50, 0xc0, 0x7d, 0x29, 0xb3, 0x74, 0xc5,
        0x1a, 0x2f, 0xd7, 0x68, 0x7a, 0x58, 0xcc, 0xe5,
        0x64, 0xd3, 0x96, 0xc3, 0x61, 0x34, 0x17, 0xb8,
        0x33, 0x96, 0x7b, 0x1d, 0xa4, 0x27, 0x0b, 0x72,
        0x82, 0x5c, 0xe3, 0x1c, 0xaa, 0x64, 0xe1, 0x89,
        0x50, 0xda, 0x46, 0x0a, 0xdc, 0xda, 0x09, 0x0e,
        0xbc, 0xc2, 0xdd, 0xd6, 0xbe, 0x08, 0xd6, 0x8f,
        0x9f, 0x2c, 0xb7, 0xfe, 0x81, 0xff, 0xf3, 0x4e
    };
    uint8_t xof[64], cxof[64];
    assert(ascon_xof128(message, sizeof message, xof, sizeof xof) == ASCON_OK);
    assert(memcmp(xof, expected_xof, sizeof xof) == 0);
    assert(ascon_cxof128(message, sizeof message,
                         customization, sizeof customization,
                         cxof, sizeof cxof) == ASCON_OK);
    assert(memcmp(cxof, expected_cxof, sizeof cxof) == 0);
}

int main(void) {
    test_separate_aead_known_answer();
    test_xof_known_answers();
    uint8_t key[16] = {0}, nonce[16] = {0}, tag[16];
    uint8_t storage[128], before[128], digest[32];
    const uint8_t empty_hash[32] = {
        0x0b,0x3b,0xe5,0x85,0x0f,0x2f,0x6b,0x98,
        0xca,0xf2,0x9f,0x8f,0xde,0xa8,0x9b,0x64,
        0xa1,0xfa,0x70,0xaa,0x24,0x9b,0x8f,0x83,
        0x9b,0xd5,0x3b,0xaa,0x30,0x4d,0x92,0xb2
    };
    assert(ascon_hash256(NULL, 0, digest) == ASCON_OK);
    assert(memcmp(digest, empty_hash, 32) == 0);
    assert(ascon_hash256(NULL, 1, digest) == ASCON_NULL_POINTER);
    assert(ascon_hash256(NULL, 0, NULL) == ASCON_NULL_POINTER);
    assert(ascon_hash256(storage, SIZE_MAX, digest) == ASCON_INVALID_LENGTH);
    assert(ascon_xof128(NULL, 0, NULL, 0) == ASCON_OK);
    assert(ascon_cxof128(NULL, 0, NULL, 0, NULL, 0) == ASCON_OK);
    assert(ascon_cxof128(NULL, 0, storage, 257, digest, 32) == ASCON_CUSTOMIZATION_TOO_LONG);
    assert(ascon_aead128_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, 0, tag) == ASCON_OK);
    assert(ascon_aead128_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL, 0) == ASCON_OK);
    tag[0] ^= 1;
    assert(ascon_aead128_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL, 0) == ASCON_AUTH_FAILED);

    memset(storage, 0x5a, sizeof storage);
    memcpy(before, storage, sizeof storage);
    assert(ascon_hash256(storage, 16, storage + 8) == ASCON_OVERLAPPING_BUFFERS);
    assert(ascon_xof128(storage, 16, storage, 16) == ASCON_OVERLAPPING_BUFFERS);
    assert(ascon_cxof128(NULL, 0, storage, 16, storage, 16) == ASCON_OVERLAPPING_BUFFERS);
    assert(ascon_aead128_encrypt(key, nonce, NULL, 0, storage, 16, storage, 16, tag) == ASCON_OVERLAPPING_BUFFERS);
    assert(ascon_aead128_encrypt(key, nonce, NULL, 0, storage, 16, storage + 32, 16, storage + 40) == ASCON_OVERLAPPING_BUFFERS);
    assert(ascon_aead128_encrypt(key, nonce, NULL, 0, storage, 16, storage + 32, 17, tag) == ASCON_INVALID_LENGTH);
    assert(ascon_aead128_encrypt_in_place(storage, nonce, NULL, 0, storage, 16, tag) == ASCON_OVERLAPPING_BUFFERS);
    assert(memcmp(storage, before, sizeof storage) == 0);

    assert(ascon_aead128_encrypt_in_place(key, nonce, NULL, 0, storage, 33, tag) == ASCON_OK);
    memcpy(before, storage, sizeof storage);
    tag[15] ^= 0x80;
    assert(ascon_aead128_decrypt_in_place(key, nonce, NULL, 0, storage, 33, tag) == ASCON_AUTH_FAILED);
    assert(memcmp(storage, before, sizeof storage) == 0);
    assert(ascon_aead128_decrypt(key, nonce, NULL, 0, storage, 33, tag, storage + 64, 33) == ASCON_AUTH_FAILED);
    assert(memcmp(storage, before, sizeof storage) == 0);
    tag[15] ^= 0x80;
    assert(ascon_aead128_decrypt_in_place(key, nonce, NULL, 0, storage, 33, tag) == ASCON_OK);
    for (size_t i = 0; i < 33; ++i) assert(storage[i] == 0x5a);
    return 0;
}
