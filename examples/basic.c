#include "ascon.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    /* Demonstration only: provision a secret key and a fresh nonce in use. */
    const uint8_t key[ASCON_KEY_SIZE] = {0x42};
    const uint8_t nonce[ASCON_NONCE_SIZE] = {1};
    const uint8_t message[] = "Hello from C";
    const uint8_t ad[] = "example";
    uint8_t ciphertext[sizeof message - 1], plaintext[sizeof message - 1];
    uint8_t tag[ASCON_TAG_SIZE], digest[ASCON_HASH_SIZE], extended[48];

    int32_t status = ascon_aead128_encrypt(key, nonce, ad, sizeof ad - 1,
        message, sizeof message - 1, ciphertext, sizeof ciphertext, tag);
    if (status != ASCON_OK) return 1;
    status = ascon_aead128_decrypt(key, nonce, ad, sizeof ad - 1,
        ciphertext, sizeof ciphertext, tag, plaintext, sizeof plaintext);
    if (status != ASCON_OK) return 2;
    if (memcmp(plaintext, message, sizeof plaintext) != 0) return 3;
    if (ascon_hash256(message, sizeof message - 1, digest) != ASCON_OK) return 4;
    if (ascon_xof128(message, sizeof message - 1, extended, sizeof extended) != ASCON_OK) return 5;
    if (ascon_cxof128(message, sizeof message - 1, ad, sizeof ad - 1,
                      extended, sizeof extended) != ASCON_OK) return 6;
    puts("C encryption/decryption, Hash256, XOF128 and CXOF128 succeeded.");
    return 0;
}
