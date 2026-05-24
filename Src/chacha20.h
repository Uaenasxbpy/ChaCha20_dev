#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

/**
 * ChaCha20 stream cipher (RFC 8439, Section 2.1-2.4)
 *
 * key:   32 bytes
 * nonce: 12 bytes
 * counter: initial block counter (32-bit)
 */

void chacha20_encrypt(const uint8_t key[32],
                      uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t *plaintext,
                      size_t plaintext_len,
                      uint8_t *ciphertext);

void chacha20_decrypt(const uint8_t key[32],
                      uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t *ciphertext,
                      size_t ciphertext_len,
                      uint8_t *plaintext);

#endif /* CHACHA20_H */
