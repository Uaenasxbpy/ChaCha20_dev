#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../Src/chacha20.h"

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int main(void)
{
    uint8_t key[32] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,
        0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe
    };
    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };

    struct {
        uint32_t counter;
        const char *plaintext;
    } tests[] = {
        {0, ""},
        {0, "A"},
        {0, "Hi"},
        {0, "Hello"},
        {0, "1234567890"},
        {0, "Hello, World!"},
        {0, "RFC 8439"},
        {0, "ChaCha20"},
        {0, "Cryptography"},
        {0, "0123456789abcdef"},
        {0, "01234567890123456789012345678901"},
        {0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"},
        {0, "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
        {0, "AbCdEfGhIjKlMnOpQrStUvWxYz"},
        {0, "abcabcabcabcabcabcabcabcabcabc"},
        {1, "Test counter = 1"},
        {100, "Test counter = 100"},
        {256, "Test counter = 256"},
        {0,
         "ChaCha20 is a stream cipher designed by Daniel J. Bernstein. "
         "It is a refinement of the Salsa20 algorithm."},
    };

    int total = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < total; i++) {
        size_t len = strlen(tests[i].plaintext);
        uint8_t *cipher = malloc(len > 0 ? len : 1);
        if (!cipher) continue;

        chacha20_encrypt(key, tests[i].counter, nonce,
                         (const uint8_t *)tests[i].plaintext, len, cipher);

        /* key | nonce | counter | plaintext | ciphertext */
        print_hex(key, 32);
        printf("|");
        print_hex(nonce, 12);
        printf("|");
        printf("%u|", tests[i].counter);
        if (len > 0) print_hex((const uint8_t *)tests[i].plaintext, len);
        else printf("-");
        printf("|");
        if (len > 0) print_hex(cipher, len);
        else printf("-");
        printf("|\n");

        free(cipher);
    }
    return 0;
}
