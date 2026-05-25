#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../Src/chacha20.h"

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n");
    }
    printf("\n");
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t bytes = hex_len / 2;
    if (bytes > max_len) return -1;
    for (size_t i = 0; i < bytes; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    *out_len = bytes;
    return 0;
}

static int read_key(uint8_t key[32])
{
    char buf[256];
    printf("请输入 32 字节密钥（64 个十六进制字符）:\n> ");
    if (!fgets(buf, sizeof(buf), stdin)) return -1;
    buf[strcspn(buf, "\n")] = 0;
    size_t len;
    if (hex_to_bytes(buf, key, 32, &len) != 0 || len != 32) {
        printf("错误: 密钥必须是 64 个十六进制字符（32 字节）\n");
        return -1;
    }
    return 0;
}

static int read_nonce(uint8_t nonce[12])
{
    char buf[256];
    printf("请输入 12 字节 nonce（24 个十六进制字符）:\n> ");
    if (!fgets(buf, sizeof(buf), stdin)) return -1;
    buf[strcspn(buf, "\n")] = 0;
    size_t len;
    if (hex_to_bytes(buf, nonce, 12, &len) != 0 || len != 12) {
        printf("错误: nonce 必须是 24 个十六进制字符（12 字节）\n");
        return -1;
    }
    return 0;
}

static uint32_t read_counter(void)
{
    char buf[64];
    printf("请输入 counter（整数，通常从 0 或 1 开始）:\n> ");
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    return (uint32_t)strtoul(buf, NULL, 0);
}

static void do_encrypt(void)
{
    uint8_t key[32], nonce[12];
    char buf[4096];

    if (read_key(key) != 0) return;
    if (read_nonce(nonce) != 0) return;
    uint32_t counter = read_counter();

    printf("请输入要加密的明文:\n> ");
    if (!fgets(buf, sizeof(buf), stdin)) return;
    size_t plaintext_len = strlen(buf);
    /* 去掉末尾换行符 */
    if (plaintext_len > 0 && buf[plaintext_len - 1] == '\n')
        buf[--plaintext_len] = 0;

    uint8_t *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        printf("错误: 内存分配失败\n");
        return;
    }

    chacha20_encrypt(key, counter, nonce, (const uint8_t *)buf, plaintext_len, ciphertext);

    printf("\n===== 加密结果 =====\n");
    printf("密文（十六进制）:\n");
    print_hex(ciphertext, plaintext_len);
    printf("密文长度: %lu 字节\n", (unsigned long)plaintext_len);

    free(ciphertext);
}

static void do_decrypt(void)
{
    uint8_t key[32], nonce[12];
    char buf[4096];

    if (read_key(key) != 0) return;
    if (read_nonce(nonce) != 0) return;
    uint32_t counter = read_counter();

    printf("请输入要解密的密文（十六进制）:\n> ");
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\n")] = 0;

    size_t ciphertext_len = strlen(buf) / 2;
    if (ciphertext_len == 0) {
        printf("错误: 密文为空\n");
        return;
    }

    uint8_t *ciphertext = malloc(ciphertext_len);
    uint8_t *plaintext = malloc(ciphertext_len + 1);
    if (!ciphertext || !plaintext) {
        printf("错误: 内存分配失败\n");
        free(ciphertext);
        free(plaintext);
        return;
    }

    size_t dec_len;
    if (hex_to_bytes(buf, ciphertext, ciphertext_len, &dec_len) != 0) {
        printf("错误: 密文不是有效的十六进制字符串\n");
        free(ciphertext);
        free(plaintext);
        return;
    }

    chacha20_decrypt(key, counter, nonce, ciphertext, dec_len, plaintext);
    plaintext[dec_len] = 0; /* 方便以字符串形式输出 */

    printf("\n===== 解密结果 =====\n");
    printf("明文（文本）: %s\n", plaintext);
    printf("明文（十六进制）:\n");
    print_hex(plaintext, dec_len);
    printf("明文长度: %lu 字节\n", (unsigned long)dec_len);

    free(ciphertext);
    free(plaintext);
}

int main(void)
{
    printf("========================================\n");
    printf("   ChaCha20 加解密工具 (RFC 8439)\n");
    printf("========================================\n\n");

    while (1) {
        printf("请选择操作:\n");
        printf("  1. 加密（明文 -> 密文）\n");
        printf("  2. 解密（密文 -> 明文）\n");
        printf("  0. 退出\n");
        printf("> ");

        char choice[16];
        if (!fgets(choice, sizeof(choice), stdin)) break;

        switch (choice[0]) {
        case '1':
            printf("\n");
            do_encrypt();
            printf("\n");
            break;
        case '2':
            printf("\n");
            do_decrypt();
            printf("\n");
            break;
        case '0':
            printf("再见！\n");
            return 0;
        default:
            printf("无效选择，请重新输入\n\n");
            break;
        }
    }

    return 0;
}
