#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../Src/chacha20.h"

/* 打印十六进制数据 */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s [%zu bytes]:\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

/* 打印可读字符串（非打印字符显示为 '.'） */
static void print_str(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: \"", label);
    for (size_t i = 0; i < len; i++) {
        printf("%c", (data[i] >= 0x20 && data[i] <= 0x7e) ? (char)data[i] : '.');
    }
    printf("\"\n");
}

int main(void)
{
    /* ========== 密钥和 nonce ========== */

    /*
     * key: 32 字节 (256-bit)
     * nonce: 12 字节 (96-bit)
     * 注意：同一个 key 下 nonce 绝不能重复使用（标准文档第9节注意事项第4条）
     */
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };

    uint32_t counter = 1;

    /* ========== 示例1：加密一段英文消息 ========== */

    printf("========== 示例1：英文消息加解密 ==========\n\n");

    const char *message = "Hello, ChaCha20! This is a secret message.";
    size_t msg_len = strlen(message);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};

    printf("原始消息:\n");
    print_str("  文本", (const uint8_t *)message, msg_len);
    print_hex("  十六进制", (const uint8_t *)message, msg_len);
    printf("\n");

    /* 加密 */
    chacha20_encrypt(key, counter, nonce,
                     (const uint8_t *)message, msg_len, ciphertext);

    printf("加密后:\n");
    print_str("  文本", ciphertext, msg_len);
    print_hex("  十六进制", ciphertext, msg_len);
    printf("\n");

    /* 解密（使用相同的 key、counter、nonce） */
    chacha20_decrypt(key, counter, nonce, ciphertext, msg_len, decrypted);

    printf("解密后:\n");
    print_str("  文本", decrypted, msg_len);
    print_hex("  十六进制", decrypted, msg_len);
    printf("\n");

    /* 验证 */
    if (memcmp(message, decrypted, msg_len) == 0) {
        printf("验证结果: 成功 - 解密后与原文一致\n\n");
    } else {
        printf("验证结果: 失败 - 解密后与原文不一致\n\n");
    }

    /* ========== 示例2：加密中文消息（UTF-8 编码） ========== */

    printf("========== 示例2：中文消息（UTF-8）加解密 ==========\n\n");

    /* 中文 UTF-8 编码的字节序列 */
    const uint8_t chinese_msg[] = {
        0xe4,0xbd,0xa0,0xe5,0xa5,0xbd,0xef,0xbc, /* 你好 */
        0x8c,0xe4,0xb8,0x96,0xe7,0x95,0x8c,0xef, /* ，世界 */
        0xbc,0x81                                    /* ！ */
    };
    size_t chinese_len = sizeof(chinese_msg);

    uint8_t chinese_cipher[64] = {0};
    uint8_t chinese_dec[64] = {0};

    uint8_t nonce2[12] = {0};
    nonce2[0] = 0x01;  /* 使用不同的 nonce，避免与上面重复 */

    print_hex("  原始字节", chinese_msg, chinese_len);
    chacha20_encrypt(key, 0, nonce2, chinese_msg, chinese_len, chinese_cipher);
    print_hex("  加密后", chinese_cipher, chinese_len);

    chacha20_decrypt(key, 0, nonce2, chinese_cipher, chinese_len, chinese_dec);
    print_hex("  解密后", chinese_dec, chinese_len);

    if (memcmp(chinese_msg, chinese_dec, chinese_len) == 0) {
        printf("验证结果: 成功 - 解密后与原文一致\n\n");
    } else {
        printf("验证结果: 失败 - 解密后与原文不一致\n\n");
    }

    /* ========== 示例3：分块加密（演示 counter 递增） ========== */

    printf("========== 示例3：跨多个 block 的加解密 ==========\n\n");

    /* 构造一段超过 64 字节的明文，迫使加密使用多个 block */
    const char *long_msg =
        "ChaCha20 is a stream cipher designed by Daniel J. Bernstein. "
        "It is a refinement of the Salsa20 algorithm, and uses a 256-bit key "
        "and a 96-bit nonce. This message is intentionally long to demonstrate "
        "multi-block encryption where the counter increments for each block.";
    size_t long_len = strlen(long_msg);

    uint8_t long_cipher[512] = {0};
    uint8_t long_dec[512] = {0};

    uint8_t nonce3[12] = {0};
    nonce3[0] = 0x02;  /* 又一个不同的 nonce */

    printf("明文长度: %zu 字节（需要 %zu 个 block）\n\n", long_len,
           (long_len + 63) / 64);

    chacha20_encrypt(key, 0, nonce3,
                     (const uint8_t *)long_msg, long_len, long_cipher);

    print_hex("  密文前64字节", long_cipher, 64);
    printf("\n");

    chacha20_decrypt(key, 0, nonce3, long_cipher, long_len, long_dec);

    if (memcmp(long_msg, long_dec, long_len) == 0) {
        printf("验证结果: 成功 - 多 block 加解密一致\n\n");
    } else {
        printf("验证结果: 失败\n\n");
    }

    print_str("解密文本", long_dec, long_len);

    printf("\n========== 全部演示完成 ==========\n");
    return 0;
}
