#include "chacha20.h"
#include <string.h>

/*
 * 对应标准文档 第2节 基本运算
 * ROTL32: 32-bit 循环左移 n 位
 * ChaCha20 使用三种基本运算：模 2^32 加法(+)、按位异或(^)、循环左移(<<<)
 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * 对应标准文档 第3节 Quarter Round
 *
 * Quarter Round 是 ChaCha20 的基本变换单元，输入为 state 数组中的四个下标 a, b, c, d。
 * 执行过程：
 *   a = a + b;  d = d ^ a;  d = d <<< 16;
 *   c = c + d;  b = b ^ c;  b = b <<< 12;
 *   a = a + b;  d = d ^ a;  d = d <<< 8;
 *   c = c + d;  b = b ^ c;  b = b <<< 7;
 *
 * 所有加法均为模 2^32 加法（C 语言 uint32_t 自动溢出实现）。
 */
static void quarter_round(uint32_t state[16],
                           int a, int b, int c, int d)
{
    /* 第1步: a = a + b; d = d ^ a; d = d <<< 16 */
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 16);
    /* 第2步: c = c + d; b = b ^ c; b = b <<< 12 */
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 12);
    /* 第3步: a = a + b; d = d ^ a; d = d <<< 8 */
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 8);
    /* 第4步: c = c + d; b = b ^ c; b = b <<< 7 */
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 7);
}

/*
 * 对应标准文档 第5节 Inner Block
 *
 * ChaCha20 每两轮（one double-round）包含 8 次 quarter round：
 *   前 4 次为 column round（列轮），对四列分别操作
 *   后 4 次为 diagonal round（对角轮），对四条对角线分别操作
 *
 * 状态矩阵布局（16 个 32-bit word）：
 *   0   1   2   3
 *   4   5   6   7
 *   8   9  10  11
 *  12  13  14  15
 */
static void inner_block(uint32_t state[16])
{
    /* 列轮 (column round): 每列的四个元素参与一次 quarter round */
    quarter_round(state, 0, 4,  8, 12);
    quarter_round(state, 1, 5,  9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    /* 对角轮 (diagonal round): 每条对角线的四个元素参与一次 quarter round */
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7,  8, 13);
    quarter_round(state, 3, 4,  9, 14);
}

/*
 * 对应标准文档 第2节 基本数据类型
 * 从字节数组中按 little-endian 顺序读取一个 32-bit word
 * 标准文档第9节注意事项第8条：key 和 nonce 写入 state 时必须按 little-endian 解析
 */
static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/*
 * 对应标准文档 第6节 serialize(state)
 * 将一个 32-bit word 按 little-endian 顺序写入字节数组
 * 标准文档第9节注意事项第9条：输出 state 序列化时必须使用 little-endian
 */
static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * 对应标准文档 第4节 ChaCha20 State 初始化 + 第6节 ChaCha20 Block Function
 *
 * ChaCha20 block function 根据 key(32字节)、counter(32-bit)、nonce(12字节)
 * 生成一个 64 字节的密钥流块。
 *
 * 算法流程（标准文档第6节）：
 *   1. state = constants | key | counter | nonce   （初始化状态矩阵）
 *   2. initial_state = state                        （保存初始状态副本）
 *   3. repeat 10 times: inner_block(state)          （执行 20 轮变换）
 *   4. state = state + initial_state                （与初始状态相加）
 *   5. return serialize(state)                       （序列化为 64 字节输出）
 */
static void chacha20_block(uint8_t output[64],
                           const uint8_t key[32],
                           uint32_t counter,
                           const uint8_t nonce[12])
{
    uint32_t state[16];
    uint32_t initial_state[16];

    /*
     * 第4节 State 初始化 - 常量部分 (state[0..3])
     * 对应 ASCII 字符串 "expand 32-byte k"
     * state[0] = 'e' | 'x' << 8 | 'p' << 16 | 'a' << 24 = 0x61707865
     * state[1] = ' ' | '3' << 8 | '2' << 16 | '-' << 24 = 0x3320646e
     * state[2] = 'b' | 'y' << 8 | 't' << 16 | 'e' << 24 = 0x79622d32
     * state[3] = ' ' | 'k' << 8 | '\0' << 16 | '\0' << 24 = 0x6b206574
     */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /*
     * 第4节 State 初始化 - key 部分 (state[4..11])
     * 32 字节 key 按 little-endian 解析为 8 个 32-bit word
     */
    state[4]  = load32_le(key + 0);
    state[5]  = load32_le(key + 4);
    state[6]  = load32_le(key + 8);
    state[7]  = load32_le(key + 12);
    state[8]  = load32_le(key + 16);
    state[9]  = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);

    /*
     * 第4节 State 初始化 - counter 部分 (state[12])
     * 32-bit 计数器，直接赋值
     */
    state[12] = counter;

    /*
     * 第4节 State 初始化 - nonce 部分 (state[13..15])
     * 12 字节 nonce 按 little-endian 解析为 3 个 32-bit word
     */
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    /* 第6节 保存初始状态副本，用于最后一步的加法 */
    memcpy(initial_state, state, sizeof(state));

    /* 第6节 执行 10 次 inner_block（共 20 轮 quarter round 变换） */
    for (int i = 0; i < 10; i++) {
        inner_block(state);
    }

    /* 第6节 state = state + initial_state（16 个 word 分别做模 2^32 加法） */
    for (int i = 0; i < 16; i++) {
        state[i] += initial_state[i];
    }

    /* 第6节 serialize(state)：将每个 32-bit word 按 little-endian 写入输出，共 64 字节 */
    for (int i = 0; i < 16; i++) {
        store32_le(output + 4 * i, state[i]);
    }
}

/*
 * 对应标准文档 第7节 ChaCha20 加密算法
 *
 * ChaCha20 是流密码，不断调用 chacha20_block 生成密钥流块：
 *   block_0 = chacha20_block(key, counter,     nonce)
 *   block_1 = chacha20_block(key, counter + 1, nonce)
 *   block_2 = chacha20_block(key, counter + 2, nonce)
 *   ...
 *
 * 然后将密钥流与明文逐字节 XOR，得到密文。
 *
 * 处理流程：
 *   1. 每次生成 64 字节密钥流，与对应的 64 字节明文 XOR
 *   2. 如果最后一个明文块不足 64 字节，只使用对应长度的密钥流，剩余部分丢弃
 *   3. 每处理完一个 block，counter 自增 1
 */
void chacha20_encrypt(const uint8_t key[32],
                      uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t *plaintext,
                      size_t plaintext_len,
                      uint8_t *ciphertext)
{
    uint8_t keystream[64];
    size_t remaining = plaintext_len;
    size_t offset = 0;

    /* 第7节 处理完整的 64 字节块 */
    while (remaining >= 64) {
        chacha20_block(keystream, key, counter, nonce);
        for (size_t i = 0; i < 64; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        counter++;  /* 标准文档第7节：counter + j */
        offset += 64;
        remaining -= 64;
    }

    /* 第7节 处理最后一个不足 64 字节的块，只使用对应长度的密钥流 */
    if (remaining > 0) {
        chacha20_block(keystream, key, counter, nonce);
        for (size_t i = 0; i < remaining; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
    }
}

/*
 * 对应标准文档 第8节 ChaCha20 解密算法
 *
 * ChaCha20 的解密和加密完全相同，因为：
 *   ciphertext = plaintext XOR keystream
 *   plaintext  = ciphertext XOR keystream
 *
 * 解密时只需再次生成相同的 keystream，然后与密文 XOR 即可恢复明文。
 */
void chacha20_decrypt(const uint8_t key[32],
                      uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t *ciphertext,
                      size_t ciphertext_len,
                      uint8_t *plaintext)
{
    /* 解密与加密操作完全一致，直接复用加密函数 */
    chacha20_encrypt(key, counter, nonce, ciphertext, ciphertext_len, plaintext);
}
