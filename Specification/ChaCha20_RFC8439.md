# ChaCha20 算法实现说明

依据：RFC 8439, Section 2.1–2.4.1  
范围：仅包括 ChaCha20 流密码本体，不包括 Poly1305 和 AEAD_CHACHA20_POLY1305。

RFC 8439 官方页面：<https://www.rfc-editor.org/rfc/rfc8439.html>

---

## 1. 基本数据类型

ChaCha20 的内部状态由 16 个 32-bit 无符号整数构成。

可以把状态看作长度为 16 的向量：

```text
0   1   2   3
4   5   6   7
8   9   10  11
12  13  14  15
```

每个元素都是一个 32-bit word。

---

## 2. 基本运算

ChaCha20 使用三种基本运算：

| 符号 | 含义 |
|---|---|
| `+` | 模 `2^32` 加法 |
| `^` | 按位异或 XOR |
| `<<< n` | 32-bit 循环左移 `n` 位 |

注意：所有加法都必须限制在 32 bit 内，即结果需要对 `2^32` 取模。

---

## 3. Quarter Round

Quarter Round 是 ChaCha20 的基本变换单元，输入为四个 32-bit word：

```text
a, b, c, d
```

执行过程如下：

```text
a = a + b;  d = d ^ a;  d = d <<< 16;
c = c + d;  b = b ^ c;  b = b <<< 12;
a = a + b;  d = d ^ a;  d = d <<< 8;
c = c + d;  b = b ^ c;  b = b <<< 7;
```

实现时可以写成函数：

```text
quarter_round(a, b, c, d):
    a = (a + b) mod 2^32
    d = d XOR a
    d = ROTL32(d, 16)

    c = (c + d) mod 2^32
    b = b XOR c
    b = ROTL32(b, 12)

    a = (a + b) mod 2^32
    d = d XOR a
    d = ROTL32(d, 8)

    c = (c + d) mod 2^32
    b = b XOR c
    b = ROTL32(b, 7)

    return a, b, c, d
```

---

## 4. ChaCha20 State 初始化

ChaCha20 block function 的输入包括：

| 输入 | 长度 |
|---|---:|
| key | 256 bit，也就是 32 字节 |
| counter | 32 bit，也就是 4 字节 |
| nonce | 96 bit，也就是 12 字节 |

ChaCha20 的初始状态是 16 个 32-bit word：

```text
state[0]  = 0x61707865
state[1]  = 0x3320646e
state[2]  = 0x79622d32
state[3]  = 0x6b206574

state[4]  = key[0..3]     little-endian
state[5]  = key[4..7]     little-endian
state[6]  = key[8..11]    little-endian
state[7]  = key[12..15]   little-endian
state[8]  = key[16..19]   little-endian
state[9]  = key[20..23]   little-endian
state[10] = key[24..27]   little-endian
state[11] = key[28..31]   little-endian

state[12] = counter

state[13] = nonce[0..3]   little-endian
state[14] = nonce[4..7]   little-endian
state[15] = nonce[8..11]  little-endian
```

也可以表示为矩阵：

```text
constant  constant  constant  constant
key       key       key       key
key       key       key       key
counter   nonce     nonce     nonce
```

四个常量对应 ASCII 字符串：

```text
"expand 32-byte k"
```

---

## 5. Inner Block

ChaCha20 每两轮包含 8 次 quarter round。

前 4 次是 column round：

```text
QUARTERROUND(state[0], state[4], state[8],  state[12])
QUARTERROUND(state[1], state[5], state[9],  state[13])
QUARTERROUND(state[2], state[6], state[10], state[14])
QUARTERROUND(state[3], state[7], state[11], state[15])
```

后 4 次是 diagonal round：

```text
QUARTERROUND(state[0], state[5], state[10], state[15])
QUARTERROUND(state[1], state[6], state[11], state[12])
QUARTERROUND(state[2], state[7], state[8],  state[13])
QUARTERROUND(state[3], state[4], state[9],  state[14])
```

伪代码：

```text
inner_block(state):
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)

    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)
```

---

## 6. ChaCha20 Block Function

ChaCha20 block function 的作用是根据：

```text
key, counter, nonce
```

生成一个 64 字节的密钥流块。

算法流程：

```text
chacha20_block(key, counter, nonce):
    state = constants | key | counter | nonce
    initial_state = state

    repeat 10 times:
        inner_block(state)

    state = state + initial_state

    return serialize(state)
```

其中：

- `|` 表示拼接；
- `state + initial_state` 表示 16 个 word 分别做模 `2^32` 加法；
- `serialize(state)` 表示把每个 32-bit word 按 little-endian 顺序转成 4 字节；
- 最终输出长度为 64 字节。

---

## 7. ChaCha20 加密算法

ChaCha20 是流密码。

它不断调用 `chacha20_block` 生成密钥流块：

```text
block_0 = chacha20_block(key, counter, nonce)
block_1 = chacha20_block(key, counter + 1, nonce)
block_2 = chacha20_block(key, counter + 2, nonce)
...
```

然后将密钥流与明文逐字节 XOR，得到密文。

加密伪代码：

```text
chacha20_encrypt(key, counter, nonce, plaintext):
    encrypted_message = empty

    for j = 0 to floor(len(plaintext) / 64) - 1:
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j*64 .. j*64 + 63]
        encrypted_message = encrypted_message || (block XOR key_stream)

    if len(plaintext) mod 64 != 0:
        j = floor(len(plaintext) / 64)
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j*64 .. len(plaintext)-1]
        encrypted_message = encrypted_message || first(len(block)) bytes of (block XOR key_stream)

    return encrypted_message
```

---

## 8. ChaCha20 解密算法

ChaCha20 的解密和加密完全相同。

因为：

```text
ciphertext = plaintext XOR keystream
plaintext  = ciphertext XOR keystream
```

所以解密时只需要再次生成相同的 keystream，然后与密文 XOR：

```text
chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)
```

---

## 9. 实现注意事项

1. key 必须是 32 字节。
2. nonce 必须是 12 字节。
3. counter 是 32-bit word。
4. 同一个 key 下，nonce 不能重复。
5. 每个 block 输出 64 字节 keystream。
6. 如果最后一个明文块不足 64 字节，只使用对应长度的 keystream，剩余 keystream 丢弃。
7. 所有 32-bit 加法都必须按模 `2^32` 处理。
8. key 和 nonce 写入 state 时必须按 little-endian 解析。
9. 输出 state 序列化时也必须使用 little-endian。
10. 使用 32-bit counter 时，同一个 key 和 nonce 组合最多处理 `2^32` 个 block，即约 256 GiB 数据。

---

## 10. 最小实现结构

推荐按下面顺序实现：

```text
rotl32(x, n)
quarter_round(state, a, b, c, d)
inner_block(state)
serialize(state)
chacha20_block(key, counter, nonce)
chacha20_encrypt(key, counter, nonce, plaintext)
chacha20_decrypt(key, counter, nonce, ciphertext)
```

---

## 11. 不包含的内容

本文档只整理 ChaCha20 流密码本体，不包含：

- Poly1305
- ChaCha20-Poly1305 AEAD
- TLS 中的 ChaCha20-Poly1305 使用方式
- RFC 8439 Section 2.8 的 AEAD 构造

---

## 12. 实现章节定位

如果要根据 RFC 8439 实现 ChaCha20，应主要参考以下章节：

| RFC 8439 章节 | 内容 | 实现必要性 |
|---|---|---|
| Section 2.1 | Quarter Round | 必须 |
| Section 2.2 | Quarter Round 测试向量 | 建议用于测试 |
| Section 2.3 | ChaCha20 Block Function | 必须 |
| Section 2.3.2 | Block Function 测试向量 | 建议用于测试 |
| Section 2.4 | ChaCha20 Encryption Algorithm | 必须 |
| Section 2.4.2 | Encryption 测试向量 | 建议用于测试 |

最关键的一点：实现 ChaCha20 时，以 RFC 8439 的 2.4.1 为加密流程入口，但必须同时实现 2.1 的 quarter round 和 2.3 的 block function。
