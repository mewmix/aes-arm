// aes_armv8_xts.c
#include "xts.h"

#include <string.h>

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>

static inline void aes256_encrypt_block_hw(const aes256_rkeys* rk,
                                           const uint8_t in[16],
                                           uint8_t out[16])
{
    const uint8x16_t* keys = (const uint8x16_t*)rk->enc;
    uint8x16_t state = vld1q_u8(in);

    state = veorq_u8(state, keys[0]);
    for (int round = 1; round < AES256_ROUNDS; ++round) {
        state = vaeseq_u8(state, keys[round]);
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, keys[AES256_ROUNDS]);
    state = veorq_u8(state, keys[AES256_ROUND_KEYS]);

    vst1q_u8(out, state);
}

static inline void aes256_decrypt_block_hw(const aes256_rkeys* rk,
                                           const uint8_t in[16],
                                           uint8_t out[16])
{
    const uint8x16_t* keys = (const uint8x16_t*)rk->dec;
    uint8x16_t state = vld1q_u8(in);

    state = veorq_u8(state, keys[0]);
    for (int round = 1; round < AES256_ROUNDS; ++round) {
        state = vaesdq_u8(state, keys[round]);
        state = vaesimcq_u8(state);
    }
    state = vaesdq_u8(state, keys[AES256_ROUNDS]);
    state = veorq_u8(state, keys[AES256_ROUND_KEYS]);

    vst1q_u8(out, state);
}
#endif

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint32_t rcon[10] = {
    0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
    0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

static inline uint32_t load_be32(const uint8_t* p){
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static inline void store_be32(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t rot_word(uint32_t w){
    return (w << 8) | (w >> 24);
}

static inline uint32_t sub_word(uint32_t w){
    return ((uint32_t)sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xff] << 8) |
           ((uint32_t)sbox[w & 0xff]);
}

static void expand_encrypt_keys(const uint8_t key[32],
                                uint8_t (*out)[16]){
    uint32_t w[60];
    for (int i = 0; i < 8; ++i) {
        w[i] = load_be32(key + 4 * i);
    }
    for (int i = 8; i < 60; ++i) {
        uint32_t temp = w[i - 1];
        if ((i & 7) == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[(i / 8) - 1];
        } else if ((i & 7) == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }
    for (int round = 0; round < AES256_ROUND_KEYS; ++round) {
        for (int j = 0; j < 4; ++j) {
            store_be32(out[round] + 4 * j, w[round * 4 + j]);
        }
    }
    memcpy(out[AES256_ROUND_KEYS], out[AES256_ROUND_KEYS - 1], 16);
}

static inline uint8_t xtime(uint8_t x){
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static inline uint8_t gf_mul(uint8_t x, uint8_t y){
    uint8_t res = 0;
    while (y) {
        if (y & 1) {
            res ^= x;
        }
        x = xtime(x);
        y >>= 1;
    }
    return res;
}

static inline void add_round_key(uint8_t state[16], const uint8_t rk[16]){
    for (int i = 0; i < 16; ++i) {
        state[i] ^= rk[i];
    }
}

static inline void sub_bytes(uint8_t state[16]){
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

static inline void shift_rows(uint8_t s[16]){
    uint8_t tmp;

    tmp = s[1];
    s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;

    tmp = s[2]; s[2] = s[10]; s[10] = tmp;
    tmp = s[6]; s[6] = s[14]; s[14] = tmp;

    tmp = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = tmp;
}

static inline void mix_columns(uint8_t s[16]){
    for (int i = 0; i < 16; i += 4) {
        uint8_t a0 = s[i + 0];
        uint8_t a1 = s[i + 1];
        uint8_t a2 = s[i + 2];
        uint8_t a3 = s[i + 3];
        uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        uint8_t u = a0;
        s[i + 0] ^= t ^ xtime((uint8_t)(a0 ^ a1));
        s[i + 1] ^= t ^ xtime((uint8_t)(a1 ^ a2));
        s[i + 2] ^= t ^ xtime((uint8_t)(a2 ^ a3));
        s[i + 3] ^= t ^ xtime((uint8_t)(a3 ^ u));
    }
}

static inline void inv_shift_rows(uint8_t s[16]){
    uint8_t tmp;

    tmp = s[13];
    s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = tmp;

    tmp = s[2]; s[2] = s[10]; s[10] = tmp;
    tmp = s[6]; s[6] = s[14]; s[14] = tmp;

    tmp = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = s[3]; s[3] = tmp;
}

static inline void inv_sub_bytes(uint8_t state[16]){
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

static inline void inv_mix_columns(uint8_t s[16]){
    for (int i = 0; i < 16; i += 4) {
        uint8_t a0 = s[i + 0];
        uint8_t a1 = s[i + 1];
        uint8_t a2 = s[i + 2];
        uint8_t a3 = s[i + 3];
        s[i + 0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[i + 1] = gf_mul(a0, 9)  ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[i + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9)  ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[i + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9)  ^ gf_mul(a3, 14);
    }
}

static inline void inv_mix_columns_block(uint8_t out[16], const uint8_t in[16]){
    memcpy(out, in, 16);
    inv_mix_columns(out);
}

static void expand_decrypt_keys(const uint8_t (*enc)[16],
                                uint8_t (*dec)[16])
{
    memcpy(dec[0], enc[AES256_ROUND_KEYS - 1], 16);
    for (int i = 1; i < AES256_ROUNDS; ++i) {
        inv_mix_columns_block(dec[i], enc[AES256_ROUND_KEYS - 1 - i]);
    }
    memcpy(dec[AES256_ROUNDS], enc[0], 16);
    memcpy(dec[AES256_ROUND_KEYS], enc[0], 16);
}

void aes256_expand_keys(const uint8_t key[32], aes256_rkeys* out){
    expand_encrypt_keys(key, out->enc);
    expand_decrypt_keys((const uint8_t (*)[16])out->enc, out->dec);
}

static void aes256_encrypt_block_soft(const aes256_rkeys* rk,
                                      const uint8_t in[16],
                                      uint8_t out[16]){
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, rk->enc[0]);
    for (int r = 1; r < AES256_ROUNDS; ++r) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk->enc[r]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk->enc[AES256_ROUNDS]);

    memcpy(out, state, 16);
}

static void aes256_decrypt_block_soft(const aes256_rkeys* rk,
                                      const uint8_t in[16],
                                      uint8_t out[16]){
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, rk->enc[AES256_ROUNDS]);
    for (int r = AES256_ROUNDS - 1; r > 0; --r) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk->enc[r]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, rk->enc[0]);

    memcpy(out, state, 16);
}

void aes256_encrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    aes256_encrypt_block_hw(rk, in, out);
#else
    aes256_encrypt_block_soft(rk, in, out);
#endif
}

void aes256_decrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    aes256_decrypt_block_hw(rk, in, out);
#else
    aes256_decrypt_block_soft(rk, in, out);
#endif
}

static inline void gf_mulx_128(uint8_t tweak[16]){
    uint64_t lo, hi;
    memcpy(&lo, tweak, 8);
    memcpy(&hi, tweak + 8, 8);
    uint64_t carry = hi >> 63;
    hi = (hi << 1) | (lo >> 63);
    lo <<= 1;
    if (carry) {
        lo ^= 0x87ULL;
    }
    memcpy(tweak, &lo, 8);
    memcpy(tweak + 8, &hi, 8);
}

static void aes_xts_process(const aes256_rkeys* data_keys,
                            const aes256_rkeys* tweak_keys,
                            const uint8_t iv[16],
                            const uint8_t* in,
                            uint8_t* out,
                            size_t len,
                            int encrypt)
{
    if (len == 0) {
        return;
    }

    uint8_t tweak[16];
    uint8_t tmp[16];
    uint8_t buf[16];

    aes256_encrypt_block_armv8(tweak_keys, iv, tweak);

    for (size_t off = 0; off < len; off += 16) {
        for (int i = 0; i < 16; ++i) {
            tmp[i] = in[off + i] ^ tweak[i];
        }

        if (encrypt) {
            aes256_encrypt_block_armv8(data_keys, tmp, buf);
        } else {
            aes256_decrypt_block_armv8(data_keys, tmp, buf);
        }

        for (int i = 0; i < 16; ++i) {
            out[off + i] = buf[i] ^ tweak[i];
        }

        gf_mulx_128(tweak);
    }
}

int aes_xts256_encrypt_armv8(const uint8_t dk[32], const uint8_t tk[32],
                             const uint8_t iv[16], const uint8_t* in,
                             uint8_t* out, size_t len)
{
    if ((len % 16) != 0) {
        return -1; // TODO: ciphertext stealing
    }
    aes256_rkeys data_keys;
    aes256_rkeys tweak_keys;
    aes256_expand_keys(dk, &data_keys);
    aes256_expand_keys(tk, &tweak_keys);
    aes_xts_process(&data_keys, &tweak_keys, iv, in, out, len, 1);
    return 0;
}

int aes_xts256_decrypt_armv8(const uint8_t dk[32], const uint8_t tk[32],
                             const uint8_t iv[16], const uint8_t* in,
                             uint8_t* out, size_t len)
{
    if ((len % 16) != 0) {
        return -1; // TODO: ciphertext stealing
    }
    aes256_rkeys data_keys;
    aes256_rkeys tweak_keys;
    aes256_expand_keys(dk, &data_keys);
    aes256_expand_keys(tk, &tweak_keys);
    aes_xts_process(&data_keys, &tweak_keys, iv, in, out, len, 0);
    return 0;
}
