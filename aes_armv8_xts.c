// aes_armv8_xts.c
#include "xts.h"
#include <arm_neon.h>
#include <string.h>

static inline uint8x16_t loadu(const void* p){ return vld1q_u8((const uint8_t*)p); }
static inline void storeu(void* p, uint8x16_t v){ vst1q_u8((uint8_t*)p, v); }
static inline uint8x16_t load_round_key(const uint8_t* p){ return vrev32q_u8(vld1q_u8(p)); }

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

static const uint32_t rcon[10] = {
    0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
    0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

static inline uint32_t load_le32(const uint8_t* p){
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
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

static void expand_encrypt_keys(const uint8_t key[32], uint8_t out[AES256_ROUND_KEYS][16]){
    uint32_t w[60];
    for (int i = 0; i < 8; ++i) {
        w[i] = load_le32(key + 4 * i);
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
            store_le32(out[round] + 4 * j, w[round * 4 + j]);
        }
    }
}

static void expand_decrypt_keys(const uint8_t enc[AES256_ROUND_KEYS][16],
                                uint8_t dec[AES256_ROUND_KEYS][16])
{
    memcpy(dec[0], enc[AES256_ROUNDS], 16);
    for (int i = 1; i < AES256_ROUNDS; ++i) {
        uint8x16_t v = loadu(enc[AES256_ROUNDS - i]);
        v = vaesimcq_u8(v);
        storeu(dec[i], v);
    }
    memcpy(dec[AES256_ROUNDS], enc[0], 16);
}

void aes256_expand_keys(const uint8_t key[32], aes256_rkeys* out){
    expand_encrypt_keys(key, out->enc);
    expand_decrypt_keys(out->enc, out->dec);
}

static inline uint8x16_t aes256_encrypt_vec(const aes256_rkeys* rk, uint8x16_t block){
    block = veorq_u8(block, load_round_key(rk->enc[0]));
    for (int r = 1; r < AES256_ROUNDS; ++r) {
        block = vaeseq_u8(block, load_round_key(rk->enc[r]));
        block = vaesmcq_u8(block);
    }
    block = vaeseq_u8(block, load_round_key(rk->enc[AES256_ROUNDS]));
    block = veorq_u8(block, load_round_key(rk->enc[AES256_ROUNDS]));
    return block;
}

static inline uint8x16_t aes256_decrypt_vec(const aes256_rkeys* rk, uint8x16_t block){
    block = veorq_u8(block, load_round_key(rk->dec[0]));
    for (int r = 1; r < AES256_ROUNDS; ++r) {
        block = vaesdq_u8(block, load_round_key(rk->dec[r]));
        block = vaesimcq_u8(block);
    }
    block = vaesdq_u8(block, load_round_key(rk->dec[AES256_ROUNDS]));
    block = veorq_u8(block, load_round_key(rk->dec[AES256_ROUNDS]));
    return block;
}

void aes256_encrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]){
    uint8x16_t b = vrev32q_u8(loadu(in));
    b = aes256_encrypt_vec(rk, b);
    storeu(out, vrev32q_u8(b));
}

void aes256_decrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]){
    uint8x16_t b = vrev32q_u8(loadu(in));
    b = aes256_decrypt_vec(rk, b);
    storeu(out, vrev32q_u8(b));
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
    aes256_encrypt_block_armv8(tweak_keys, iv, tweak);
    uint8x16_t tweak_vec = loadu(tweak);

    for (size_t off = 0; off < len; off += 16) {
        uint8x16_t block = loadu(in + off);
        uint8x16_t x = veorq_u8(block, tweak_vec);
        uint8x16_t y = encrypt ? aes256_encrypt_vec(data_keys, x)
                               : aes256_decrypt_vec(data_keys, x);
        y = veorq_u8(y, tweak_vec);
        storeu(out + off, y);

        storeu(tweak, tweak_vec);
        gf_mulx_128(tweak);
        tweak_vec = loadu(tweak);
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
