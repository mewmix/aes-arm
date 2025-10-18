// aes_armv8_xts.c
#include "xts.h"
#include <arm_neon.h>
#include <string.h>
#include <stdio.h>

// S-box table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round constants
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

typedef struct { uint8_t k[16][16]; } aes256_keys16;

// RotWord performs a cyclic permutation on a 4-byte word.
static void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// SubWord substitutes each byte of a 4-byte word using the S-box.
static void SubWord(uint8_t *word) {
    word[0] = sbox[word[0]];
    word[1] = sbox[word[1]];
    word[2] = sbox[word[2]];
    word[3] = sbox[word[3]];
}

void aes256_expand_keys(const uint8_t key[32], aes256_rkeys* out) {
    uint32_t i = 0;
    uint8_t temp[4];

    for (i = 0; i < 8; ++i) {
        memcpy(&out->rk[i/4][(i%4)*4], &key[i*4], 4);
    }

    i = 8;

    while (i < 60) {
        memcpy(temp, &out->rk[(i-1)/4][((i-1)%4)*4], 4);

        if (i % 8 == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / 8];
        } else if (i % 8 == 4) {
            SubWord(temp);
        }

        uint8_t* prev_key = &out->rk[(i-8)/4][((i-8)%4)*4];
        uint8_t* curr_key = &out->rk[i/4][(i%4)*4];
        curr_key[0] = prev_key[0] ^ temp[0];
        curr_key[1] = prev_key[1] ^ temp[1];
        curr_key[2] = prev_key[2] ^ temp[2];
        curr_key[3] = prev_key[3] ^ temp[3];
        
        i++;
    }
}

static void aes256_expand_k16(const uint8_t key[32], aes256_keys16* out) {
    aes256_rkeys rks;
    aes256_expand_keys(key, &rks);
    memcpy(out->k, rks.rk, 15 * 16);
    // The 16th key is a copy of the 15th key for the final whitening step in encryption
    memcpy(out->k[15], rks.rk[14], 16);
}

static void aes256_prepare_dec_keys(const aes256_keys16* enc_keys, aes256_keys16* dec_keys) {
    dec_keys->k[0][0] = enc_keys->k[14][0];
    dec_keys->k[14][0] = enc_keys->k[0][0];

    for (int r = 1; r < 14; r++) {
        uint8x16_t k = vld1q_u8(enc_keys->k[14-r]);
        k = vaesimcq_u8(k);
        vst1q_u8(dec_keys->k[r], k);
    }
}

static inline uint8x16_t loadu(const void* p){ return vld1q_u8((const uint8_t*)p); }
static inline void storeu(void* p, uint8x16_t v){ vst1q_u8((uint8_t*)p, v); }

static inline void aes256_encrypt_block_k16(const aes256_keys16* ks, const uint8_t in[16], uint8_t out[16]) {
    uint8x16_t s = loadu(in);
    s = veorq_u8(s, vld1q_u8(ks->k[0]));
    for (int r = 1; r <= 13; r++) {
        s = vaeseq_u8(s, vld1q_u8(ks->k[r]));
        s = vaesmcq_u8(s);
    }
    s = vaeseq_u8(s, vld1q_u8(ks->k[14]));
    s = veorq_u8(s, vld1q_u8(ks->k[15]));
    storeu(out, s);
}

static inline void aes256_decrypt_block_k16(const aes256_keys16* ks, const uint8_t in[16], uint8_t out[16]) {
    uint8x16_t s = loadu(in);
    s = veorq_u8(s, vld1q_u8(ks->k[0]));
    for (int r = 1; r <= 13; r++) {
        s = vaesdq_u8(s, vld1q_u8(ks->k[r]));
        s = vaesimcq_u8(s);
    }
    s = vaesdq_u8(s, vld1q_u8(ks->k[14]));
    storeu(out, s);
}

void aes256_encrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]) {
    aes256_keys16 ks;
    memcpy(ks.k, rk->rk, 15 * 16);
    memcpy(ks.k[15], rk->rk[14], 16);
	aes256_encrypt_block_k16(&ks, in, out);
}

static inline void gf_mulx_128(uint8_t T[16]) {
    uint64_t lo, hi;
    memcpy(&lo, T, 8);
    memcpy(&hi, T+8, 8);
    uint64_t carry = hi >> 63;
    hi = (hi << 1) | (lo >> 63);
    lo = (lo << 1);
    if (carry) {
        lo ^= 0x87ULL;
    }
    memcpy(T, &lo, 8);
    memcpy(T+8, &hi, 8);
}

static void aes_xts_process(
    const aes256_keys16* data_k, const aes256_keys16* tweak_k,
    const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len, int enc)
{
    if (len % 16) { return; }
    uint8_t T[16];
    aes256_encrypt_block_k16(tweak_k, iv, T);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t x[16], y[16];
        for (int i = 0; i < 16; i++) x[i] = in[off+i] ^ T[i];
        if (enc) {
            aes256_encrypt_block_k16(data_k, x, y);
        } else {
            aes256_decrypt_block_k16(data_k, x, y);
        }
        for (int i = 0; i < 16; i++) out[off+i] = y[i] ^ T[i];
        gf_mulx_128(T);
    }
}

int aes_xts256_encrypt_armv8(const uint8_t dk[32], const uint8_t tk[32],
                             const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len)
{
    if ((len % 16) != 0) return -1;
    aes256_keys16 dks = {0}, tks = {0};
    aes256_expand_k16(dk, &dks);
    aes256_expand_k16(tk, &tks);

    printf("C data key:\n");
    for (int i = 0; i < 32; ++i) {
        printf("%02x ", dk[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("C tweak key:\n");
    for (int i = 0; i < 32; ++i) {
        printf("%02x ", tk[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("C IV:\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x ", iv[i]);
    }
    printf("\n\n");

    aes_xts_process(&dks, &tks, iv, in, out, len, 1);

    printf("C ciphertext:\n");
    for (int i = 0; i < len; ++i) {
        printf("%02x ", out[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    return 0;
}

int aes_xts256_decrypt_armv8(const uint8_t dk[32], const uint8_t tk[32],
                             const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len)
{
    if ((len % 16) != 0) return -1;
    aes256_keys16 dks_enc = {0}, dks_dec = {0}, tks = {0};
    aes256_expand_k16(dk, &dks_enc);
    aes256_prepare_dec_keys(&dks_enc, &dks_dec);
    aes256_expand_k16(tk, &tks);
    return 0;
}

int main() {
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = i;
    }

    aes256_rkeys rks;
    aes256_expand_keys(key, &rks);

    printf("C key schedule:\n");
    for (int i = 0; i < 15; ++i) {
        for (int j = 0; j < 16; ++j) {
            printf("%02x ", rks.rk[i][j]);
        }
        printf("\n");
    }

    return 0;
}