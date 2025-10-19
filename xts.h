// xts.h
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    AES256_ROUNDS = 14,
    AES256_ROUND_KEYS = AES256_ROUNDS + 1, // 15 round keys
};

typedef struct {
    uint8_t enc[AES256_ROUND_KEYS][16];
    uint8_t dec[AES256_ROUND_KEYS][16];
} aes256_rkeys;

// Expand a 256-bit key into 15 round keys (portable C, not shown here)
void aes256_expand_keys(const uint8_t key[32], aes256_rkeys* out);

// AES-256 encrypt one 16B block using ARMv8 Crypto (AESE/AESMC).
void aes256_encrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]);

// AES-256 decrypt one 16B block using ARMv8 Crypto (AESD/AESIMC).
void aes256_decrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16]);

// XTS encrypt (no ciphertext stealing). length must be multiple of 16.
// data_key and tweak_key are independent 256-bit keys (XTS-256).
// iv (aka tweak input) is a 128-bit sector number / block tweak (little-endian).
int aes_xts256_encrypt_armv8(
    const uint8_t data_key[32],
    const uint8_t tweak_key[32],
    const uint8_t iv[16],
    const uint8_t* in, uint8_t* out, size_t len);

// Decrypt symmetric to encrypt (no CTS).
int aes_xts256_decrypt_armv8(
    const uint8_t data_key[32],
    const uint8_t tweak_key[32],
    const uint8_t iv[16],
    const uint8_t* in, uint8_t* out, size_t len);

#ifdef __cplusplus
}
#endif
