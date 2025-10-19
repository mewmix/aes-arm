# AES-XTS-256 with ARMv8 Crypto Extensions

This repository provides a high-performance implementation of AES-XTS-256 using ARMv8 Crypto Extensions, with a focus on correctness and performance. It includes a C implementation with ARM intrinsics, a Python-based Known Answer Test (KAT) harness using PyCA, and a clear build process.

## Git History Summary

The development of this toolkit progressed as follows:

1.  **Initial Implementation**: The initial commit laid the groundwork for AES-XTS-256 with a C implementation of the C ABI (`xts.h`), a portable C implementation of the AES-256 key expansion, and a basic structure for the XTS implementation (`aes_armv8_xts.c`). A Python-based Known Answer Test (KAT) script (`xts_kat.py`) was also created to verify the implementation against PyCA.
2.  **Key Schedule Extension**: The AES-256 key schedule was extended to duplicate the last round key for hardware whitening and to build decrypt-side mixes that suit both the software and AES instruction flows.
3.  **ARMv8 Crypto Extensions**: ARMv8 Crypto Extension block routines were added, guarded by feature detection, while preserving the portable C fallback so non-AArch64 builds continue to work unchanged.
4.  **ARM Assembly Rework**: The ARM assembly path was reworked so each round now does an explicit AESE/AESD with a zero key plus the correct XOR of the true round subkeys. The C support code was updated to match, and the public header was slimmed down.
5.  **Build Verification**: Documentation was added to the `README.md` to provide clear instructions on how to build and verify the implementation.

## How to Use

This toolkit provides a C library and a Python script for testing.

### Building the Library

A `Makefile` is provided for easy compilation of the C code into a shared library (`libxts.so`).

```bash
make
```

This command compiles the C code in `aes_armv8_xts.c` and the ARMv8 assembly in `aes_armv8_xts_asm.S` into a shared library named `libxts.so`.

### Verifying the Implementation

The `xts_kat.py` script is a Known Answer Test (KAT) harness that uses PyCA to verify the correctness of the C implementation.

```bash
python3 xts_kat.py
```

The script will print "XTS-256 KAT OK" if the C implementation matches PyCA's AES-XTS reference.

### C ABI

The C Application Binary Interface (ABI) is defined in `xts.h`. It exposes the following functions:

*   `aes256_expand_keys(const uint8_t key[32], aes256_rkeys* out)`: Expands a 256-bit key into 15 round keys.
*   `aes256_encrypt_block_armv8(const aes256_rkeys* rk, const uint8_t in[16], uint8_t out[16])`: Encrypts one 16-byte block using ARMv8 Crypto Extensions.
*   `aes_xts256_encrypt_armv8(const uint8_t data_key[32], const uint8_t tweak_key[32], const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len)`: Encrypts data using AES-XTS with ARMv8 Crypto Extensions. The length must be a multiple of 16.
*   `aes_xts256_decrypt_armv8(const uint8_t data_key[32], const uint8_t tweak_key[32], const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len)`: Decrypts data using AES-XTS with ARMv8 Crypto Extensions. The length must be a multiple of 16.

### Other Files

*   `aes_armv8_xts_asm.S`: This file contains the ARMv8 assembly code for the AES-XTS implementation.
*   `check_key_schedule.py`: This is a simple script that uses PyCryptodome to create an AES cipher and print the output of encrypting a block of zeros. It can be used as a basic check to ensure that the key schedule is working correctly.

## Future Work

The following tasks are planned for future development:

*   **Ciphertext Stealing (CTS)**: Implement ciphertext stealing to handle inputs that are not a multiple of 16 bytes.
*   **Decrypt Block**: Add a decrypt block using `AESD/AESIMC` for improved performance.
*   **Constant-Time Audit**: Perform a constant-time audit to ensure that the implementation is not vulnerable to timing attacks.
*   **Micro-benchmarking**: Conduct micro-benchmarking to measure cycles/byte and optimize performance through alignment and prefetch polishing.
