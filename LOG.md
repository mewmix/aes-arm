commit ca7e567b40432e0fe6af7094d199d12ab39fd1dc
Author: Alexander James Klein <him@Alexanders-MacBook-Pro.local>
Date:   Fri Oct 17 23:28:19 2025 -0700

    feat: Initial implementation of AES-XTS-256
    
    - Created xts.h with the C ABI.
    - Created aes_armv8_xts.c with a portable C implementation of the AES-256 key expansion and a basic structure for the XTS implementation.
    - Created xts_kat.py for Known Answer Tests (KAT) against PyCA.
    - Implemented the AES-256 decryption logic using ARMv8 Crypto intrinsics.
    - Added debug prints to both C and Python code to compare values.
