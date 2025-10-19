
.global aes256_encrypt_block_armv8_asm

aes256_encrypt_block_armv8_asm:
    ld1 {v0.16b}, [x1]
    ld1 {v1.16b}, [x0], #16
    eor v0.16b, v0.16b, v1.16b
    movi v2.16b, #0
    mov w3, #13
.Lenc_loop:
    aese v0.16b, v2.16b
    aesmc v0.16b, v0.16b
    ld1 {v1.16b}, [x0], #16
    eor v0.16b, v0.16b, v1.16b
    subs w3, w3, #1
    b.ne .Lenc_loop
    aese v0.16b, v2.16b
    ld1 {v1.16b}, [x0]
    eor v0.16b, v0.16b, v1.16b

    st1 {v0.16b}, [x2]

    ret

.global aes256_decrypt_block_armv8_asm

aes256_decrypt_block_armv8_asm:
    ld1 {v0.16b}, [x1]
    ld1 {v1.16b}, [x0], #16
    eor v0.16b, v0.16b, v1.16b
    movi v2.16b, #0
    mov w3, #13
.Ldec_loop:
    aesd v0.16b, v2.16b
    aesimc v0.16b, v0.16b
    ld1 {v1.16b}, [x0], #16
    eor v0.16b, v0.16b, v1.16b
    subs w3, w3, #1
    b.ne .Ldec_loop
    aesd v0.16b, v2.16b
    ld1 {v1.16b}, [x0]
    eor v0.16b, v0.16b, v1.16b

    st1 {v0.16b}, [x2]

    ret
