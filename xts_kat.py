# xts_kat.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, ctypes, sys, pathlib, binascii

# Load your shared lib
lib = ctypes.CDLL(str(pathlib.Path("./libxts.so").resolve()))

# C types
u8_p = ctypes.POINTER(ctypes.c_uint8)

lib.aes_xts256_encrypt_armv8.argtypes = [u8_p,u8_p,u8_p,u8_p,u8_p,ctypes.c_size_t]
lib.aes_xts256_encrypt_armv8.restype  = ctypes.c_int
lib.aes_xts256_decrypt_armv8.argtypes = [u8_p,u8_p,u8_p,u8_p,u8_p,ctypes.c_size_t]
lib.aes_xts256_decrypt_armv8.restype  = ctypes.c_int

def xts_pyca_enc(dk, tk, iv, pt):
    key = dk + tk
    cipher = Cipher(algorithms.AES(key), modes.XTS(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(pt) + enc.finalize()

def xts_pyca_dec(dk, tk, iv, ct):
    key = dk + tk
    cipher = Cipher(algorithms.AES(key), modes.XTS(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def c_encrypt(dk, tk, iv, pt):
    out = bytearray(len(pt))
    rc = lib.aes_xts256_encrypt_armv8(
        (ctypes.c_uint8*32).from_buffer_copy(dk),
        (ctypes.c_uint8*32).from_buffer_copy(tk),
        (ctypes.c_uint8*16).from_buffer_copy(iv),
        (ctypes.c_uint8*len(pt)).from_buffer_copy(pt),
        (ctypes.c_uint8*len(pt)).from_buffer(out),
        len(pt)
    )
    assert rc==0
    return bytes(out)

def c_decrypt(dk, tk, iv, ct):
    out = bytearray(len(ct))
    rc = lib.aes_xts256_decrypt_armv8(
        (ctypes.c_uint8*32).from_buffer_copy(dk),
        (ctypes.c_uint8*32).from_buffer_copy(tk),
        (ctypes.c_uint8*16).from_buffer_copy(iv),
        (ctypes.c_uint8*len(ct)).from_buffer_copy(ct),
        (ctypes.c_uint8*len(ct)).from_buffer(out),
        len(ct)
    )
    assert rc==0
    return bytes(out)

def main():
    dk = os.urandom(32)
    tk = os.urandom(32)
    iv = os.urandom(16)
    pt = os.urandom(16*8)  # 8 blocks

    ct_py = xts_pyca_enc(dk, tk, iv, pt)
    pt_py = xts_pyca_dec(dk, tk, iv, ct_py)

    print("Python data key:")
    print(dk.hex())
    print("\nPython tweak key:")
    print(tk.hex())
    print("\nPython IV:")
    print(iv.hex())
    print("\nPython ciphertext:")
    print(ct_py.hex())

    ct_c = c_encrypt(dk, tk, iv, pt)
    pt_c = c_decrypt(dk, tk, iv, ct_c)

    assert ct_py == ct_c, "CT mismatch"
    assert pt_py == pt == pt_c, "PT mismatch"

    print("XTS-256 KAT OK")
    print("CT:", binascii.hexlify(ct_c).decode())

if __name__ == "__main__":
    main()
