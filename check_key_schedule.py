from Crypto.Cipher import AES

def main():
    key = bytes(range(32))
    print("Key:", key.hex())
    cipher = AES.new(key, AES.MODE_ECB)
    
    # The key schedule is not directly accessible.
    # We can encrypt a block of zeros to get the first round key applied to it.
    # To get the full key schedule, we would need to re-implement the key expansion in python.
    
    # For now, let's just check the first round key.
    
    print("Python first round output:", cipher.encrypt(b'\x00'*16).hex())

if __name__ == "__main__":
    main()