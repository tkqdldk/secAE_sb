from aes import AES
from des_module import des, triple_des, PAD_PKCS5, ECB

def aes_test():
    print("==== AES TEST ====")
    # Clé de 128 bits (16 octets)
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x3243f6a8885a308d313198a2e0370734

    aes = AES(key)
    encrypted = aes.encrypt(plaintext)
    decrypted = aes.decrypt(encrypted)

    print(f"Plaintext : {hex(plaintext)}")
    print(f"Encrypted : {hex(encrypted)}")
    print(f"Decrypted : {hex(decrypted)}")
    print("Success" if plaintext == decrypted else "Failure")

def des_test():
    print("\n==== DES TEST ====")
    key = b"8bytekey"
    message = b"secret!!"  # Exactly 8 bytes
    des_cipher = des(key, pad=None, padmode=PAD_PKCS5)
    encrypted = des_cipher.encrypt(message)
    decrypted = des_cipher.decrypt(encrypted)

    print(f"Plaintext : {message}")
    print(f"Encrypted : {encrypted.hex()}")
    print(f"Decrypted : {decrypted}")
    print("Success" if decrypted == message else "Failure")

def triple_des_test():
    print("\n==== Triple DES TEST ====")
    key = b"Sixteen byte key"  # 16 bytes for 2-key 3DES
    message = b"Confidential!!"  # Multiple of 8 bytes
    cipher = triple_des(key, padmode=PAD_PKCS5)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)

    print(f"Plaintext : {message}")
    print(f"Encrypted : {encrypted.hex()}")
    print(f"Decrypted : {decrypted}")
    print("Success" if decrypted == message else "Failure")

if __name__ == "__main__":
    aes_test()
    des_test()
    triple_des_test()
