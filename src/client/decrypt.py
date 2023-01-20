from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
plaintext = "Hello World"
with open("public.pem", "rb") as f:
    key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())

with open("private.pem", "rb") as f:
    key = RSA.import_key(f.read(), passphrase=input("Enter passphrase: ").encode())
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext).decode()
    print(plaintext)
    
