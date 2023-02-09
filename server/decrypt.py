from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def load_keys():
    """
    It reads the private key from the file and returns it
    :return: The private key is being returned.
    """
    with open('private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase='server'.encode())
    return private_key

def decrypt_file(filename):
    """
    It reads the encrypted file, decrypts it using the private key, and writes the decrypted data back
    to the file
    
    :param filename: The name of the file to be decrypted
    """
    private_key = load_keys()
    with open(filename, 'rb') as f:
        enc_data = f.read()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data = cipher_rsa.decrypt(enc_data)
    with open(filename, 'wb') as f:
        f.write(data)

def encrypt_file(filename):
    """
    It encrypts the file using the public key.
    
    :param filename: The name of the file to encrypt
    """
    public_key = load_keys()
    with open(filename, 'rb') as f:
        data = f.read()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_data = cipher_rsa.encrypt(data)
    with open(filename, 'wb') as f:
        f.write(enc_data)
    
if __name__ == '__main__':
    for file in os.listdir():
        if "result" in file:
            try:
                decrypt_file(file)
            except Exception as e:
                if "Ciphertext" in str(e):
                    encrypt_file(file)

