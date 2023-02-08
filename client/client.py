#------------------------------------------------------------------------------------------
# client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client

import sys              # handle system error
import socket
from termcolor import colored
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

host = socket.gethostbyname(socket.gethostname())
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
cmd_KEYS = b"PKI"
cmd_CERTS = b"CERTS"
cmd_AES = b"AES"
menu_file = "menu.csv"
return_file = "day_end.csv"

def request_session():
    """
    It requests a new AES key and IV from the server, decrypts them, and stores them in global variables
    """
    global aes_key, iv
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_AES)
        print(colored(f"[AES] Requesting New Session Key...", "blue"))

        enc_data = conn.recv(4096)
        print(colored(f"[AES] Received Encrypted Session Key: {enc_data[:10]}...", "blue"))

        dec_data = cipher.decrypt(enc_data).split(b"|")
        print(colored(f"[AES] Decrypting Session Key...", "blue"))

        aes_key = dec_data[0]
        print(colored(f"[AES] Decrypted AES Key: {aes_key}", "blue"))

        iv = dec_data[1]
        print(colored(f"[AES] Decrypted IV: {iv}", "blue"))

        print(colored(f"[IMPORTANT] Session Key Exchange Complete! All further exchanges will be encrypted using the shared session key.", "green", attrs=["bold"]))
        
def encrypt_aes(data):
    """
    It takes a string, pads it to a multiple of 16 bytes, and then encrypts it using AES-CBC with a key
    and IV
    
    :param data: The data to be encrypted
    :return: The encrypted data.
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes

def decrypt_aes(ct):
    """
    It decrypts the ciphertext using the AES key and the initialization vector
    
    :param ct: ciphertext
    :return: The decrypted message.
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def exchange_certs():
    """
    The client sends a command to the server, the server responds with a command to send the client's
    certificate, the client sends the certificate, and the server responds with the server's certificate
    :return: The server's certificate.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        print(f"[CLIENT] Connected to {host}:{port}")
        print(f"""
        {colored("Unencrypted: RED (danger)", "red")} 
        {colored("Encrypted: BLUE (safe)", "blue")}
        """)
        conn.sendall(cmd_CERTS)
        try:
            with open("client_cert.crt", "rb") as f:
                file_data = f.read()
                data = conn.recv(4096)
                print(colored(f"[CERTS] Receiving cert...", "red"))
                conn.send(file_data)
                print(colored(f"[CERTS] Sending cert...", "red"))
                return data
        except FileNotFoundError:
            print(f"[CERTS] FAIL: File not found: 'client.crt'.")
            return False
        
def check_certs(cert):
    """
    It takes a certificate as a string, loads it as a certificate object, and then verifies that the
    certificate was signed by the correct public key
    
    :param cert: The certificate to check
    :return: The server's certificate.
    """
    with open("server_cert.crt", "rb") as f:
        server_cert_data = f.read()
        correct_server_cert = x509.load_pem_x509_certificate(server_cert_data, default_backend())
        server_cert = x509.load_pem_x509_certificate(cert, default_backend())
        try:
            server_cert.public_key().verify(
                server_cert.signature,
                correct_server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False

def exchange_keys():
    """
    It sends a command to the server, then it sends the public key to the server, then it receives the
    server's public key, then it returns the cipher and the server's public key
    :return: The cipher and the data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_KEYS)
        try:
            with open("public.pem", "rb") as f:
                data = f.read()
                conn.send(data)
                print(colored(f"[PKI] Sending key...", "red"))
                data = conn.recv(4096)
                print(colored(f"[PKI] Receiving key...", "red"))
                cipher = PKCS1_OAEP.new(RSA.import_key(data))
                return cipher, data
        except FileNotFoundError:
            print(f"[KEYS] FAIL: File not found: '{menu_file}'.")
            return False

def send_file():
    """
    It opens a socket connection to the server, sends a command to the server, then opens the file to be
    sent, reads the file, signs the file, sends the file, and closes the connection
    :return: The return_file is being returned.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_END_DAY)
        try:
            with open(return_file, "rb") as f:
                data = f.read()
                signature = pkcs1_15.new(client_private).sign(SHA256.new(data))
                send_data = signature + b"|" + data
                print(f"[CLOSING] UNENCRYPTED data: {send_data[:10]}")
                enc_data = encrypt_aes(send_data)
                print(f"[CLOSING] Sending ENCRYPTED data: {enc_data[:10]}")
                conn.send(enc_data)
                return True
        except FileNotFoundError:
            print(f"[CLOSING] FAIL: File not found: '{return_file}'.")
            return False

def receive_file():
    """
    It receives a file from the server, decrypts it, verifies the signature, and saves it to a file
    :return: True if the file was saved successfully, otherwise it returns False.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_GET_MENU)
        try:
            enc_data = conn.recv(4096)
            print(f"[GET_MENU] Receiving ENCRYPTED data: {enc_data[:10]}")
            data = decrypt_aes(enc_data)
        except ValueError:
                print(f"[ERROR] !!! Packet was dropped during transmission, this could be due to bad connection.")
        print(f"[GET_MENU] After DECRYPTING data:{data[:10]}")
        server_signature = data.split(b"|")[0]
        data = data.split(b"|")[1]
        hash_obj = SHA256.new(data)
        try:
            pkcs1_15.new(RSA.import_key(server_key)).verify(hash_obj, server_signature)
            print(f"[DEBUGGING] Signature OK")
        except (ValueError, TypeError):
            print(f"[DEBUGGING] Signature FAIL")
            return False
        try:
            with open(menu_file, "wb") as f:
                f.write(data)
                return True
        except FileNotFoundError:
            print(f"[GET_MENU] FAIL: File not could not be saved to: '{menu_file}'.")
            conn.close()
            return False

def initialize_keys(password: str):
    """
    It takes a password, and then it tries to open the private key file, and if it can't, it prints an
    error message and exits. If it can, it tries to open the public key file, and if it can't, it prints
    an error message and exits. If it can, it returns the private and public keys.
    
    :param password: str - The password to decrypt the private key
    :type password: str
    :return: The private_enc, public_enc, and private_key are being returned.
    """
    try:
        with open("private.pem", "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase=password.encode())
            private_enc = PKCS1_OAEP.new(private_key)
    except:
        print(f"Authenticity of private key could not be verified. Ensure that the key is correct.")
        sys.exit()
    try:
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())
            public_enc = PKCS1_OAEP.new(public_key)
    except FileNotFoundError:
        print(f"[ERROR] Could not import public key. Ensure that the key exists.")
        sys.exit()
    return private_enc, public_enc, private_key


if __name__ == "__main__":
    server_cert = exchange_certs()
    if check_certs(server_cert):
        print(colored(f"[CERTS] Certificates verified.\n", attrs=["bold"]))
    else:
        print(f"[CERTS] FAIL.")
        sys.exit()
    print(colored(f"[PKI] Loading keys...", "red"))
    cipher, client_public, client_private = initialize_keys("client")
    server_public, server_key = exchange_keys()
    print(colored(f"[PKI] Keys OK.", attrs=["bold"]))
    print(colored(f"[IMPORTANT] PKI Established, AES key exchange will now occur with RSA encryption.\n", "green", attrs=["bold"]))
    request_session()
    # print(f"\n[CLIENT] Sending: {cmd_GET_MENU.decode()}")
    print(colored(f"\n[CLIENT] Sending: {cmd_GET_MENU.decode()}", attrs=["bold"]))
    if receive_file():
        print(f"[GET_MENU] OK. \n")
    print(f"[CLIENT] Sending: {cmd_END_DAY.decode()}")
    if send_file():
        print(f"[CLOSING] OK.")
    print(f"[CLIENT] Closing connection.")
