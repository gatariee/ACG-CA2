#------------------------------------------------------------------------------------------
# client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client

import sys              # handle system error
import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
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
    global aes_key, iv
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_AES)
        enc_data = conn.recv(4096)
        dec_data = cipher.decrypt(enc_data).split(b"|")
        aes_key = dec_data[0]
        iv = dec_data[1]

def encrypt_aes(data):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes

def decrypt_aes(ct):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def exchange_certs():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        print(f"[CLIENT] Connected to {host}:{port}")
        conn.sendall(cmd_CERTS)
        try:
            with open("client_cert.crt", "rb") as f:
                file_data = f.read()
                data = conn.recv(4096)
                print(f"[CLIENT] Receiving cert...")
                conn.send(file_data)
                print(f"[CLIENT] Sending cert...")
                return data
        except FileNotFoundError:
            print(f"[CERTS] FAIL: File not found: 'client.crt'.")
            return False
def check_certs(cert):
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_KEYS)
        try:
            with open("public.pem", "rb") as f:
                data = f.read()
                conn.send(data)
                print(f"[CLIENT] Sending key...")
                data = conn.recv(4096)
                print(f"[CLIENT] Receiving key...")
                cipher = PKCS1_OAEP.new(RSA.import_key(data))
                return cipher, data
        except FileNotFoundError:
            print(f"[KEYS] FAIL: File not found: '{menu_file}'.")
            return False


def send_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_END_DAY)
        try:
            with open(return_file, "rb") as f:
                data = f.read()
                signature = pkcs1_15.new(client_private).sign(SHA256.new(data))
                send_data = signature + b"|" + data
                enc_data = encrypt_aes(send_data)
                conn.send(enc_data)
                return True
        except FileNotFoundError:
            print(f"[CLOSING] FAIL: File not found: '{return_file}'.")
            return False

def receive_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_GET_MENU)
        enc_data = conn.recv(4096)
        print(f"[DEBUGGING] Receiving ENCRYPTED data: {enc_data[:10]}")
        data = decrypt_aes(enc_data)
        print(f"[DEBUGGING] Decrypting data: {data[:20]}")
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
        print(f"[CERTS] OK.")
    else:
        print(f"[CERTS] FAIL.")
        sys.exit()
    print(f"[CLIENT] Loading keys...")
    cipher, client_public, client_private = initialize_keys("client")
    server_public, server_key = exchange_keys()
    print(f"[PKI] OK. ")
    request_session()
    print(f"[CLIENT] Sending: {cmd_GET_MENU.decode()}")
    if receive_file():
        print(f"[GET_MENU] OK.")
    print(f"[CLIENT] Sending: {cmd_END_DAY.decode()}")
    if send_file():
        print(f"[CLOSING] OK.")
    print(f"[CLIENT] Closing connection.")
    input("Press enter to exit...")




