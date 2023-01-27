#------------------------------------------------------------------------------------------
# client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client
 
import datetime
import sys              # handle system error
import socket
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

host = socket.gethostbyname(socket.gethostname())
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
cmd_KEYS = b"PKI"
menu_file = "menu.csv"
return_file = "day_end.csv"

def exchange_keys():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_KEYS)
        try:
            with open("client_public.pem", "rb") as f:
                data = f.read()
                conn.send(data)
                print(f"[CLIENT] Sending public key...")
                data = conn.recv(4096)
                print(f"[CLIENT] Receiving server's public key...")
                cipher = PKCS1_OAEP.new(RSA.import_key(data))
                return cipher
        except FileNotFoundError:
            print(f"[KEYS] FAIL: File not found: '{menu_file}'.")
            return False

def send_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_END_DAY)
        try:
            with open(return_file, "rb") as f:
                data = f.read(1024)
                while data != b'':
                    print(f"[DEBUGGING] Sending: {data}")
                    conn.send(data)
                    data = f.read(1024)
                return True
        except FileNotFoundError:
            print(f"[CLOSING] FAIL: File not found: '{return_file}'.")
            return False

def receive_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((host, port))
        conn.sendall(cmd_GET_MENU)
        data = conn.recv(4096)
        print(f"[DEBUGGING] Received: {data}")
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
        with open("client_private.pem", "rb") as f:
            key = RSA.import_key(f.read(), passphrase=password.encode())
            private_enc = PKCS1_OAEP.new(key)
    except:
        print(f"Authenticity of private key could not be verified. Ensure that the key is correct.")
        sys.exit()
    try:
        with open("client_public.pem", "rb") as f:
            key = RSA.import_key(f.read())
            public_enc = PKCS1_OAEP.new(key)
    except FileNotFoundError:
        print(f"[ERROR] Could not import public key. Ensure that the key exists.")
        sys.exit()
    return private_enc, public_enc


if __name__ == "__main__":
    print(f"[CLIENT] Loading keys...")
    cipher, client_public = initialize_keys("client")
    print(f"[CLIENT] OK. Keys successfully loaded")
    print(f"[CLIENT] Attempting Connection to {host}:{port}")
    print(f"[CLIENT] Connected to {host}:{port}")
    print(f"[CLIENT] Beginning PKI exchange...")
    server_public = exchange_keys()
    print(f"[CLIENT] OK. PKI exchange complete.")
    # print(f"[CLIENT] Sending: {cmd_GET_MENU.decode()}")
    if receive_file():
        print(f"[GET_MENU] OK.")
    # print(f"[CLIENT] Sending: {cmd_END_DAY.decode()}")
    if send_file():
        print(f"[CLOSING] OK.")
    print(f"[CLIENT] Closing connection.")




