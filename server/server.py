#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
from threading import Thread
import socket
import datetime
import sys
import os
from termcolor import colored
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
CMD_MENU = "GET_MENU"
CMD_CLOSING = "CLOSING"
CMD_KEYS = "PKI"
CMD_CERTS = "CERTS"
CMD_AES = "AES"
PKI = []
MENU = "menu_today.txt"
SAVE_NAME = "result-"
MAX_BUFFER_SIZE = 2048
def generate_aes():
    global aes_key, iv
    aes_key = os.urandom(16)
    iv = os.urandom(16)

def encrypt_aes(data):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes

def decrypt_aes(ct):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def send_aes(conn: socket.socket):
    data = aes_key + b"|" + iv
    ip = conn.getpeername()[0]
    for client in PKI:
        if client['ip'] == ip:
            cipher = client['cipher']
            data = cipher.encrypt(data)
    conn.send(data)


def send_key(conn: socket.socket):
    try:
        with open("public.pem", "rb") as f:
            data = f.read()
            conn.send(data)
            data = conn.recv(4096)
            return data
    except FileNotFoundError:
        print(f"[KEYS] FAIL: Public key not found.")
        return False
def load_keys(password: str):
    try:
        with open("private.pem", "rb") as f:
            key = RSA.import_key(f.read(), passphrase=password.encode())
            private_enc = PKCS1_OAEP.new(key)
    except FileNotFoundError:
        print(f"[ERROR] Could not import public key. Please ensure that the key exists.")
        sys.exit()
    return private_enc, key

def send_file(conn: socket.socket, filename: str):
    try:
        with open(filename, "rb") as f:
            read_bytes = f.read()
            signature = pkcs1_15.new(key).sign(SHA256.new(read_bytes))
            data = signature + b"|" + read_bytes
            print(f"[CMD] UNENCRYPTED data: {data[:10]}")
            enc_data = encrypt_aes(data)
            conn.send(enc_data)
            print(f"[CMD] Sending ENCRYPTED data: {enc_data[:10]}")
    except FileNotFoundError:
        print(f"[SERVER] FAIL: File not found: '{filename}'.") 
        sys.exit(0)

def save_file(filename: str, data: bytes):
    if(len(data) == 0):
        print(f"[SERVER] WARNING: Sales received is empty.")
    with open(filename, "wb") as f:
        f.write(data)

def receive_file(conn: socket.socket, data_block: bytes):
    data_block += conn.recv(MAX_BUFFER_SIZE)
    while True:
        net_bytes = conn.recv(MAX_BUFFER_SIZE)
        if net_bytes == '':
            data_block += net_bytes
        else:
            break
    return data_block

def check_signature(data: bytes):
    signature = data.split(b"|")[0]
    data = data.split(b"|")[1]
    try:
        pkcs1_15.new(PKI[0]['key']).verify(SHA256.new(data), signature)
        print("[SERVER] Signature OK")
        return True
    except (ValueError, TypeError):
        print("[SERVER] Signature FAIL")
        return False

def check_certs(cert):
    with open("client_cert.crt", "rb") as f:
        client_cert_data = f.read()
        correct_server_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())
        client_cert = x509.load_pem_x509_certificate(cert, default_backend())
        try:
            client_cert.public_key().verify(
                client_cert.signature,
                correct_server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False
def exchange_certs(conn: socket.socket):
    try:
        with open("server_cert.crt", "rb") as f:
            data = f.read()
            conn.send(data)
            data = conn.recv(4096)
            return data
    except FileNotFoundError:
        print(f"[KEYS] FAIL: Certificate not found.")
        return False

def command_menu(conn: socket.socket, ip_addr: str):  
    while True:
        net_bytes = conn.recv(MAX_BUFFER_SIZE)
        if net_bytes:
            break
    usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
    if CMD_MENU in usr_cmd:
        print(f"\n[CMD] RECIEVED: {CMD_MENU} from {ip_addr}")
        send_file(conn, MENU)
        print("[CMD] OK: Sent menu to " + ip_addr + "\n")
    elif CMD_CLOSING in usr_cmd: 
        print(f"[CMD] RECIEVED: {CMD_CLOSING} from {ip_addr}")
        initial = b""
        initial += net_bytes
        enc_data = receive_file(conn, initial)[7:]
        print(f"[CMD] RECEIVED ENCRYPTED data: {enc_data[:10]}")
        try:
            data = decrypt_aes(enc_data)
        except Exception as e:
            print(f"[CMD] FAIL: {e}")
            sys.exit(0)
        print(f"[CMD] After UNENCRYPTING data: {data[:10]}")
        if check_signature(data):
            filename = SAVE_NAME +  ip_addr + "-" + (datetime.datetime.now()).strftime("%Y-%m-%d_%H%M")
            data = data.split(b"|")[1]
            save_file(filename, data)
            print(f"[CMD] OK: File saved as: {filename}")
        else:
            print("[SERVER] FAIL: Signature invalid.")
    elif CMD_KEYS in usr_cmd:
        print(f"[SERVER] RECEIVED: {CMD_KEYS} from {ip_addr}")
        for i in range(len(PKI)):
            if PKI[i]['ip'] == ip_addr:
                print("[PKI] OK: PKI already bound to: " + ip_addr)
                send_key(conn)
                return
        dict_data = {
            "ip": ip_addr,
            "key": RSA.import_key(net_bytes[3:]),
            "cipher": PKCS1_OAEP.new(RSA.import_key(net_bytes[3:]))
        }
        PKI.append(dict_data)
        send_key(conn)
        print("[PKI] Key sent to: " + ip_addr)
        print("[PKI] OK: PKI bound to: " + ip_addr)
    elif CMD_CERTS in usr_cmd:
        print(f"[SERVER] RECEIVED: {CMD_CERTS} from {ip_addr}")
        client_cert = exchange_certs(conn)
        if check_certs(client_cert):
            print("[CERTS] OK.")
        else:
            print("[CERTS] FAIL.")
    elif CMD_AES in usr_cmd:
        print(f"[SERVER] RECEIVED: {CMD_AES} from {ip_addr}")
        if len(PKI) == 0:
            print("[AES] FAIL: No PKI bound.")
            return
        generate_aes()
        send_aes(conn)
        print("[AES] OK: AES sent to: " + ip_addr)

def client_thread(conn: socket.socket, ip: str, port: int):
    command_menu(conn, ip)
    conn.close()

def start_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"Server started on {host}:{port}")
    sock.bind((host, port))
    sock.listen(10)
    print(f"Server is listening on port {port}...")
    while True:
        try:
            conn, addr = sock.accept()
            ip, port = str(addr[0]), str(addr[1])
            Thread(target=client_thread, args=(conn, ip, port)).start()
        except KeyboardInterrupt:
            print("[SERVER] Keyboard Interrupt. Closing server.")
            sock.close()
            sys.exit()
if __name__ == "__main__":
    cipher, key = load_keys("server")
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 8888
    start_server(HOST, PORT)
