#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
from threading import Thread
import socket
import datetime
import sys
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
CMD_MENU = "GET_MENU"
CMD_CLOSING = "CLOSING"
CMD_KEYS = "PKI"
CMD_CERTS = "CERTS"
PKI = []
MENU = "menu_today.txt"
SAVE_NAME = "result-"
MAX_BUFFER_SIZE = 2048
def send_key(conn: socket.socket):
    try:
        with open("server_public.pem", "rb") as f:
            data = f.read()
            conn.send(data)
            data = conn.recv(4096)
            return data
    except FileNotFoundError:
        print(f"[KEYS] FAIL: Public key not found.")
        return False
def load_keys(password: str):
    try:
        with open("server_private.pem", "rb") as f:
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
            conn.send(data)
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
    signature = data.split(b"|")[0][7:]
    # print(f"[DEBUGGING] Received Signature: {signature[:10]}...")
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
        print(f"[CMD] RECIEVED: {CMD_MENU} from {ip_addr}")
        send_file(conn, MENU)
        print("[CMD] OK: Sent menu to " + ip_addr)
    elif CMD_CLOSING in usr_cmd: 
        print(f"[CMD] RECIEVED: {CMD_CLOSING} from {ip_addr}")
        initial = b""
        initial += net_bytes
        data = receive_file(conn, initial)
        if check_signature(data):
            filename = SAVE_NAME +  ip_addr + "-" + (datetime.datetime.now()).strftime("%Y-%m-%d_%H%M")
            data = data.split(b"|")[1]
            save_file(filename, data)
            print(f"[CMD] OK: File saved as: {filename}")
        else:
            print("[SERVER] FAIL: Signature invalid.")
    elif CMD_KEYS in usr_cmd:
        print(f"[SERVER] RECEIVED: {CMD_KEYS} from {ip_addr}")
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

def client_thread(conn: socket.socket, ip: str, port: int):
    command_menu(conn, ip)
    conn.close()
    print(f"[SERVER] Connection from {ip}:{port} closed.")

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
            print(f"[SERVER] INCOMING connection from {ip}:{port}")
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
