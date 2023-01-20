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
# constants
CMD_MENU = "GET_MENU"
CMD_CLOSING = "CLOSING"
CMD_KEYS = "PKI"
PKI = {}
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
        print(f"[ERROR] Could not import public key. Ensure that the key exists.")
        sys.exit()
    return private_enc

def send_file(conn: socket.socket, filename: str):
    try:
        with open(filename, "rb") as f:
            read_bytes = f.read()
            if(len(read_bytes) == 0):
                print(f"[SERVER] WARNING: File is empty: '{filename}'.")
            conn.send(read_bytes)
    except FileNotFoundError:
        print(f"[SERVER] FAIL: File not found: '{filename}'.") 
        sys.exit(0)

def save_file(filename: str, data: bytes):
    if(len(data) == 0):
        print(f"[SERVER] WARNING: Sales received is empty.")
    with open(filename, "wb") as f:
        f.write(data[7:])

def receive_file(conn: socket.socket, data_block: bytes):
    data_block += conn.recv(MAX_BUFFER_SIZE)
    while True:
        net_bytes = conn.recv(MAX_BUFFER_SIZE)
        if net_bytes == '':
            data_block += net_bytes
        else:
            break
    return data_block
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
        return
    elif CMD_CLOSING in usr_cmd: 
        initial = b""
        initial += net_bytes
        data = receive_file(conn, initial)
        print(f"[CMD] RECIEVED: {CMD_CLOSING} from {ip_addr}")
        filename = SAVE_NAME +  ip_addr + "-" + (datetime.datetime.now()).strftime("%Y-%m-%d_%H%M")
        save_file(filename, data)
        print(f"[CMD] OK: File saved as: {filename}")
        return
    elif CMD_KEYS in usr_cmd:
        print(f"[SERVER] RECEIVED: {CMD_KEYS} from {ip_addr}")
        print("[SERVER] OK: PKI bound with: " + ip_addr)
        PKI[ip_addr] = PKCS1_OAEP.new(RSA.import_key(net_bytes[3:]))
        send_key(conn)
        print("[SERVER] OK: PKI sent to: " + ip_addr)
        print("[SERVER] OK. RSA KP Successful.")
        return
def client_thread(conn: socket.socket, ip: str, port: int):
    command_menu(conn, ip)
    conn.close()  # close connection
    print('[SERVER] Connection ' + ip + ':' + port + " closed.")

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
    cipher = load_keys("server")
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 8888
    start_server(HOST, PORT)
