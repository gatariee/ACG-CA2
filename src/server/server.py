#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
from threading import Thread
import socket
import datetime
import sys
import time

# constants
CMD_MENU = "GET_MENU"
CMD_CLOSING = "CLOSING"
MENU = "menu_today.txt"
SAVE_NAME = "result-"
MAX_BUFFER_SIZE = 2048
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
        if net_bytes != b'':
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
        print("[CMD] OK: Sent Menu to " + ip_addr)
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
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 8888
    start_server(HOST, PORT)
