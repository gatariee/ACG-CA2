#------------------------------------------------------------------------------------------
# client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client
 
import datetime
import sys              # handle system error
import socket
import time
host = socket.gethostbyname(socket.gethostname())
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

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
                conn.close()
                return True
        except FileNotFoundError:
            print(f"[CLIENT] FAIL: File not found: '{return_file}'.")
            conn.close()
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
                conn.close()
                return True
        except FileNotFoundError:
            print(f"[CLIENT] FAIL: File not could not be saved to: '{menu_file}'.")
            conn.close()
            return False
    

if __name__ == "__main__":
    print(f"[CLIENT] Connected to {host}:{port}")
    print(f"[CLIENT] Sending: {cmd_GET_MENU.decode()}")
    if receive_file():
        print(f"[GET_MENU] OK.")
    print(f"[CLIENT] Sending: {cmd_END_DAY.decode()}")
    if send_file():
        print(f"[CLOSING] OK.")
    print(f"[CLIENT] Closing connection.")




