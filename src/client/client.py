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
        print(f"[{cmd_GET_MENU.decode()}] OK.")
    print(f"[CLIENT] Sending: {cmd_END_DAY.decode()}")
    if send_file():
        print(f"[{cmd_END_DAY.decode()}] OK.")
    print(f"[CLIENT] Closing connection.")

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_GET_MENU )
#     data = my_socket.recv(4096)
#     #hints : need to apply a scheme to verify the integrity of data.  
#     menu_file = open(menu_file,"wb")
#     menu_file.write( data)
#     menu_file.close()
#     my_socket.close()
# print('Menu today received from server')
# #print('Received', repr(data))  # for debugging use
# my_socket.close()

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_END_DAY)
#     try:
#         out_file = open(return_file,"rb")
#     except:
#         print("file not found : " + return_file)
#         sys.exit(0)
#     file_bytes = out_file.read(1024)
#     sent_bytes=b''
#     while file_bytes != b'':
#         my_socket.send(file_bytes)
#         sent_bytes+=file_bytes
#         file_bytes = out_file.read(1024)
#     out_file.close()
#     my_socket.close()
# print('Sale of the day sent to server')
# my_socket.close()





