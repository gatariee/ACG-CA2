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
MAX_BUFFER_SIZE = 4096

# ports and host
host = socket.gethostname()
port = 8888

def process_connection( conn , ip_addr):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if CMD_MENU in usr_cmd: # ask for menu
                try:
                    src_file = open(MENU,"rb")
                except:
                    print("file not found : " + MENU)
                    sys.exit(0)
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break
                    #hints: you may apply a scheme (hashing/encryption) to read_bytes before sending to client.
                    conn.send(read_bytes)
                src_file.close()
                print("Processed SENDING menu") 
                return
            elif CMD_CLOSING in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the CMD_CLOSING may be encrypted. 
                now = datetime.datetime.now()
                filename = SAVE_NAME +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                dest_file.write( net_bytes[ len(CMD_CLOSING): ] ) # remove the CLOSING header    
                blk_count = blk_count + 1
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done") 

def client_thread(conn, ip, port):
    process_connection( conn, ip)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + "ended")

def start_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"Server started on {host}:{port}")
    try:
        sock.bind((host, port))
        print(f"Server binded to {host}:{port}")
    except socket.error as e:
        print(f"Bind failed. Error: {e}")
        sys.exit()
    sock.listen(10)
    print(f"Server is listening on port {port}...")
    while True:
        try:
            conn, addr = sock.accept()
            ip, port = str(addr[0]), str(addr[1])
            print(f"Accepted connection from {ip}:{port}")
            Thread(target=client_thread, args=(conn, ip, port)).start()
        except Exception as e:
            print(f"Error: {e}")
            break
    sock.close()
if __name__ == "__main__":
    start_server(host, port)
