import datetime
import sys              # handle system error
import socket
import time
from Crypto.Cipher import AES, RSA
from Crypto.Random import get_random_bytes

global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

# RSA key pair generation
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# AES key generation
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

# Send RSA public key to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(public_key.export_key())
    my_socket.close()
print('Public key sent to server')

# Send menu request to server and receive menu
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU)
    data = my_socket.recv(4096)
    # decrypt the received data
    decrypted_data = private_key.decrypt(data)
    # verify the integrity of the data
    # hints : need to apply a scheme to verify the integrity of data.
    menu_file = open(menu_file, "wb")
    menu_file.write(decrypted_data)
    menu_file.close()
    my_socket.close()
print('Menu today received from server')

# Send end of day report to server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file, "rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes = b''
    while file_bytes != b'':
        # encrypt the file_bytes before sending it out
        ciphertext = cipher.encrypt(file_bytes)
        my_socket.send(ciphertext)
        sent_bytes += file_bytes
        file_bytes = out_file.read(1024)  # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
