This is the code for a server script that uses the RSA encryption algorithm to secure communication between clients and the server. The script includes functions for sending and receiving files, checking digital signatures, and checking certificates. The script uses the Cryptodome library for encryption and the cryptography library for certificate handling. The server has several file names such as "public.pem" and "private.pem", which are expected to exist in the same directory as the script. The script uses a "GET_MENU" command to receive the menu from the client, "PKI" command to receive the client's public key, "CERTS" command to receive the client's certificate and a "CLOSING" command to close the connection. The script also uses the RSA encryption algorithm to encrypt and decrypt the data sent and received and uses the SHA256 hash function to create a signature for the data.

Server Functions:
1. `send_key(conn: socket.socket)`: sends the public key to a connected client over the given socket connection.
2. `load_keys(password: str)`: loads the private key from a file and returns it.
3. `send_file(conn: socket.socket, filename: str)`: sends a file to a connected client over the given socket connection.
4. `save_file(filename: str, data: bytes)`: saves data in bytes to a file with the given filename.
5. `receive_file(conn: socket.socket, data_block: bytes)`: receives a file from a connected client over the given socket connection and returns the file in bytes.
6. `check_signature(data: bytes)`: checks the signature of a file in bytes, returns True if the signature is valid, False otherwise.
7. `check_certs(cert)`: checks the validity of a client certificate
8. `exchange_certs(conn: socket.socket)`: exchanges certificates between the server and client over the given socket connection.
9. `command_menu(conn: socket.socket, ip_addr: str)`: Handles the menu command sent by the client over the given socket connection.
10. `connection_handler(conn: socket.socket, ip_addr: str)`: Handles a single client connection over the given socket connection.
11. `main()`: starts the server and handles client connections.