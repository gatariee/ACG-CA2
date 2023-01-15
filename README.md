Outline 
=======
## Functionality
- The program is run in additional outlets outside SP, using public wifi
    - we should assume that the wifi does not have a secure tunnel
    - this means that the data is not encrypted
## Program Flow
- server.py
    - the server is run by the main outlet
        - we are assuming that the server is run on a secure network
    - clients will connect to the server and request for a connection
    - clients will send either "GET_MENU" or "CLOSING"
        - "GET_MENU" will send the menu to the client
        - "CLOSING" will receieve the sales from the client
- client.py 
    - the client is run by the additional outlets
        - the client is connected to public wifi
    - the client will connect to the server
    - the client will send either "GET_MENU" or "CLOSING"
    - we can safely assume that:
        - "GET_MENU" is called at the start of a day
        - "CLOSING" is called at the end of the day
## Security Issues  
- The connection between the client and server is not encrypted
    - Confidentiality is compromised
    - The attacker will be able to read sensitive data(client sales)
    - Our scope is: DAY-CLOSING (client.py)
- The authenticity of the data is not verified
    - Integrity is compromised
    - Both parties can not trust the data being sent
    - Menu and sales could both be tampered with
    - Our scope is: MENU (server.py)
        - specifically, data in transit (encryption)
- There is no way to verify the identity of the client
    - Non-repudiation is compromised
    - An attacker could impersonate a client
    - The attacker could send fake sales
    - Our scope is: DAY-CLOSING (client.py)
## Mitigation
- Confidentiality
    - Problem:
        - The data is not encrypted
        - Confidentiality of data in transit is compromised (client and server)
        - Confidentiality of data at rest is compromised (client)
    - Solution:
        - We will solve this by encrypting the data with AES (Advanced Encryption Standard)
        - AES is a symmetric encryption algorithm
        - We will use a shared key between the client and server
            - Using a shared key introduces a new problem: Key Distribution
        - We will use RSA (Rivest–Shamir–Adleman) to distribute the key
            - RSA is an asymmetric encryption algorithm
            - Both the client and server will have generate an RSA key pair
                - The client will send the server its public key
                - The server will send the client its public key
            - Key Exchange
                - The server will generate a random AES key, this is your session key
                - The server will encrypt the AES key with the client's public key
                - The server will send the encrypted AES key to the client
                - The client will decrypt the AES key with its private key
                - The client and server will now use the AES key to encrypt and decrypt data
            - The AES key is discarded after every session, a new key is generated for every session.
            - However, there is now another problem of storing the RSA keypairs on the client.
                - We will use a password to encrypt the RSA keypair
                - The client will be prompted for a password
                - The client will use the password to decrypt their private key
                - The same transaction will follow, see above.
                    - This ensures that even if private.pem is stolen
                    - The attacker will not be able to decrypt the AES key
                    - As the attacker does not have the password to decrypt the private key
            - Why AES > RSA?
                - RSA is slower
                - AES is faster
                - RSA is typically used for key distribution
                - AES is typically used for data encryption
    - Issues Solved: 
        - Data transferred between the client and server is encrypted with an AES key
            - Confidentiality of data in transit is restored
        - The RSA keypairs are encrypted with a password (for the client)
            - The AES key is distributed using RSA
            - Confidentiality of data at rest is restored
- Integrity
    - Problem:
        - The data is not verified by the client and server, the data could be tampered with
        - Integrity of data in transit is compromised (client and server)
    - Solution:
        - We will solve this by using a message digest via a hash function
        - We will use SHA-256 (Secure Hash Algorithm 256)
        - All data sent between the client and server will be hashed
        - This hash value is called the "message digest"
        - The message digest will be sent along with the data
        - The receiver will hash the data and compare it with the message digest
        - If the message digest does not match, the data is tampered with
    - Issues Solved:
        - If any data is tampered with, the message digest will not match. 
            - The receiving party will know that the data is tampered with
            - Integrity of data in transit is restored
- Non-repudiation
    - Problem:
        - The client and server can not verify the identity of each other
        - An attacker can impersonate the client or server
        - Non-repudiation of data in transit is compromised (client and server)
    - Solution:
        - We will solve this by using a self-signed certificate
        - The client and server generate their own public/private key pair
        - The client and server generate a certificate signing request (CSR)
        - The client and server sign their own CSR with their private key
            - Client and server send their signed CSR to the other party
            - The other party validates the certificate
                - expiration date, domain name, etc.
            - Validate the signature of the CSR
                - The other party will use the certificate creator's public key to verify the signature
                - If the signature is valid, the certificate is valid
        - The client and server will now use their own certificate to authenticate each other
        - Note that since the certificate is self-signed:
            - It is not verified by a trusted third-party (such as a certificate authority) and should be used with caution
            - It is important that both the client and the server have a copy of the certificate and trust it before using it to authenticate each other
    - Issues Solved:
        - The client and server can now verify the identity of each other
            - The data sent can now be trusted, as the identity of the sender is verified
            - Non-repudiation of data in transit is restored








